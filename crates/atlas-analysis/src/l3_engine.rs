//! L3 跨函數污染傳播引擎。
//!
//! Phase 1: 從多檔案 AST 建構 call graph 和 scope graphs。
//! Phase 2: BFS 遍歷 call graph，追蹤污染跨函數傳播，偵測 sinks。

use std::collections::{HashMap, HashSet, VecDeque};

use atlas_lang::Language;
use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};
use tree_sitter::Tree;

use crate::call_graph_builder::CallGraphBuilder;
use crate::finding::{Finding, FindingBuilder, LineRange};
use crate::import_resolver;
use crate::l2_builder::{get_l2_config, ScopeGraphBuilder};
use crate::l2_intraprocedural::{ScopeGraph, TaintState, VarDef};
use crate::l2_taint_config::TaintConfig;
use crate::l3_interprocedural::CallGraph;
use crate::l3_lang_config::get_l3_config;

// ---------------------------------------------------------------------------
// 公開型別
// ---------------------------------------------------------------------------

/// 單一檔案的解析資料。
pub struct ParsedFile<'a> {
    pub file_path: &'a str,
    pub source: &'a [u8],
    pub tree: &'a Tree,
}

/// L3 跨函數污染分析引擎。
pub struct L3Engine {
    language: Language,
    taint_config: TaintConfig,
    max_depth: u32,
}

impl L3Engine {
    /// 建立新的 L3 引擎。
    pub fn new(language: Language, taint_config: TaintConfig, max_depth: u32) -> Self {
        Self {
            language,
            taint_config,
            max_depth,
        }
    }

    /// 回傳最大分析深度。
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// 完整分析（Phase 1 + Phase 2）。
    pub fn analyze_project(&self, files: &[ParsedFile<'_>]) -> Vec<Finding> {
        let l3_config = match get_l3_config(self.language) {
            Some(c) => c,
            None => return Vec::new(),
        };
        let l2_config = match get_l2_config(self.language) {
            Some(c) => c,
            None => return Vec::new(),
        };

        // Phase 1: 建構 call graph 和 scope graphs
        let mut call_graph = CallGraph::new();
        let mut file_map: HashMap<&str, &ParsedFile<'_>> = HashMap::new();
        let mut scope_cache: HashMap<String, ScopeGraph> = HashMap::new();

        for file in files {
            file_map.insert(file.file_path, file);

            // 建構 call graph
            let cg_builder =
                CallGraphBuilder::new(l3_config, file.source, file.file_path);
            let (functions, calls) = cg_builder.build_file(file.tree);

            // 將函數參數資訊儲存到 call graph
            for func in &functions {
                call_graph.add_function(func.clone());
            }
            for (caller_key, call_site) in calls {
                call_graph.add_call(&caller_key, call_site);
            }

            // 提取 imports
            let imports = import_resolver::extract_imports(
                file.tree,
                file.source,
                file.file_path,
                l3_config,
            );
            for entry in imports {
                call_graph.imports.add(entry);
            }

            // 建構 scope graphs（L2 基礎設施）
            let sg_builder =
                ScopeGraphBuilder::new(file.source, l2_config, &self.taint_config);
            for (func_name, mut sg) in sg_builder.build_all(file.tree) {
                let key = CallGraph::function_key(file.file_path, &func_name);

                // 將函數參數加入 scope graph 定義（L2 不含參數）
                if let Some(func_ref) = call_graph.functions.get(&key) {
                    for param in &func_ref.parameters {
                        // 只在 scope graph 中尚無此名稱定義時新增
                        let has_def = sg
                            .definitions
                            .iter()
                            .any(|d| d.name == *param);
                        if !has_def {
                            sg.definitions.push(VarDef {
                                name: param.clone(),
                                def_line: func_ref.line,
                                tainted: false,
                                taint_state: TaintState::Unknown,
                                scope_id: 0,
                            });
                        }
                    }
                }

                scope_cache.insert(key, sg);
            }
        }

        // Phase 2: BFS 從 entry points 分析
        let entry_points = find_entry_points(&call_graph, &scope_cache);
        let mut findings = Vec::new();

        for entry_key in &entry_points {
            self.bfs_analyze(
                entry_key,
                &call_graph,
                &file_map,
                &scope_cache,
                &mut findings,
            );
        }

        findings
    }

    /// BFS 遍歷 call graph，追蹤跨函數污染傳播。
    fn bfs_analyze(
        &self,
        entry_key: &str,
        call_graph: &CallGraph,
        file_map: &HashMap<&str, &ParsedFile<'_>>,
        scope_cache: &HashMap<String, ScopeGraph>,
        findings: &mut Vec<Finding>,
    ) {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<BfsItem> = VecDeque::new();

        queue.push_back(BfsItem {
            func_key: entry_key.to_string(),
            tainted_param_indices: Vec::new(),
            depth: 0,
            call_chain: vec![entry_key.to_string()],
        });

        while let Some(item) = queue.pop_front() {
            if item.depth > self.max_depth || visited.contains(&item.func_key) {
                continue;
            }
            visited.insert(item.func_key.clone());

            // 取得此函數的 scope graph
            let Some(base_sg) = scope_cache.get(&item.func_key) else {
                continue;
            };

            // 如果有來自 caller 的 tainted params，複製並標記
            let sg = if item.tainted_param_indices.is_empty() {
                base_sg.clone()
            } else {
                mark_params_tainted(
                    base_sg,
                    &item.func_key,
                    &item.tainted_param_indices,
                    call_graph,
                )
            };

            // 執行 reaching-definitions 傳播
            let reaching = propagate_taint(&sg);

            // 偵測此函數中的 sinks（只報告跨函數的 findings）
            if item.depth > 0 {
                let file_path =
                    item.func_key.split("::").next().unwrap_or("");
                if let Some(file) = file_map.get(file_path) {
                    let source_str =
                        std::str::from_utf8(file.source).unwrap_or("");
                    let detections = check_sinks_in_function(
                        &item.func_key,
                        call_graph,
                        &reaching,
                        &self.taint_config,
                    );

                    for detection in &detections {
                        if let Some(finding) = build_l3_finding(
                            detection,
                            file_path,
                            source_str,
                            &item.call_chain,
                            item.depth,
                            self.language,
                        ) {
                            findings.push(finding);
                        }
                    }
                }
            }

            // 對每個 call site，追蹤 tainted args → callee params
            if let Some(calls) = call_graph.calls.get(&item.func_key) {
                for call_site in calls {
                    let tainted_args =
                        find_tainted_call_args(call_site, &reaching);
                    if tainted_args.is_empty() {
                        continue;
                    }

                    let caller_file =
                        item.func_key.split("::").next().unwrap_or("");
                    if let Some(callee_key) =
                        call_graph.resolve_call(caller_file, &call_site.callee)
                    {
                        let mut chain = item.call_chain.clone();
                        chain.push(callee_key.clone());

                        queue.push_back(BfsItem {
                            func_key: callee_key,
                            tainted_param_indices: tainted_args,
                            depth: item.depth + 1,
                            call_chain: chain,
                        });
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 內部型別
// ---------------------------------------------------------------------------

/// BFS 佇列項目。
struct BfsItem {
    /// 函數 key（`file_path::func_name`）。
    func_key: String,
    /// 從 caller 傳入的受污染參數索引。
    tainted_param_indices: Vec<u32>,
    /// 當前 BFS 深度。
    depth: u32,
    /// 呼叫鏈（用於 finding 報告）。
    call_chain: Vec<String>,
}

/// Reaching-definition 條目。
#[derive(Debug, Clone)]
struct ReachingDef {
    /// 變數名稱。
    name: String,
    /// 定義行號（1-indexed）。
    def_line: u32,
    /// 污染狀態。
    taint_state: TaintState,
}

/// L3 sink 偵測結果。
#[derive(Debug)]
struct L3SinkDetection {
    sink_function: String,
    vulnerability: String,
    cwe: String,
    call_line: u32,
    tainted_arg: String,
}

// ---------------------------------------------------------------------------
// Phase 2 核心演算法
// ---------------------------------------------------------------------------

/// 找到含有 taint source 的函數作為 BFS 入口點。
fn find_entry_points(
    call_graph: &CallGraph,
    scope_cache: &HashMap<String, ScopeGraph>,
) -> Vec<String> {
    scope_cache
        .iter()
        .filter(|(key, sg)| {
            sg.definitions
                .iter()
                .any(|d| d.taint_state == TaintState::Tainted)
                && call_graph.functions.contains_key(*key)
        })
        .map(|(key, _)| key.clone())
        .collect()
}

/// 標記函數參數為 Tainted。
fn mark_params_tainted(
    base_sg: &ScopeGraph,
    func_key: &str,
    tainted_indices: &[u32],
    call_graph: &CallGraph,
) -> ScopeGraph {
    let mut sg = base_sg.clone();

    if let Some(func_ref) = call_graph.functions.get(func_key) {
        for &idx in tainted_indices {
            if let Some(param_name) = func_ref.parameters.get(idx as usize) {
                for def in &mut sg.definitions {
                    if def.name == *param_name {
                        def.taint_state = TaintState::Tainted;
                        def.tainted = true;
                        break;
                    }
                }
            }
        }
    }

    sg
}

/// Reaching-definitions worklist 演算法（與 L2 相同邏輯）。
fn propagate_taint(sg: &ScopeGraph) -> HashMap<String, Vec<ReachingDef>> {
    let mut reaching: HashMap<String, Vec<ReachingDef>> = HashMap::new();

    for def in &sg.definitions {
        reaching
            .entry(def.name.clone())
            .or_default()
            .push(ReachingDef {
                name: def.name.clone(),
                def_line: def.def_line,
                taint_state: def.taint_state,
            });
    }

    // Worklist 迭代直到固定點
    let mut changed = true;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 100;

    while changed && iterations < MAX_ITERATIONS {
        changed = false;
        iterations += 1;

        let mut updates: Vec<(String, u32)> = Vec::new();

        for var_use in &sg.uses {
            if let Some(defs) = reaching.get(&var_use.name) {
                let rd = defs
                    .iter()
                    .filter(|d| d.def_line <= var_use.use_line)
                    .max_by_key(|d| d.def_line);

                if let Some(rd) = rd {
                    if rd.taint_state == TaintState::Tainted {
                        for other_defs in reaching.values() {
                            for other_def in other_defs {
                                if other_def.taint_state == TaintState::Unknown
                                    && other_def.def_line > rd.def_line
                                {
                                    for use_at in &sg.uses {
                                        if use_at.name == var_use.name
                                            && use_at.use_line
                                                == other_def.def_line
                                        {
                                            updates.push((
                                                other_def.name.clone(),
                                                other_def.def_line,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for (name, line) in updates {
            if let Some(defs) = reaching.get_mut(&name) {
                for def in defs.iter_mut() {
                    if def.def_line == line
                        && def.taint_state == TaintState::Unknown
                    {
                        def.taint_state = TaintState::Tainted;
                        changed = true;
                    }
                }
            }
        }
    }

    reaching
}

/// 檢查函數中的 call sites 是否有 tainted 引數傳入 sink。
fn check_sinks_in_function(
    func_key: &str,
    call_graph: &CallGraph,
    reaching: &HashMap<String, Vec<ReachingDef>>,
    taint_config: &TaintConfig,
) -> Vec<L3SinkDetection> {
    let mut detections = Vec::new();

    let Some(calls) = call_graph.calls.get(func_key) else {
        return detections;
    };

    for call_site in calls {
        // 檢查 callee 是否匹配 sink 模式
        let sink = taint_config.sinks.iter().find(|s| {
            call_site.callee == s.function
                || call_site.callee.ends_with(&format!(".{}", s.function))
        });

        if let Some(sink) = sink {
            for &arg_idx in &sink.tainted_args {
                if let Some(arg_expr) =
                    call_site.argument_expressions.get(arg_idx as usize)
                {
                    if is_var_tainted(arg_expr, call_site.line, reaching) {
                        detections.push(L3SinkDetection {
                            sink_function: sink.function.clone(),
                            vulnerability: sink.vulnerability.clone(),
                            cwe: sink.cwe.clone(),
                            call_line: call_site.line,
                            tainted_arg: arg_expr.clone(),
                        });
                    }
                }
            }
        }
    }

    detections
}

/// 檢查 call site 的哪些引數是受污染的。
fn find_tainted_call_args(
    call_site: &crate::l3_interprocedural::CallSite,
    reaching: &HashMap<String, Vec<ReachingDef>>,
) -> Vec<u32> {
    call_site
        .argument_expressions
        .iter()
        .enumerate()
        .filter_map(|(idx, arg_expr)| {
            if is_var_tainted(arg_expr, call_site.line, reaching) {
                Some(idx as u32)
            } else {
                None
            }
        })
        .collect()
}

/// 檢查變數在指定行是否受污染。
fn is_var_tainted(
    var_name: &str,
    at_line: u32,
    reaching: &HashMap<String, Vec<ReachingDef>>,
) -> bool {
    if let Some(defs) = reaching.get(var_name) {
        let rd = defs
            .iter()
            .filter(|d| d.def_line <= at_line)
            .max_by_key(|d| d.def_line);
        if let Some(rd) = rd {
            return rd.taint_state == TaintState::Tainted;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// L3 Finding 生成
// ---------------------------------------------------------------------------

/// 從 L3 sink detection 建構 Finding。
fn build_l3_finding(
    detection: &L3SinkDetection,
    file_path: &str,
    source_str: &str,
    call_chain: &[String],
    call_depth: u32,
    language: Language,
) -> Option<Finding> {
    let lang_str = language_short_name(language);
    let rule_id = format!(
        "atlas/security/{}/l3-{}",
        lang_str, detection.vulnerability
    );

    let severity = vulnerability_severity(&detection.vulnerability);
    let snippet = extract_snippet(source_str, detection.call_line, 3);

    let line_range = LineRange::new(
        detection.call_line,
        1,
        detection.call_line,
        80,
    )
    .ok()?;

    // data_flow metadata：呼叫鏈
    let chain_steps: Vec<serde_json::Value> = call_chain
        .iter()
        .enumerate()
        .map(|(i, func)| {
            serde_json::json!({
                "step": i + 1,
                "function": func,
                "type": if i == 0 { "entry" } else if i == call_chain.len() - 1 { "sink_site" } else { "propagation" },
            })
        })
        .collect();

    let description = format!(
        "L3 cross-function: tainted value '{}' flows through {} function call(s) to sink '{}' ({})",
        detection.tainted_arg,
        call_depth,
        detection.sink_function,
        detection.vulnerability.replace('-', " "),
    );

    let remediation = generate_remediation(&detection.vulnerability);

    FindingBuilder::new()
        .rule_id(rule_id)
        .severity(severity)
        .category(Category::Security)
        .cwe_id(&detection.cwe)
        .file_path(file_path)
        .line_range(line_range)
        .snippet(snippet)
        .description(description)
        .remediation(remediation)
        .analysis_level(AnalysisLevel::L3)
        .confidence(Confidence::Medium)
        .meta("data_flow", serde_json::Value::Array(chain_steps))
        .meta("call_depth", serde_json::json!(call_depth))
        .meta(
            "sink_function",
            serde_json::json!(detection.sink_function),
        )
        .build()
        .ok()
}

// ---------------------------------------------------------------------------
// 工具函數
// ---------------------------------------------------------------------------

fn language_short_name(language: Language) -> &'static str {
    match language {
        Language::TypeScript | Language::JavaScript => "typescript",
        Language::Java => "java",
        Language::Python => "python",
        Language::CSharp => "csharp",
        Language::Go => "go",
        Language::Ruby => "ruby",
        Language::Php => "php",
        Language::Kotlin => "kotlin",
    }
}

fn vulnerability_severity(vulnerability: &str) -> Severity {
    match vulnerability {
        "sql-injection" | "command-injection" => Severity::Critical,
        "xss" | "path-traversal" | "ssrf" => Severity::High,
        _ => Severity::Medium,
    }
}

fn generate_remediation(vulnerability: &str) -> String {
    match vulnerability {
        "sql-injection" => {
            "Use parameterized queries or prepared statements instead of \
             string concatenation."
                .to_string()
        }
        "xss" => {
            "Sanitize and encode user input before rendering in HTML."
                .to_string()
        }
        "command-injection" => {
            "Avoid passing user input to system commands. \
             Use allowlists and input validation."
                .to_string()
        }
        "path-traversal" => {
            "Validate and canonicalize file paths. \
             Restrict to allowed directories."
                .to_string()
        }
        "ssrf" => {
            "Validate and restrict URLs to allowed hosts and protocols."
                .to_string()
        }
        _ => "Review and sanitize user input before use.".to_string(),
    }
}

fn extract_snippet(source: &str, line: u32, context: u32) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = (line.saturating_sub(context + 1)) as usize;
    let end = ((line + context) as usize).min(lines.len());
    let end = end.min(start + 10);
    if start < lines.len() {
        lines[start..end].join("\n")
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2_taint_config::load_taint_config;

    fn parse_ts(source: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(
                &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            )
            .expect("set language");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    fn make_engine() -> L3Engine {
        let taint_config =
            load_taint_config(Language::TypeScript).unwrap();
        L3Engine::new(Language::TypeScript, taint_config, 5)
    }

    // -------------------------------------------------------------------
    // 入口點辨識
    // -------------------------------------------------------------------

    #[test]
    fn find_entry_points_with_taint_source() {
        let source = r#"
function handleRequest(req) {
    const name = req.body.name;
    queryDb(name);
}

function queryDb(sql) {
    db.query(sql);
}
"#;
        let tree = parse_ts(source);
        let engine = make_engine();
        let l3_config =
            get_l3_config(Language::TypeScript).unwrap();
        let l2_config =
            get_l2_config(Language::TypeScript).unwrap();

        // Phase 1
        let mut call_graph = CallGraph::new();
        let cg_builder = CallGraphBuilder::new(
            l3_config,
            source.as_bytes(),
            "app.ts",
        );
        let (functions, calls) = cg_builder.build_file(&tree);
        for func in &functions {
            call_graph.add_function(func.clone());
        }
        for (k, cs) in calls {
            call_graph.add_call(&k, cs);
        }

        let sg_builder = ScopeGraphBuilder::new(
            source.as_bytes(),
            l2_config,
            &engine.taint_config,
        );
        let mut scope_cache: HashMap<String, ScopeGraph> = HashMap::new();
        for (name, sg) in sg_builder.build_all(&tree) {
            scope_cache
                .insert(CallGraph::function_key("app.ts", &name), sg);
        }

        let entries = find_entry_points(&call_graph, &scope_cache);
        assert!(
            entries.iter().any(|e| e.contains("handleRequest")),
            "handleRequest 應為 entry point（含 taint source），entries: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e.contains("queryDb")),
            "queryDb 不應為 entry point（無 taint source）"
        );
    }

    // -------------------------------------------------------------------
    // BFS 深度限制
    // -------------------------------------------------------------------

    #[test]
    fn bfs_respects_depth_limit() {
        let source = r#"
function a(req) {
    const x = req.body.name;
    b(x);
}
function b(p) {
    c(p);
}
function c(q) {
    db.query(q);
}
"#;
        let tree = parse_ts(source);
        let taint_config =
            load_taint_config(Language::TypeScript).unwrap();

        // max_depth=1: a→b 可達，b→c 不可達
        let engine = L3Engine::new(
            Language::TypeScript,
            taint_config.clone(),
            1,
        );
        let files = [ParsedFile {
            file_path: "app.ts",
            source: source.as_bytes(),
            tree: &tree,
        }];
        let findings_d1 = engine.analyze_project(&files);

        // max_depth=5: 完整鏈 a→b→c
        let engine_deep = L3Engine::new(
            Language::TypeScript,
            taint_config,
            5,
        );
        let findings_d5 = engine_deep.analyze_project(&files);

        // depth=1 應找不到 sink（sink 在 c，需 depth>=2）
        assert!(
            findings_d1.is_empty(),
            "depth=1 不應到達 c 中的 sink，findings: {findings_d1:?}"
        );
        // depth=5 應找到 sink
        assert!(
            !findings_d5.is_empty(),
            "depth=5 應到達 c 中的 sink"
        );
    }

    // -------------------------------------------------------------------
    // 循環偵測
    // -------------------------------------------------------------------

    #[test]
    fn cycle_detection_no_infinite_loop() {
        let source = r#"
function a(req) {
    const x = req.body.name;
    b(x);
}
function b(p) {
    a(p);
}
"#;
        let tree = parse_ts(source);
        let engine = make_engine();
        let files = [ParsedFile {
            file_path: "app.ts",
            source: source.as_bytes(),
            tree: &tree,
        }];

        // 不應無限迴圈
        let findings = engine.analyze_project(&files);
        // 結果可能為空或有限 — 關鍵是不 hang
        let _ = findings;
    }

    // -------------------------------------------------------------------
    // 正向污染傳播（tainted arg → callee param → sink）
    // -------------------------------------------------------------------

    #[test]
    fn forward_taint_propagation_to_sink() {
        let source = r#"
function handleRequest(req) {
    const input = req.body.name;
    queryDb(input);
}

function queryDb(sql) {
    db.query(sql);
}
"#;
        let tree = parse_ts(source);
        let engine = make_engine();
        let files = [ParsedFile {
            file_path: "app.ts",
            source: source.as_bytes(),
            tree: &tree,
        }];
        let findings = engine.analyze_project(&files);

        assert!(
            !findings.is_empty(),
            "應偵測到跨函數 SQL injection"
        );
        let f = &findings[0];
        assert!(
            f.rule_id.contains("l3-sql-injection"),
            "rule_id 應為 l3-sql-injection，got: {}",
            f.rule_id
        );
        assert_eq!(f.analysis_level, AnalysisLevel::L3);
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(f.metadata.contains_key("call_depth"));
    }

    // -------------------------------------------------------------------
    // Sanitizer 清除跨函數污染
    // -------------------------------------------------------------------

    #[test]
    fn sanitizer_clears_cross_function_taint() {
        let source = r#"
function handleRequest(req) {
    const input = req.body.id;
    const safe = parseInt(input);
    queryDb(safe);
}

function queryDb(sql) {
    db.query(sql);
}
"#;
        let tree = parse_ts(source);
        let engine = make_engine();
        let files = [ParsedFile {
            file_path: "app.ts",
            source: source.as_bytes(),
            tree: &tree,
        }];
        let findings = engine.analyze_project(&files);

        assert!(
            findings.is_empty(),
            "經過 parseInt 淨化後不應產生 L3 finding，got: {findings:?}"
        );
    }

    // -------------------------------------------------------------------
    // 菱形呼叫（A→B→D, A→C→D）D 僅分析一次
    // -------------------------------------------------------------------

    #[test]
    fn diamond_call_analyzes_d_once() {
        let source = r#"
function a(req) {
    const x = req.body.name;
    b(x);
    c(x);
}
function b(p) {
    d(p);
}
function c(q) {
    d(q);
}
function d(v) {
    db.query(v);
}
"#;
        let tree = parse_ts(source);
        let engine = make_engine();
        let files = [ParsedFile {
            file_path: "app.ts",
            source: source.as_bytes(),
            tree: &tree,
        }];
        let findings = engine.analyze_project(&files);

        // D 中的 sink 應該只被報告一次（visited 防重複）
        let l3_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.contains("l3-"))
            .collect();
        assert!(
            l3_findings.len() <= 1,
            "Diamond call 中 D 的 sink 應最多報告一次，got: {}",
            l3_findings.len()
        );
    }

    // -------------------------------------------------------------------
    // L3 finding 格式
    // -------------------------------------------------------------------

    #[test]
    fn l3_finding_has_correct_metadata() {
        let source = r#"
function handleRequest(req) {
    const input = req.body.name;
    queryDb(input);
}

function queryDb(sql) {
    db.query(sql);
}
"#;
        let tree = parse_ts(source);
        let engine = make_engine();
        let files = [ParsedFile {
            file_path: "app.ts",
            source: source.as_bytes(),
            tree: &tree,
        }];
        let findings = engine.analyze_project(&files);

        if !findings.is_empty() {
            let f = &findings[0];
            assert_eq!(f.analysis_level, AnalysisLevel::L3);
            assert!(f.metadata.contains_key("data_flow"));
            assert!(f.metadata.contains_key("call_depth"));
            assert!(f.metadata.contains_key("sink_function"));

            let depth = f.metadata.get("call_depth").unwrap();
            assert!(
                depth.as_u64().unwrap() > 0,
                "call_depth 應大於 0"
            );
        }
    }
}
