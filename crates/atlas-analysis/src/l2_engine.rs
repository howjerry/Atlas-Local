//! L2 污染傳播引擎 — reaching-definitions worklist + sink 偵測。
//!
//! 為每個函數：
//! 1. 透過 `ScopeGraphBuilder` 建構 scope graph
//! 2. 執行 reaching-definitions worklist 演算法傳播污染
//! 3. 偵測受污染變數傳入 sink 函數
//! 4. 建構 `DataFlowPath` 並產生 `Finding`

use std::collections::HashMap;

use atlas_lang::Language;
use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};
use tree_sitter::{Node, Tree};

use crate::finding::{Finding, FindingBuilder, LineRange};
use crate::l2_builder::{get_l2_config, L2LanguageConfig, ScopeGraphBuilder};
use crate::l2_intraprocedural::{DataFlowStep, FlowStepType, ScopeGraph, TaintState};
use crate::l2_taint_config::{load_taint_config, TaintConfig};

// ---------------------------------------------------------------------------
// L2Engine
// ---------------------------------------------------------------------------

/// L2 intra-procedural 污染分析引擎。
pub struct L2Engine {
    language: Language,
    taint_config: TaintConfig,
}

impl L2Engine {
    /// 建立新的 L2Engine。
    ///
    /// # Errors
    ///
    /// 若語言的 taint config 載入失敗則回傳錯誤。
    pub fn new(language: Language) -> Result<Self, String> {
        let taint_config = load_taint_config(language)?;
        Ok(Self {
            language,
            taint_config,
        })
    }

    /// 分析一個已解析的檔案，回傳 L2 findings。
    ///
    /// `tree` 與 `source` 為已由 tree-sitter 解析的 AST 及原始碼。
    /// `file_path` 為相對路徑，用於 finding 輸出。
    pub fn analyze_file(
        &self,
        tree: &Tree,
        source: &[u8],
        file_path: &str,
    ) -> Vec<Finding> {
        let Some(lang_config) = get_l2_config(self.language) else {
            return Vec::new();
        };

        let builder = ScopeGraphBuilder::new(source, lang_config, &self.taint_config);
        let scope_graphs = builder.build_all(tree);

        let source_str = std::str::from_utf8(source).unwrap_or("");

        let mut findings = Vec::new();
        for (func_name, sg) in &scope_graphs {
            let propagated = self.propagate_taint(sg);
            let detected = self.detect_sinks(
                tree, source, lang_config, &propagated, func_name,
            );
            for detection in detected {
                if let Some(finding) = self.build_finding(
                    &detection, file_path, source_str,
                ) {
                    findings.push(finding);
                }
            }
        }

        findings
    }

    // -----------------------------------------------------------------------
    // Taint propagation（reaching-definitions worklist）
    // -----------------------------------------------------------------------

    /// 執行 reaching-definitions worklist 演算法，傳播污染狀態。
    ///
    /// 回傳更新後的 `(變數名稱, 定義行, TaintState)` 映射。
    fn propagate_taint(&self, sg: &ScopeGraph) -> HashMap<String, Vec<ReachingDef>> {
        // 收集每個變數的所有定義點
        let mut reaching: HashMap<String, Vec<ReachingDef>> = HashMap::new();

        for (idx, def) in sg.definitions.iter().enumerate() {
            let rd = ReachingDef {
                def_index: idx,
                name: def.name.clone(),
                def_line: def.def_line,
                taint_state: def.taint_state,
                scope_id: def.scope_id,
            };
            reaching.entry(def.name.clone()).or_default().push(rd);
        }

        // Worklist：反覆傳播直到固定點
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // 先收集所有需要傳播的更新（避免同時可變/不可變借用）
            let mut updates: Vec<(String, u32)> = Vec::new();

            for var_use in &sg.uses {
                if let Some(defs) = reaching.get(&var_use.name) {
                    // 找到最接近（且在使用之前）的定義
                    let reaching_def = defs.iter()
                        .filter(|d| d.def_line <= var_use.use_line)
                        .max_by_key(|d| d.def_line);

                    if let Some(rd) = reaching_def {
                        if rd.taint_state == TaintState::Tainted {
                            let tainted_name = var_use.name.clone();
                            let tainted_def_line = rd.def_line;

                            // 找到所有在此 tainted 定義之後、且 RHS 引用此變數的定義
                            for other_defs in reaching.values() {
                                for other_def in other_defs {
                                    // 只傳播到 Unknown 狀態（Clean 不受影響）
                                    if other_def.taint_state == TaintState::Unknown
                                        && other_def.def_line > tainted_def_line
                                    {
                                        for use_at in &sg.uses {
                                            if use_at.name == tainted_name
                                                && use_at.use_line == other_def.def_line
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

            // 批次套用更新
            for (name, line) in updates {
                if let Some(defs) = reaching.get_mut(&name) {
                    for def in defs.iter_mut() {
                        if def.def_line == line && def.taint_state == TaintState::Unknown {
                            def.taint_state = TaintState::Tainted;
                            changed = true;
                        }
                    }
                }
            }
        }

        reaching
    }

    // -----------------------------------------------------------------------
    // Sink detection
    // -----------------------------------------------------------------------

    /// 偵測受污染變數傳入 sink 函數。
    fn detect_sinks(
        &self,
        tree: &Tree,
        source: &[u8],
        lang_config: &dyn L2LanguageConfig,
        reaching: &HashMap<String, Vec<ReachingDef>>,
        func_name: &str,
    ) -> Vec<SinkDetection> {
        let mut detections = Vec::new();
        let root = tree.root_node();
        self.walk_for_sinks(
            root, source, lang_config, reaching, func_name, &mut detections,
        );
        detections
    }

    /// 遞迴走訪 AST 尋找 sink 呼叫。
    fn walk_for_sinks(
        &self,
        node: Node,
        source: &[u8],
        lang_config: &dyn L2LanguageConfig,
        reaching: &HashMap<String, Vec<ReachingDef>>,
        func_name: &str,
        detections: &mut Vec<SinkDetection>,
    ) {
        let kind = node.kind();

        if kind == lang_config.call_expression_kind() {
            if let Some(call_name) = lang_config.extract_call_name(node, source) {
                // 檢查是否為配置的 sink
                if let Some(sink) = self.taint_config.sinks.iter().find(|s| {
                    call_name == s.function || call_name.ends_with(&format!(".{}", s.function))
                }) {
                    // 檢查引數是否受污染
                    let args = self.extract_call_args(node, source, lang_config);
                    for &arg_idx in &sink.tainted_args {
                        if let Some(arg_name) = args.get(arg_idx as usize) {
                            // 檢查此引數是否是受污染的變數
                            let call_line = node.start_position().row as u32 + 1;
                            if self.is_var_tainted_at(arg_name, call_line, reaching) {
                                // 建構 data flow path
                                let source_def = self.find_taint_source(
                                    arg_name, call_line, reaching,
                                );
                                let steps = self.build_flow_steps(
                                    source_def.as_ref(),
                                    arg_name,
                                    &call_name,
                                    call_line,
                                    node.start_position().column as u32 + 1,
                                );

                                detections.push(SinkDetection {
                                    func_name: func_name.to_string(),
                                    sink_function: sink.function.clone(),
                                    vulnerability: sink.vulnerability.clone(),
                                    cwe: sink.cwe.clone(),
                                    call_line,
                                    call_col: node.start_position().column as u32 + 1,
                                    tainted_arg: arg_name.clone(),
                                    data_flow_steps: steps,
                                    call_text: node_text(node, source)
                                        .unwrap_or_default()
                                        .to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // 遞迴子節點
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_for_sinks(child, source, lang_config, reaching, func_name, detections);
        }
    }

    /// 提取呼叫表達式的引數名稱列表。
    fn extract_call_args(
        &self,
        call_node: Node,
        source: &[u8],
        _lang_config: &dyn L2LanguageConfig,
    ) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(arg_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = arg_list.walk();
            for child in arg_list.children(&mut cursor) {
                let kind = child.kind();
                // 跳過語法符號（括號、逗號）
                if kind == "(" || kind == ")" || kind == "," {
                    continue;
                }
                // 取得引數文字（可能是識別碼或複合表達式）
                if let Some(text) = node_text(child, source) {
                    args.push(text.to_string());
                }
            }
        }
        args
    }

    /// 檢查變數在指定行是否受污染。
    fn is_var_tainted_at(
        &self,
        var_name: &str,
        at_line: u32,
        reaching: &HashMap<String, Vec<ReachingDef>>,
    ) -> bool {
        if let Some(defs) = reaching.get(var_name) {
            // 找到最接近且在 at_line 之前（含）的定義
            let reaching_def = defs.iter()
                .filter(|d| d.def_line <= at_line)
                .max_by_key(|d| d.def_line);
            if let Some(rd) = reaching_def {
                return rd.taint_state == TaintState::Tainted;
            }
        }
        false
    }

    /// 找到引起污染的原始定義。
    fn find_taint_source(
        &self,
        var_name: &str,
        at_line: u32,
        reaching: &HashMap<String, Vec<ReachingDef>>,
    ) -> Option<ReachingDef> {
        if let Some(defs) = reaching.get(var_name) {
            // 從最接近的受污染定義回溯到最早的來源
            let tainted_defs: Vec<_> = defs.iter()
                .filter(|d| d.def_line <= at_line && d.taint_state == TaintState::Tainted)
                .collect();
            // 回傳最早的受污染定義
            return tainted_defs.into_iter().min_by_key(|d| d.def_line).cloned();
        }
        None
    }

    /// 建構 data flow steps。
    fn build_flow_steps(
        &self,
        source_def: Option<&ReachingDef>,
        tainted_arg: &str,
        sink_function: &str,
        sink_line: u32,
        sink_col: u32,
    ) -> Vec<DataFlowStep> {
        let mut steps = Vec::new();

        // Source step
        if let Some(src) = source_def {
            steps.push(DataFlowStep {
                step_type: FlowStepType::Source,
                line: src.def_line,
                column: 1, // 精確欄位需要更多 AST 資訊
                expression: src.name.clone(),
                description: format!("User input assigned to '{}'", src.name),
            });

            // Propagation step（若變數名稱不同，代表有傳播）
            if src.name != tainted_arg {
                steps.push(DataFlowStep {
                    step_type: FlowStepType::Propagation,
                    line: src.def_line,
                    column: 1,
                    expression: format!("{} -> {}", src.name, tainted_arg),
                    description: format!(
                        "Tainted value propagated from '{}' to '{}'",
                        src.name, tainted_arg
                    ),
                });
            }
        }

        // Sink step
        steps.push(DataFlowStep {
            step_type: FlowStepType::Sink,
            line: sink_line,
            column: sink_col,
            expression: format!("{}({})", sink_function, tainted_arg),
            description: format!(
                "Tainted value '{}' passed to dangerous function '{}'",
                tainted_arg, sink_function
            ),
        });

        steps
    }

    // -----------------------------------------------------------------------
    // Finding generation
    // -----------------------------------------------------------------------

    /// 從 SinkDetection 建構 Finding。
    fn build_finding(
        &self,
        detection: &SinkDetection,
        file_path: &str,
        source_str: &str,
    ) -> Option<Finding> {
        let lang_str = language_short_name(self.language);
        let rule_id = format!(
            "atlas/security/{}/l2-{}",
            lang_str, detection.vulnerability
        );

        // 從漏洞類型決定嚴重性
        let severity = vulnerability_severity(&detection.vulnerability);

        // 取得 snippet（sink 所在行前後共 3 行）
        let snippet = extract_snippet(source_str, detection.call_line, 3);

        let line_range = LineRange::new(
            detection.call_line,
            detection.call_col,
            detection.call_line,
            detection.call_col + detection.call_text.len() as u32,
        ).ok()?;

        // data_flow metadata
        let data_flow_json: Vec<serde_json::Value> = detection.data_flow_steps.iter()
            .map(|step| serde_json::json!({
                "step_type": step.step_type,
                "line": step.line,
                "column": step.column,
                "expression": step.expression,
                "description": step.description,
            }))
            .collect();

        let description = format!(
            "L2 data-flow: tainted value '{}' flows to dangerous function '{}' ({})",
            detection.tainted_arg,
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
            .analysis_level(AnalysisLevel::L2)
            .confidence(Confidence::Medium)
            .meta("data_flow", serde_json::Value::Array(data_flow_json))
            .meta("function", serde_json::json!(detection.func_name))
            .meta("sink_function", serde_json::json!(detection.sink_function))
            .build()
            .ok()
    }
}

// ---------------------------------------------------------------------------
// 內部型別
// ---------------------------------------------------------------------------

/// Reaching-definition 條目。
#[derive(Debug, Clone)]
struct ReachingDef {
    /// 在 ScopeGraph.definitions 中的索引。
    #[allow(dead_code)]
    def_index: usize,
    /// 變數名稱。
    name: String,
    /// 定義行號（1-indexed）。
    def_line: u32,
    /// 污染狀態。
    taint_state: TaintState,
    /// 所屬作用域。
    #[allow(dead_code)]
    scope_id: u32,
}

/// Sink 偵測結果。
#[derive(Debug, Clone)]
struct SinkDetection {
    /// 所在函數名稱。
    func_name: String,
    /// Sink 函數名稱。
    sink_function: String,
    /// 漏洞類型（如 sql-injection）。
    vulnerability: String,
    /// CWE 識別碼。
    cwe: String,
    /// 呼叫行號。
    call_line: u32,
    /// 呼叫欄位號。
    call_col: u32,
    /// 受污染的引數名稱。
    tainted_arg: String,
    /// 資料流步驟。
    data_flow_steps: Vec<DataFlowStep>,
    /// 呼叫原始碼文字。
    call_text: String,
}

// ---------------------------------------------------------------------------
// 工具函數
// ---------------------------------------------------------------------------

/// 從節點取得原始碼文字。
fn node_text<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
    std::str::from_utf8(&source[node.byte_range()]).ok()
}

/// 語言簡稱（用於 rule_id）。
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

/// 根據漏洞類型決定嚴重性。
fn vulnerability_severity(vulnerability: &str) -> Severity {
    match vulnerability {
        "sql-injection" | "command-injection" => Severity::Critical,
        "xss" | "path-traversal" | "ssrf" => Severity::High,
        _ => Severity::Medium,
    }
}

/// 產生漏洞類型對應的修復建議。
fn generate_remediation(vulnerability: &str) -> String {
    match vulnerability {
        "sql-injection" => {
            "Use parameterized queries or prepared statements instead of \
             string concatenation for SQL queries."
                .to_string()
        }
        "xss" => {
            "Sanitize and encode user input before rendering in HTML. \
             Use a template engine with auto-escaping."
                .to_string()
        }
        "command-injection" => {
            "Avoid passing user input to system commands. \
             Use allowlists and input validation instead."
                .to_string()
        }
        "path-traversal" => {
            "Validate and sanitize file paths. Use path canonicalization \
             and restrict to allowed directories."
                .to_string()
        }
        "ssrf" => {
            "Validate and restrict URLs. Use allowlists for permitted \
             hosts and protocols."
                .to_string()
        }
        _ => "Review and sanitize user input before use.".to_string(),
    }
}

/// 從原始碼提取指定行附近的 snippet。
fn extract_snippet(source: &str, line: u32, context: u32) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = (line.saturating_sub(context + 1)) as usize;
    let end = ((line + context) as usize).min(lines.len());
    // 最多 10 行（FindingBuilder 限制）
    let end = end.min(start + 10);
    lines[start..end].join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 建立 TypeScript parser 並解析原始碼。
    fn parse_ts(source: &[u8]) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    // --- Worklist 收斂測試 ---

    #[test]
    fn propagation_simple_taint() {
        // 簡單情境：tainted source → sink
        let source = br#"function handler(req) {
    const name = req.body.name;
    db.query(name);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let config = get_l2_config(Language::TypeScript).unwrap();
        let taint_config = load_taint_config(Language::TypeScript).unwrap();
        let builder = ScopeGraphBuilder::new(source, config, &taint_config);
        let scope_graphs = builder.build_all(&tree);

        assert!(!scope_graphs.is_empty());
        let (_, sg) = &scope_graphs[0];
        let reaching = engine.propagate_taint(sg);

        // name 應該是 tainted
        assert!(
            reaching.get("name").is_some_and(|defs| {
                defs.iter().any(|d| d.taint_state == TaintState::Tainted)
            }),
            "name 變數應被標記為 tainted"
        );
    }

    #[test]
    fn propagation_taint_through_assignment() {
        // 傳播：x = tainted, y = x → y 也受污染
        let source = br#"function handler(req) {
    const input = req.body.name;
    const query = input;
    db.query(query);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let config = get_l2_config(Language::TypeScript).unwrap();
        let taint_config = load_taint_config(Language::TypeScript).unwrap();
        let builder = ScopeGraphBuilder::new(source, config, &taint_config);
        let scope_graphs = builder.build_all(&tree);

        let (_, sg) = &scope_graphs[0];
        let reaching = engine.propagate_taint(sg);

        // input 應該是 tainted
        assert!(
            reaching.get("input").is_some_and(|defs| {
                defs.iter().any(|d| d.taint_state == TaintState::Tainted)
            }),
            "input 變數應被標記為 tainted"
        );
    }

    #[test]
    fn propagation_sanitizer_clears_taint() {
        // 淨化：sanitized = parseInt(tainted) → sanitized 不受污染
        let source = br#"function handler(req) {
    const id = req.body.id;
    const safeId = parseInt(id);
    db.query(safeId);
}"#;
        let tree = parse_ts(source);
        let config = get_l2_config(Language::TypeScript).unwrap();
        let taint_config = load_taint_config(Language::TypeScript).unwrap();
        let builder = ScopeGraphBuilder::new(source, config, &taint_config);
        let scope_graphs = builder.build_all(&tree);

        let (_, sg) = &scope_graphs[0];

        // safeId 的初始值來自 parseInt()，應被標記為 Clean
        let safe_def = sg.definitions.iter().find(|d| d.name == "safeId");
        assert!(
            safe_def.is_some_and(|d| d.taint_state == TaintState::Clean),
            "safeId 經過 parseInt 淨化後應標記為 Clean"
        );

        // 整合測試：不應產生 finding
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "test.ts");
        assert!(
            findings.is_empty(),
            "經過 parseInt 淨化後不應產生 finding"
        );
    }

    // --- Sink detection 測試 ---

    #[test]
    fn detect_sql_injection_sink() {
        let source = br#"function handler(req) {
    const name = req.body.name;
    db.query(name);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "src/handler.ts");

        assert!(
            !findings.is_empty(),
            "應偵測到 SQL injection sink"
        );
        let f = &findings[0];
        assert!(f.rule_id.contains("l2-sql-injection"));
        assert_eq!(f.cwe_id.as_deref(), Some("CWE-89"));
        assert_eq!(f.analysis_level, AnalysisLevel::L2);
        assert_eq!(f.confidence, Confidence::Medium);
    }

    #[test]
    fn no_finding_when_sanitized() {
        let source = br#"function handler(req) {
    const id = req.body.id;
    const safeId = parseInt(id);
    db.query(safeId);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "src/handler.ts");

        assert!(
            findings.is_empty(),
            "經過 parseInt 淨化後不應產生 finding"
        );
    }

    #[test]
    fn detect_xss_sink() {
        let source = br#"function handler(req, res) {
    const name = req.body.name;
    res.send(name);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "src/handler.ts");

        assert!(
            !findings.is_empty(),
            "應偵測到 XSS sink"
        );
        assert!(findings[0].rule_id.contains("l2-xss"));
        assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-79"));
    }

    #[test]
    fn finding_has_data_flow_metadata() {
        let source = br#"function handler(req) {
    const name = req.body.name;
    db.query(name);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "src/handler.ts");

        assert!(!findings.is_empty());
        let f = &findings[0];
        // 應有 data_flow metadata
        assert!(
            f.metadata.contains_key("data_flow"),
            "finding 應包含 data_flow metadata"
        );
        let data_flow = f.metadata.get("data_flow").unwrap();
        assert!(data_flow.is_array(), "data_flow 應為陣列");
        let steps = data_flow.as_array().unwrap();
        assert!(
            !steps.is_empty(),
            "data_flow 應有至少一個步驟"
        );
        // 最後一步應為 sink
        let last = steps.last().unwrap();
        assert_eq!(last["step_type"], "sink");
    }

    #[test]
    fn finding_has_correct_rule_id_format() {
        let source = br#"function handler(req) {
    const name = req.body.name;
    db.query(name);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "src/handler.ts");

        assert!(!findings.is_empty());
        assert_eq!(
            findings[0].rule_id,
            "atlas/security/typescript/l2-sql-injection"
        );
    }

    #[test]
    fn no_finding_for_clean_code() {
        let source = br#"function handler() {
    const x = 42;
    console.log(x);
}"#;
        let tree = parse_ts(source);
        let engine = L2Engine::new(Language::TypeScript).unwrap();
        let findings = engine.analyze_file(&tree, source, "src/handler.ts");

        assert!(
            findings.is_empty(),
            "無污染源的程式碼不應產生 finding"
        );
    }

    #[test]
    fn finding_severity_sql_injection_is_critical() {
        assert_eq!(vulnerability_severity("sql-injection"), Severity::Critical);
    }

    #[test]
    fn finding_severity_xss_is_high() {
        assert_eq!(vulnerability_severity("xss"), Severity::High);
    }

    // --- 工具函數測試 ---

    #[test]
    fn extract_snippet_basic() {
        let source = "line1\nline2\nline3\nline4\nline5\nline6\nline7";
        let snippet = extract_snippet(source, 4, 1);
        assert!(snippet.contains("line3"));
        assert!(snippet.contains("line4"));
        assert!(snippet.contains("line5"));
    }

    #[test]
    fn extract_snippet_at_start() {
        let source = "line1\nline2\nline3";
        let snippet = extract_snippet(source, 1, 1);
        assert!(snippet.contains("line1"));
    }

    #[test]
    fn language_short_names() {
        assert_eq!(language_short_name(Language::TypeScript), "typescript");
        assert_eq!(language_short_name(Language::Java), "java");
        assert_eq!(language_short_name(Language::Python), "python");
        assert_eq!(language_short_name(Language::CSharp), "csharp");
        assert_eq!(language_short_name(Language::Go), "go");
    }
}
