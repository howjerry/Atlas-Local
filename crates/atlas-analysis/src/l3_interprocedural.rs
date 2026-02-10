//! L3 inter-procedural taint analysis。
//!
//! 建構跨檔案 call graph，追蹤污染源與接收點跨函數邊界傳播，
//! 支援可配置的 call-depth 限制以防止大型程式碼庫中的效能爆炸。

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Call graph types
// ---------------------------------------------------------------------------

/// 函數宣告及其位置資訊。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionRef {
    /// 包含此函數的檔案路徑。
    pub file_path: String,
    /// 函數名稱。
    pub name: String,
    /// 函數宣告的行號。
    pub line: u32,
    /// 函數參數名稱列表。
    #[serde(default)]
    pub parameters: Vec<String>,
    /// return 表達式中的變數名及行號（用於 return value taint propagation）。
    #[serde(default)]
    pub return_var_names: Vec<(String, u32)>,
}

/// 函數內的呼叫點。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallSite {
    /// 被呼叫的函數名稱。
    pub callee: String,
    /// 呼叫行號。
    pub line: u32,
    /// 受污染的引數索引。
    pub tainted_args: Vec<u32>,
    /// 每個引數的原始碼文字。
    #[serde(default)]
    pub argument_expressions: Vec<String>,
    /// 接收 return value 的變數名（如 `const data = foo()` 中的 `data`）。
    #[serde(default)]
    pub return_receiver: Option<String>,
}

/// Import 條目 — 記錄一個 import 聲明。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportEntry {
    /// 進行 import 的檔案路徑。
    pub file_path: String,
    /// 被 import 的名稱（本地綁定名稱）。
    pub imported_name: String,
    /// 來源模組路徑（如 `./userService`）。
    pub source_module: String,
    /// 來源模組中的 exported 名稱。
    pub exported_name: String,
}

/// Import 索引 — 解析跨檔案函數呼叫。
///
/// key: `(file_path, imported_name)` → value: `(resolved_file_path, exported_name)`
#[derive(Debug, Clone, Default)]
pub struct ImportIndex {
    /// 映射表：(file, local_name) → (source_file, export_name)。
    entries: HashMap<(String, String), (String, String)>,
}

impl ImportIndex {
    /// 建立空的 import index。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 註冊一個 import 條目。
    pub fn add(&mut self, entry: ImportEntry) {
        self.entries.insert(
            (entry.file_path, entry.imported_name),
            (entry.source_module, entry.exported_name),
        );
    }

    /// 解析某檔案中的名稱，回傳 `(source_file, exported_name)`。
    #[must_use]
    pub fn resolve(&self, file_path: &str, name: &str) -> Option<&(String, String)> {
        self.entries
            .get(&(file_path.to_string(), name.to_string()))
    }

    /// 回傳 import 條目數量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否為空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 污染源（使用者輸入、外部資料）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub file_path: String,
    pub function: String,
    pub variable: String,
    pub line: u32,
    pub source_type: String,
}

/// 污染接收點（危險操作）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub file_path: String,
    pub function: String,
    pub variable: String,
    pub line: u32,
    pub sink_type: String,
}

/// 跨檔案的污染路徑（source → sink）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: TaintSource,
    pub sink: TaintSink,
    /// 呼叫鏈中經過的函數。
    pub call_chain: Vec<FunctionRef>,
    /// 呼叫鏈深度。
    pub depth: u32,
}

// ---------------------------------------------------------------------------
// Call graph
// ---------------------------------------------------------------------------

/// L3 污染分析配置。
#[derive(Debug, Clone)]
pub struct L3TaintConfig {
    /// 最大呼叫深度。
    pub max_depth: u32,
}

impl Default for L3TaintConfig {
    fn default() -> Self {
        Self { max_depth: 5 }
    }
}

/// 跨檔案 call graph。
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// 函數索引，key 為 `file_path::function_name`。
    pub functions: BTreeMap<String, FunctionRef>,
    /// 每個函數的外出呼叫。
    pub calls: BTreeMap<String, Vec<CallSite>>,
    /// 已知污染源。
    pub sources: Vec<TaintSource>,
    /// 已知污染接收點。
    pub sinks: Vec<TaintSink>,
    /// Import 索引（跨檔案解析）。
    pub imports: ImportIndex,
}

impl CallGraph {
    /// 建立空的 call graph。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 產生函數的 key（`file_path::name`）。
    #[must_use]
    pub fn function_key(file_path: &str, name: &str) -> String {
        format!("{file_path}::{name}")
    }

    /// 註冊一個函數。
    pub fn add_function(&mut self, func: FunctionRef) {
        let key = Self::function_key(&func.file_path, &func.name);
        self.functions.insert(key, func);
    }

    /// 新增一個呼叫點。
    pub fn add_call(&mut self, caller_key: &str, call: CallSite) {
        self.calls
            .entry(caller_key.to_string())
            .or_default()
            .push(call);
    }

    /// 新增污染源。
    pub fn add_source(&mut self, source: TaintSource) {
        self.sources.push(source);
    }

    /// 新增污染接收點。
    pub fn add_sink(&mut self, sink: TaintSink) {
        self.sinks.push(sink);
    }

    /// 解析呼叫目標 — 結合 import index 與 function index。
    ///
    /// 優先嘗試：
    /// 1. 同檔案直接名稱匹配
    /// 2. 透過 import index 跨檔案解析
    /// 3. 全域名稱匹配（fallback）
    #[must_use]
    pub fn resolve_call(&self, caller_file: &str, callee_name: &str) -> Option<String> {
        // 1. 同檔案匹配
        let same_file_key = Self::function_key(caller_file, callee_name);
        if self.functions.contains_key(&same_file_key) {
            return Some(same_file_key);
        }

        // 2. Import index 解析
        if let Some((source_file, exported_name)) =
            self.imports.resolve(caller_file, callee_name)
        {
            let import_key = Self::function_key(source_file, exported_name);
            if self.functions.contains_key(&import_key) {
                return Some(import_key);
            }
        }

        // 3. 全域 fallback（名稱結尾匹配）
        let suffix = format!("::{callee_name}");
        for key in self.functions.keys() {
            if key.ends_with(&suffix) {
                return Some(key.clone());
            }
        }

        None
    }

    /// 回傳從指定函數出發在 max_depth 內可達的所有函數。
    pub fn reachable_from(&self, function_key: &str, max_depth: u32) -> BTreeSet<String> {
        let mut visited = BTreeSet::new();
        let mut queue = vec![(function_key.to_string(), 0u32)];

        while let Some((current, depth)) = queue.pop() {
            if depth > max_depth || visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            let caller_file = current.split("::").next().unwrap_or("");
            if let Some(calls) = self.calls.get(&current) {
                for call in calls {
                    if let Some(resolved) = self.resolve_call(caller_file, &call.callee) {
                        queue.push((resolved, depth + 1));
                    }
                }
            }
        }

        visited
    }

    /// 回傳已註冊的函數數量。
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// 回傳所有呼叫點數量。
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.values().map(|v| v.len()).sum()
    }
}

/// L3 分析結果。
#[derive(Debug, Clone, Default)]
pub struct L3AnalysisResult {
    /// 找到的污染路徑。
    pub taint_paths: Vec<TaintPath>,
    /// 已分析的函數數量。
    pub functions_analyzed: u32,
    /// 總呼叫數。
    pub total_calls: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_graph_new_is_empty() {
        let cg = CallGraph::new();
        assert_eq!(cg.function_count(), 0);
        assert_eq!(cg.call_count(), 0);
    }

    #[test]
    fn add_function_and_call() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "src/main.ts".to_string(),
            name: "handleRequest".to_string(),
            line: 10,
            parameters: vec!["req".to_string()],
            return_var_names: vec![],
        });
        cg.add_function(FunctionRef {
            file_path: "src/db.ts".to_string(),
            name: "queryDb".to_string(),
            line: 5,
            parameters: vec!["sql".to_string()],
            return_var_names: vec![],
        });
        cg.add_call(
            "src/main.ts::handleRequest",
            CallSite {
                callee: "queryDb".to_string(),
                line: 15,
                tainted_args: vec![0],
                argument_expressions: vec!["userInput".to_string()],
                return_receiver: None,
            },
        );

        assert_eq!(cg.function_count(), 2);
        assert_eq!(cg.call_count(), 1);
    }

    #[test]
    fn reachable_from_simple_chain() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "a.ts".to_string(),
            name: "a".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });
        cg.add_function(FunctionRef {
            file_path: "b.ts".to_string(),
            name: "b".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });
        cg.add_function(FunctionRef {
            file_path: "c.ts".to_string(),
            name: "c".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });

        cg.add_call(
            "a.ts::a",
            CallSite {
                callee: "b".to_string(),
                line: 2,
                tainted_args: vec![],
                argument_expressions: vec![],
                return_receiver: None,
            },
        );
        cg.add_call(
            "b.ts::b",
            CallSite {
                callee: "c".to_string(),
                line: 2,
                tainted_args: vec![],
                argument_expressions: vec![],
                return_receiver: None,
            },
        );

        let reachable = cg.reachable_from("a.ts::a", 5);
        assert!(reachable.contains("a.ts::a"));
        assert!(reachable.contains("b.ts::b"));
        assert!(reachable.contains("c.ts::c"));
    }

    #[test]
    fn reachable_respects_depth_limit() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "a.ts".to_string(),
            name: "a".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });
        cg.add_function(FunctionRef {
            file_path: "b.ts".to_string(),
            name: "b".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });
        cg.add_function(FunctionRef {
            file_path: "c.ts".to_string(),
            name: "c".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });

        cg.add_call(
            "a.ts::a",
            CallSite {
                callee: "b".to_string(),
                line: 2,
                tainted_args: vec![],
                argument_expressions: vec![],
                return_receiver: None,
            },
        );
        cg.add_call(
            "b.ts::b",
            CallSite {
                callee: "c".to_string(),
                line: 2,
                tainted_args: vec![],
                argument_expressions: vec![],
                return_receiver: None,
            },
        );

        // 深度 1: 只有 a 和 b 可達。
        let reachable = cg.reachable_from("a.ts::a", 1);
        assert!(reachable.contains("a.ts::a"));
        assert!(reachable.contains("b.ts::b"));
        assert!(!reachable.contains("c.ts::c"));
    }

    #[test]
    fn l3_taint_config_default() {
        let config = L3TaintConfig::default();
        assert_eq!(config.max_depth, 5);
    }

    #[test]
    fn l3_result_default() {
        let result = L3AnalysisResult::default();
        assert!(result.taint_paths.is_empty());
        assert_eq!(result.functions_analyzed, 0);
        assert_eq!(result.total_calls, 0);
    }

    #[test]
    fn add_source_and_sink() {
        let mut cg = CallGraph::new();
        cg.add_source(TaintSource {
            file_path: "src/api.ts".to_string(),
            function: "handlePost".to_string(),
            variable: "body".to_string(),
            line: 5,
            source_type: "user_input".to_string(),
        });
        cg.add_sink(TaintSink {
            file_path: "src/db.ts".to_string(),
            function: "query".to_string(),
            variable: "sql".to_string(),
            line: 10,
            sink_type: "sql_query".to_string(),
        });

        assert_eq!(cg.sources.len(), 1);
        assert_eq!(cg.sinks.len(), 1);
    }

    #[test]
    fn import_index_resolve() {
        let mut idx = ImportIndex::new();
        idx.add(ImportEntry {
            file_path: "src/controller.ts".to_string(),
            imported_name: "findUser".to_string(),
            source_module: "src/userService.ts".to_string(),
            exported_name: "findUser".to_string(),
        });

        let result = idx.resolve("src/controller.ts", "findUser");
        assert!(result.is_some());
        let (src, name) = result.unwrap();
        assert_eq!(src, "src/userService.ts");
        assert_eq!(name, "findUser");

        // 未知的 import 回傳 None
        assert!(idx.resolve("src/controller.ts", "unknown").is_none());
        assert!(idx.resolve("other.ts", "findUser").is_none());
    }

    #[test]
    fn resolve_call_same_file() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "app.ts".to_string(),
            name: "handler".to_string(),
            line: 1,
            parameters: vec![],
            return_var_names: vec![],
        });
        cg.add_function(FunctionRef {
            file_path: "app.ts".to_string(),
            name: "helper".to_string(),
            line: 10,
            parameters: vec![],
            return_var_names: vec![],
        });

        // 同檔案解析
        let resolved = cg.resolve_call("app.ts", "helper");
        assert_eq!(resolved, Some("app.ts::helper".to_string()));

        // 不存在的函數
        assert!(cg.resolve_call("app.ts", "nonexistent").is_none());
    }

    #[test]
    fn resolve_call_via_import() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "src/service.ts".to_string(),
            name: "findUser".to_string(),
            line: 5,
            parameters: vec!["name".to_string()],
            return_var_names: vec![],
        });
        cg.imports.add(ImportEntry {
            file_path: "src/controller.ts".to_string(),
            imported_name: "findUser".to_string(),
            source_module: "src/service.ts".to_string(),
            exported_name: "findUser".to_string(),
        });

        // 透過 import 解析跨檔案呼叫
        let resolved = cg.resolve_call("src/controller.ts", "findUser");
        assert_eq!(resolved, Some("src/service.ts::findUser".to_string()));
    }

    #[test]
    fn function_ref_parameters() {
        let func = FunctionRef {
            file_path: "test.ts".to_string(),
            name: "process".to_string(),
            line: 1,
            parameters: vec!["input".to_string(), "options".to_string()],
            return_var_names: vec![],
        };
        assert_eq!(func.parameters.len(), 2);
        assert_eq!(func.parameters[0], "input");
    }

    #[test]
    fn call_site_argument_expressions() {
        let cs = CallSite {
            callee: "query".to_string(),
            line: 5,
            tainted_args: vec![0],
            argument_expressions: vec!["userInput".to_string(), "\"safe\"".to_string()],
            return_receiver: None,
        };
        assert_eq!(cs.argument_expressions.len(), 2);
        assert_eq!(cs.argument_expressions[0], "userInput");
    }
}
