//! Call Graph 建構器 — 從 tree-sitter AST 提取函數定義與呼叫點。
//!
//! Phase 1 的核心模組，per-file 執行：
//! 1. 遞迴走訪 AST 提取函數定義 → `FunctionRef`
//! 2. 在每個函數內提取呼叫表達式 → `CallSite`
//! 3. 解析 class 方法呼叫（`this.method()` / `self.method()`）

use tree_sitter::{Node, Tree};

use crate::l3_interprocedural::{CallSite, FunctionRef};
use crate::l3_lang_config::L3LanguageConfig;

// ---------------------------------------------------------------------------
// CallGraphBuilder
// ---------------------------------------------------------------------------

/// 從 tree-sitter AST 建構 call graph 的 per-file 建構器。
pub struct CallGraphBuilder<'a> {
    config: &'a dyn L3LanguageConfig,
    source: &'a [u8],
    file_path: &'a str,
}

impl<'a> CallGraphBuilder<'a> {
    /// 建立新的 CallGraphBuilder。
    pub fn new(
        config: &'a dyn L3LanguageConfig,
        source: &'a [u8],
        file_path: &'a str,
    ) -> Self {
        Self {
            config,
            source,
            file_path,
        }
    }

    /// 從 AST 提取函數定義與呼叫點。
    ///
    /// 回傳 `(函數定義列表, [(caller_key, CallSite)])`。
    pub fn build_file(
        &self,
        tree: &Tree,
    ) -> (Vec<FunctionRef>, Vec<(String, CallSite)>) {
        let root = tree.root_node();
        let mut functions = Vec::new();
        let mut calls = Vec::new();

        self.extract_functions(root, &mut functions, &mut calls, None);

        (functions, calls)
    }

    /// 遞迴走訪 AST，提取函數定義及其內部的呼叫點。
    fn extract_functions(
        &self,
        node: Node<'_>,
        functions: &mut Vec<FunctionRef>,
        calls: &mut Vec<(String, CallSite)>,
        current_class: Option<&str>,
    ) {
        let func_kinds = self.config.function_node_kinds();

        // 檢查是否為 class 定義（用於解析 this.method()）
        let class_name = if node.kind() == "class_declaration"
            || node.kind() == "class_definition"
            || node.kind() == "class"
        {
            node.child_by_field_name("name")
                .and_then(|n| node_text(n, self.source))
        } else {
            None
        };

        let active_class = class_name.or(current_class);

        if func_kinds.contains(&node.kind()) {
            // 提取函數定義
            if let Some(func_ref) = self.extract_function_def(node) {
                let caller_key = format!("{}::{}", self.file_path, func_ref.name);
                functions.push(func_ref);

                // 在此函數內提取呼叫點（不進入巢狀函數）
                self.extract_calls_in_function(
                    node,
                    &caller_key,
                    calls,
                    active_class,
                );
            }
            return; // 不再遞迴進入巢狀函數
        }

        // 繼續遞迴
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_functions(child, functions, calls, active_class);
        }
    }

    /// 從函數節點提取 FunctionRef。
    fn extract_function_def(&self, node: Node<'_>) -> Option<FunctionRef> {
        let name = self.config.extract_function_name(node, self.source)?;
        let parameters = self.config.extract_parameters(node, self.source);

        Some(FunctionRef {
            file_path: self.file_path.to_string(),
            name: name.to_string(),
            line: node.start_position().row as u32 + 1,
            parameters,
        })
    }

    /// 在函數體內提取呼叫點（不進入巢狀函數定義）。
    fn extract_calls_in_function(
        &self,
        node: Node<'_>,
        caller_key: &str,
        calls: &mut Vec<(String, CallSite)>,
        current_class: Option<&str>,
    ) {
        let call_kind = self.config.call_expression_kind();
        let func_kinds = self.config.function_node_kinds();

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // 跳過巢狀函數定義
            if func_kinds.contains(&child.kind()) {
                continue;
            }

            if child.kind() == call_kind {
                if let Some(call_site) =
                    self.extract_call_site(child, current_class)
                {
                    calls.push((caller_key.to_string(), call_site));
                }
            }

            // 繼續遞迴（但跳過巢狀函數）
            self.extract_calls_in_function(child, caller_key, calls, current_class);
        }
    }

    /// 從 call expression 節點提取 CallSite。
    fn extract_call_site(
        &self,
        node: Node<'_>,
        current_class: Option<&str>,
    ) -> Option<CallSite> {
        let raw_name = self.config.extract_call_name(node, self.source)?;

        // 解析呼叫名稱：處理 this.method() / self.method()
        let callee = resolve_callee_name(&raw_name, current_class);

        // 提取引數表達式
        let argument_expressions = self.extract_arguments(node);

        Some(CallSite {
            callee,
            line: node.start_position().row as u32 + 1,
            tainted_args: Vec::new(), // L3 engine 將在 Phase 2 填入
            argument_expressions,
        })
    }

    /// 從 call expression 提取引數表達式文字。
    fn extract_arguments(&self, node: Node<'_>) -> Vec<String> {
        let mut args = Vec::new();

        // 尋找 arguments 節點（不同語言名稱不同）
        let arg_list = node
            .child_by_field_name("arguments")
            .or_else(|| find_child_by_kind(node, "argument_list"))
            .or_else(|| find_child_by_kind(node, "arguments"));

        if let Some(arg_list) = arg_list {
            let mut cursor = arg_list.walk();
            for child in arg_list.children(&mut cursor) {
                // 跳過分隔符號（逗號、括號）
                if child.kind() == "," || child.kind() == "(" || child.kind() == ")" {
                    continue;
                }
                // 跳過 argument wrapper（某些語言如 C# 有 argument 包裝節點）
                let expr = if child.kind() == "argument" {
                    // 取第一個非標點符號子節點
                    let mut c2 = child.walk();
                    child
                        .children(&mut c2)
                        .find(|c| c.kind() != "," && c.kind() != "(" && c.kind() != ")")
                } else {
                    Some(child)
                };

                if let Some(expr) = expr {
                    if let Some(text) = node_text(expr, self.source) {
                        args.push(text.to_string());
                    }
                }
            }
        }

        args
    }
}

// ---------------------------------------------------------------------------
// 輔助函式
// ---------------------------------------------------------------------------

/// 解析呼叫名稱 — 處理 this/self 前綴。
fn resolve_callee_name(raw_name: &str, current_class: Option<&str>) -> String {
    // 移除 this. / self. 前綴，保留方法名
    if let Some(method) = raw_name
        .strip_prefix("this.")
        .or_else(|| raw_name.strip_prefix("self."))
    {
        // 如果在 class 內，方法名即為 callee
        let _ = current_class; // class context 已用於限定解析範圍
        return method.to_string();
    }
    raw_name.to_string()
}

/// 從 AST node 提取文字。
fn node_text<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    std::str::from_utf8(&source[node.byte_range()]).ok()
}

/// 搜尋某個 kind 的子節點。
fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|c| c.kind() == kind)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3_lang_config::{get_l3_config, TypeScriptL3Config};

    fn parse_ts(source: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("set language");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    #[test]
    fn extract_function_definitions() {
        let source = r#"
function handleRequest(req, res) {
    console.log("hello");
}

function queryDb(sql) {
    return db.execute(sql);
}
"#;
        let tree = parse_ts(source);
        let config = get_l3_config(atlas_lang::Language::TypeScript).unwrap();
        let builder = CallGraphBuilder::new(config, source.as_bytes(), "app.ts");
        let (functions, _calls) = builder.build_file(&tree);

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "handleRequest");
        assert_eq!(functions[0].parameters, vec!["req", "res"]);
        assert_eq!(functions[1].name, "queryDb");
        assert_eq!(functions[1].parameters, vec!["sql"]);
    }

    #[test]
    fn extract_call_sites_same_file() {
        let source = r#"
function handleRequest(req) {
    const input = req.body.name;
    queryDb(input);
}

function queryDb(sql) {
    db.execute(sql);
}
"#;
        let tree = parse_ts(source);
        let config = get_l3_config(atlas_lang::Language::TypeScript).unwrap();
        let builder = CallGraphBuilder::new(config, source.as_bytes(), "app.ts");
        let (_functions, calls) = builder.build_file(&tree);

        // handleRequest 內有 2 個呼叫：req.body.name (member access) 和 queryDb(input)
        let handle_calls: Vec<_> = calls
            .iter()
            .filter(|(k, _)| k == "app.ts::handleRequest")
            .collect();
        // 至少有 queryDb 呼叫
        assert!(
            handle_calls.iter().any(|(_, cs)| cs.callee == "queryDb"),
            "Should find queryDb call, got: {:?}",
            handle_calls
        );
    }

    #[test]
    fn extract_class_method_call() {
        let source = r#"
class UserService {
    processData(data) {
        this.validate(data);
    }
    validate(input) {
        return input.trim();
    }
}
"#;
        let tree = parse_ts(source);
        let config: &dyn L3LanguageConfig = &TypeScriptL3Config;
        let builder = CallGraphBuilder::new(config, source.as_bytes(), "service.ts");
        let (functions, calls) = builder.build_file(&tree);

        // 確認 processData 和 validate 都被提取
        let func_names: Vec<_> = functions.iter().map(|f| &f.name).collect();
        assert!(func_names.contains(&&"processData".to_string()));
        assert!(func_names.contains(&&"validate".to_string()));

        // 確認 this.validate 被解析為 validate
        let process_calls: Vec<_> = calls
            .iter()
            .filter(|(k, _)| k.contains("processData"))
            .collect();
        assert!(
            process_calls.iter().any(|(_, cs)| cs.callee == "validate"),
            "this.validate should resolve to validate, got: {:?}",
            process_calls
        );
    }

    #[test]
    fn unresolvable_calls_included_in_output() {
        let source = r#"
function handler(req) {
    externalLib.doSomething(req.body);
}
"#;
        let tree = parse_ts(source);
        let config = get_l3_config(atlas_lang::Language::TypeScript).unwrap();
        let builder = CallGraphBuilder::new(config, source.as_bytes(), "app.ts");
        let (_functions, calls) = builder.build_file(&tree);

        // 呼叫會被提取，但 resolve_call 在 CallGraph 層級判斷是否可解析
        let handler_calls: Vec<_> = calls
            .iter()
            .filter(|(k, _)| k.contains("handler"))
            .collect();
        assert!(
            handler_calls
                .iter()
                .any(|(_, cs)| cs.callee.contains("doSomething")),
            "External call should still be extracted, got: {:?}",
            handler_calls
        );
    }
}
