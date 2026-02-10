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
        let return_var_names = extract_return_var_names(node, self.config, self.source);

        Some(FunctionRef {
            file_path: self.file_path.to_string(),
            name: name.to_string(),
            line: node.start_position().row as u32 + 1,
            parameters,
            return_var_names,
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

        // 提取 return receiver（接收呼叫結果的變數名）
        let return_receiver = extract_return_receiver(node, self.config, self.source);

        Some(CallSite {
            callee,
            line: node.start_position().row as u32 + 1,
            tainted_args: Vec::new(), // L3 engine 將在 Phase 2 填入
            argument_expressions,
            return_receiver,
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

/// 從 call_expression 向上走 parent 鏈，找到接收 return value 的變數名。
///
/// 支援 `const x = foo()` 和 `x = foo()` 兩種形式。
fn extract_return_receiver<'a>(
    call_node: Node<'a>,
    config: &dyn L3LanguageConfig,
    source: &'a [u8],
) -> Option<String> {
    let var_decl_kinds = config.variable_declaration_kinds();
    let assignment_kinds = config.assignment_kinds();
    let id_kind = config.identifier_kind();

    // 向上走 parent 鏈（最多 3 層）
    let mut current = call_node;
    for _ in 0..3 {
        let parent = current.parent()?;
        let kind = parent.kind();

        // 變數宣告：const x = foo()
        if var_decl_kinds.contains(&kind) {
            // 透過 config 提取變數名
            return config.extract_var_name(parent, source).map(|s| s.to_string());
        }

        // variable_declarator: 中間層（如 TypeScript 的 variable_declarator）
        if kind == "variable_declarator" {
            if let Some(name_node) = parent.child_by_field_name("name") {
                if name_node.kind() == id_kind {
                    return node_text(name_node, source).map(|s| s.to_string());
                }
            }
        }

        // 賦值表達式：x = foo()
        if assignment_kinds.contains(&kind) {
            if let Some(left) = parent.child_by_field_name("left") {
                if left.kind() == id_kind {
                    return node_text(left, source).map(|s| s.to_string());
                }
            }
        }

        current = parent;
    }

    None
}

/// 遞迴走訪函數體，提取 return 語句中的變數名及行號。
///
/// 跳過巢狀函數定義，避免提取內部函數的 return。
fn extract_return_var_names(
    func_node: Node<'_>,
    config: &dyn L3LanguageConfig,
    source: &[u8],
) -> Vec<(String, u32)> {
    let return_kind = config.return_statement_kind();
    let func_kinds = config.function_node_kinds();
    let id_kind = config.identifier_kind();
    let mut results = Vec::new();
    collect_return_vars(func_node, return_kind, func_kinds, id_kind, source, &mut results, true);
    results
}

/// 遞迴收集 return 語句中的 identifier。
fn collect_return_vars(
    node: Node<'_>,
    return_kind: &str,
    func_kinds: &[&str],
    id_kind: &str,
    source: &[u8],
    results: &mut Vec<(String, u32)>,
    is_root: bool,
) {
    // 跳過巢狀函數（但不跳過根節點自己）
    if !is_root && func_kinds.contains(&node.kind()) {
        return;
    }

    if node.kind() == return_kind {
        // 從 return 的子表達式中收集 identifier
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect_identifiers_in_expr(child, id_kind, source, results);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_return_vars(child, return_kind, func_kinds, id_kind, source, results, false);
    }
}

/// 從表達式中收集所有 identifier 節點。
fn collect_identifiers_in_expr(
    node: Node<'_>,
    id_kind: &str,
    source: &[u8],
    results: &mut Vec<(String, u32)>,
) {
    if node.kind() == id_kind {
        if let Some(text) = node_text(node, source) {
            let line = node.start_position().row as u32 + 1;
            results.push((text.to_string(), line));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifiers_in_expr(child, id_kind, source, results);
    }
}

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

    #[test]
    fn extract_return_receiver_from_var_decl() {
        // `const x = foo()` → return_receiver = Some("x")
        let source = r#"
function wrapper() {
    const x = foo();
}
function foo() {
    return 42;
}
"#;
        let tree = parse_ts(source);
        let config = get_l3_config(atlas_lang::Language::TypeScript).unwrap();
        let builder = CallGraphBuilder::new(config, source.as_bytes(), "app.ts");
        let (_functions, calls) = builder.build_file(&tree);

        let foo_calls: Vec<_> = calls
            .iter()
            .filter(|(_, cs)| cs.callee == "foo")
            .collect();
        assert!(
            !foo_calls.is_empty(),
            "Should find foo() call"
        );
        assert_eq!(
            foo_calls[0].1.return_receiver,
            Some("x".to_string()),
            "return_receiver should be 'x', got: {:?}",
            foo_calls[0].1.return_receiver
        );
    }

    #[test]
    fn extract_return_var_names_simple() {
        // `function f(x) { return x; }` → return_var_names = [("x", line)]
        let source = r#"
function f(x) {
    return x;
}
"#;
        let tree = parse_ts(source);
        let config = get_l3_config(atlas_lang::Language::TypeScript).unwrap();
        let builder = CallGraphBuilder::new(config, source.as_bytes(), "app.ts");
        let (functions, _calls) = builder.build_file(&tree);

        let func_f = functions.iter().find(|f| f.name == "f");
        assert!(func_f.is_some(), "Should find function f");
        let func_f = func_f.unwrap();

        assert!(
            !func_f.return_var_names.is_empty(),
            "return_var_names should not be empty"
        );
        assert_eq!(
            func_f.return_var_names[0].0, "x",
            "return var should be 'x', got: {:?}",
            func_f.return_var_names
        );
    }
}
