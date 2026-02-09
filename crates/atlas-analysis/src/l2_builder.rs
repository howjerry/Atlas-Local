//! L2 Scope Graph 構建器 — 從 tree-sitter AST 建構 scope graph。
//!
//! 包含 `L2LanguageConfig` trait（抽象語言差異）和 `ScopeGraphBuilder`
//! （走訪 AST 收集變數定義與使用）。

use tree_sitter::{Node, Tree};

use crate::l2_intraprocedural::{Scope, ScopeGraph, TaintState, VarDef, VarUse};
use crate::l2_taint_config::TaintConfig;

// ---------------------------------------------------------------------------
// L2LanguageConfig trait
// ---------------------------------------------------------------------------

/// 抽象各語言 AST 節點類型差異的 trait。
pub trait L2LanguageConfig: Send + Sync {
    /// 函數宣告節點類型（如 function_declaration, method_definition）。
    fn function_node_kinds(&self) -> &[&str];
    /// 變數宣告節點類型（如 lexical_declaration, variable_declaration）。
    fn variable_declaration_kinds(&self) -> &[&str];
    /// 呼叫表達式節點類型。
    fn call_expression_kind(&self) -> &str;
    /// 賦值表達式節點類型。
    fn assignment_kinds(&self) -> &[&str];
    /// 識別碼節點類型。
    fn identifier_kind(&self) -> &str;
    /// 字串文字節點類型。
    fn string_literal_kinds(&self) -> &[&str];
    /// 模板字串節點類型（無則回傳 None）。
    fn template_literal_kind(&self) -> Option<&str>;
    /// 區塊（block scope）節點類型。
    fn block_kinds(&self) -> &[&str];
    /// 從變數宣告節點提取變數名稱。
    fn extract_var_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<&'a str>;
    /// 從呼叫表達式提取函數名稱（含 member access，如 `db.query`）。
    fn extract_call_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<String>;
    /// 二元表達式節點類型（含字串串接）。
    fn binary_expression_kind(&self) -> &str;
}

// ---------------------------------------------------------------------------
// TypeScript 配置
// ---------------------------------------------------------------------------

/// TypeScript / JavaScript L2 語言配置。
pub struct TypeScriptL2Config;

impl L2LanguageConfig for TypeScriptL2Config {
    fn function_node_kinds(&self) -> &[&str] {
        &[
            "function_declaration",
            "arrow_function",
            "method_definition",
            "function",
        ]
    }
    fn variable_declaration_kinds(&self) -> &[&str] {
        &["lexical_declaration", "variable_declaration"]
    }
    fn call_expression_kind(&self) -> &str {
        "call_expression"
    }
    fn assignment_kinds(&self) -> &[&str] {
        &["assignment_expression", "augmented_assignment_expression"]
    }
    fn identifier_kind(&self) -> &str {
        "identifier"
    }
    fn string_literal_kinds(&self) -> &[&str] {
        &["string", "string_fragment"]
    }
    fn template_literal_kind(&self) -> Option<&str> {
        Some("template_string")
    }
    fn block_kinds(&self) -> &[&str] {
        &["statement_block"]
    }
    fn extract_var_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
        // lexical_declaration → variable_declarator → name (identifier)
        let declarator = find_child_by_kind(node, "variable_declarator")?;
        let name_node = declarator.child_by_field_name("name")?;
        node_text(name_node, source)
    }
    fn extract_call_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

// ---------------------------------------------------------------------------
// Java 配置
// ---------------------------------------------------------------------------

/// Java L2 語言配置。
pub struct JavaL2Config;

impl L2LanguageConfig for JavaL2Config {
    fn function_node_kinds(&self) -> &[&str] {
        &["method_declaration", "constructor_declaration"]
    }
    fn variable_declaration_kinds(&self) -> &[&str] {
        &["local_variable_declaration"]
    }
    fn call_expression_kind(&self) -> &str {
        "method_invocation"
    }
    fn assignment_kinds(&self) -> &[&str] {
        &["assignment_expression"]
    }
    fn identifier_kind(&self) -> &str {
        "identifier"
    }
    fn string_literal_kinds(&self) -> &[&str] {
        &["string_literal"]
    }
    fn template_literal_kind(&self) -> Option<&str> {
        None
    }
    fn block_kinds(&self) -> &[&str] {
        &["block"]
    }
    fn extract_var_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
        // local_variable_declaration → variable_declarator → name (identifier)
        let declarator = find_child_by_kind(node, "variable_declarator")?;
        let name_node = declarator.child_by_field_name("name")?;
        node_text(name_node, source)
    }
    fn extract_call_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<String> {
        // method_invocation 的 name 或 object.name
        let name_node = node.child_by_field_name("name")?;
        let name = node_text(name_node, source)?;
        // 檢查是否有 object（如 statement.executeQuery）
        if let Some(obj) = node.child_by_field_name("object") {
            let obj_text = node_text(obj, source)?;
            return Some(format!("{obj_text}.{name}"));
        }
        Some(name.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

// ---------------------------------------------------------------------------
// Python 配置
// ---------------------------------------------------------------------------

/// Python L2 語言配置。
pub struct PythonL2Config;

impl L2LanguageConfig for PythonL2Config {
    fn function_node_kinds(&self) -> &[&str] {
        &["function_definition"]
    }
    fn variable_declaration_kinds(&self) -> &[&str] {
        // Python 沒有明確的變數宣告，賦值即宣告
        &["assignment"]
    }
    fn call_expression_kind(&self) -> &str {
        "call"
    }
    fn assignment_kinds(&self) -> &[&str] {
        &["assignment", "augmented_assignment"]
    }
    fn identifier_kind(&self) -> &str {
        "identifier"
    }
    fn string_literal_kinds(&self) -> &[&str] {
        &["string"]
    }
    fn template_literal_kind(&self) -> Option<&str> {
        Some("string") // Python f-string 也是 string 節點
    }
    fn block_kinds(&self) -> &[&str] {
        &["block"]
    }
    fn extract_var_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
        // assignment → left (identifier)
        let left = node.child_by_field_name("left")?;
        if left.kind() == "identifier" {
            return node_text(left, source);
        }
        None
    }
    fn extract_call_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_operator"
    }
}

// ---------------------------------------------------------------------------
// C# 配置
// ---------------------------------------------------------------------------

/// C# L2 語言配置。
pub struct CSharpL2Config;

impl L2LanguageConfig for CSharpL2Config {
    fn function_node_kinds(&self) -> &[&str] {
        &["method_declaration", "constructor_declaration"]
    }
    fn variable_declaration_kinds(&self) -> &[&str] {
        &["local_declaration_statement"]
    }
    fn call_expression_kind(&self) -> &str {
        "invocation_expression"
    }
    fn assignment_kinds(&self) -> &[&str] {
        &["assignment_expression"]
    }
    fn identifier_kind(&self) -> &str {
        "identifier"
    }
    fn string_literal_kinds(&self) -> &[&str] {
        &["string_literal", "verbatim_string_literal"]
    }
    fn template_literal_kind(&self) -> Option<&str> {
        Some("interpolated_string_expression")
    }
    fn block_kinds(&self) -> &[&str] {
        &["block"]
    }
    fn extract_var_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
        // local_declaration_statement → variable_declaration → variable_declarator → identifier
        let var_decl = find_child_by_kind(node, "variable_declaration")?;
        let declarator = find_child_by_kind(var_decl, "variable_declarator")?;
        let name_node = find_child_by_kind(declarator, "identifier")?;
        node_text(name_node, source)
    }
    fn extract_call_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<String> {
        // invocation_expression → function (member_access_expression 或 identifier)
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

// ---------------------------------------------------------------------------
// Go 配置
// ---------------------------------------------------------------------------

/// Go L2 語言配置。
pub struct GoL2Config;

impl L2LanguageConfig for GoL2Config {
    fn function_node_kinds(&self) -> &[&str] {
        &["function_declaration", "method_declaration"]
    }
    fn variable_declaration_kinds(&self) -> &[&str] {
        &["short_var_declaration", "var_declaration"]
    }
    fn call_expression_kind(&self) -> &str {
        "call_expression"
    }
    fn assignment_kinds(&self) -> &[&str] {
        &["assignment_statement", "short_var_declaration"]
    }
    fn identifier_kind(&self) -> &str {
        "identifier"
    }
    fn string_literal_kinds(&self) -> &[&str] {
        &["interpreted_string_literal", "raw_string_literal"]
    }
    fn template_literal_kind(&self) -> Option<&str> {
        None // Go 沒有模板字串
    }
    fn block_kinds(&self) -> &[&str] {
        &["block"]
    }
    fn extract_var_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
        // short_var_declaration → left (expression_list → identifier)
        if let Some(left) = node.child_by_field_name("left") {
            // expression_list 的第一個子節點
            if left.kind() == "expression_list" {
                let first = left.child(0)?;
                return node_text(first, source);
            }
            return node_text(left, source);
        }
        None
    }
    fn extract_call_name<'a>(&self, node: Node<'a>, source: &'a [u8]) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

// ---------------------------------------------------------------------------
// 語言配置註冊
// ---------------------------------------------------------------------------

/// 根據語言取得對應的 L2 語言配置。
pub fn get_l2_config(language: atlas_lang::Language) -> Option<&'static dyn L2LanguageConfig> {
    match language {
        atlas_lang::Language::TypeScript | atlas_lang::Language::JavaScript => {
            Some(&TypeScriptL2Config)
        }
        atlas_lang::Language::Java => Some(&JavaL2Config),
        atlas_lang::Language::Python => Some(&PythonL2Config),
        atlas_lang::Language::CSharp => Some(&CSharpL2Config),
        atlas_lang::Language::Go => Some(&GoL2Config),
    }
}

// ---------------------------------------------------------------------------
// ScopeGraphBuilder
// ---------------------------------------------------------------------------

/// 從 tree-sitter AST 構建 ScopeGraph 的建構器。
pub struct ScopeGraphBuilder<'a> {
    source: &'a [u8],
    config: &'a dyn L2LanguageConfig,
    taint_config: &'a TaintConfig,
}

impl<'a> ScopeGraphBuilder<'a> {
    /// 建立新的 ScopeGraphBuilder。
    pub fn new(
        source: &'a [u8],
        config: &'a dyn L2LanguageConfig,
        taint_config: &'a TaintConfig,
    ) -> Self {
        Self {
            source,
            config,
            taint_config,
        }
    }

    /// 從 AST 提取所有函數節點，並為每個函數構建 ScopeGraph。
    ///
    /// 回傳 `(函數名稱, ScopeGraph)` 的列表。
    pub fn build_all(&self, tree: &Tree) -> Vec<(String, ScopeGraph)> {
        let root = tree.root_node();
        let mut results = Vec::new();
        self.find_functions(root, &mut results);
        results
    }

    /// 遞迴搜尋函數節點。
    fn find_functions(&self, node: Node, results: &mut Vec<(String, ScopeGraph)>) {
        let kind = node.kind();
        if self.config.function_node_kinds().contains(&kind) {
            let func_name = self.extract_function_name(node);
            let sg = self.build_scope_graph(node);
            results.push((func_name, sg));
            return; // 不遞迴進入嵌套函數（L2 是 intra-procedural）
        }
        // 遞迴搜尋子節點
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_functions(child, results);
        }
    }

    /// 提取函數名稱。
    fn extract_function_name(&self, node: Node) -> String {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Some(name) = node_text(name_node, self.source) {
                return name.to_string();
            }
        }
        // 匿名函數用行號標識
        format!("<anonymous>:{}", node.start_position().row + 1)
    }

    /// 為單一函數建構 ScopeGraph。
    fn build_scope_graph(&self, func_node: Node) -> ScopeGraph {
        let mut sg = ScopeGraph::new();
        // 下一個可分配的 scope ID（0 已被根作用域使用）
        let mut next_scope_id = 1u32;

        // 建立根作用域
        sg.add_scope(Scope {
            id: 0,
            parent: None,
            level: 0,
        });

        // 找到函數體節點，直接走訪其子節點。
        // 跳過函數體的 statement_block 本身，避免建立多餘的作用域。
        if let Some(body) = func_node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                self.walk_node(child, 0, &mut next_scope_id, &mut sg);
            }
        }

        sg
    }

    /// 遞迴走訪節點，收集 VarDef 和 VarUse。
    fn walk_node(
        &self,
        node: Node,
        current_scope: u32,
        next_scope_id: &mut u32,
        sg: &mut ScopeGraph,
    ) {
        let kind = node.kind();

        // 區塊節點建立新的子作用域
        if self.config.block_kinds().contains(&kind) && *next_scope_id > 0 {
            *next_scope_id += 1;
            let new_scope = *next_scope_id;
            sg.add_scope(Scope {
                id: new_scope,
                parent: Some(current_scope),
                level: sg.scopes.iter().find(|s| s.id == current_scope).map_or(0, |s| s.level + 1),
            });
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                self.walk_node(child, new_scope, next_scope_id, sg);
            }
            return;
        }

        // 變數宣告
        if self.config.variable_declaration_kinds().contains(&kind) {
            if let Some(name) = self.config.extract_var_name(node, self.source) {
                let tainted = self.check_initializer_tainted(node);
                let sanitized = self.check_initializer_sanitized(node);
                let taint_state = if tainted {
                    TaintState::Tainted
                } else if sanitized {
                    TaintState::Clean
                } else {
                    TaintState::Unknown
                };
                sg.add_definition(VarDef {
                    name: name.to_string(),
                    def_line: node.start_position().row as u32 + 1,
                    tainted,
                    taint_state,
                    scope_id: current_scope,
                });
            }
        }

        // 賦值表達式（重新賦值）
        if self.config.assignment_kinds().contains(&kind)
            && !self.config.variable_declaration_kinds().contains(&kind)
        {
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == self.config.identifier_kind() {
                    if let Some(name) = node_text(left, self.source) {
                        let tainted = self.check_rhs_tainted(node);
                        let sanitized = self.check_rhs_sanitized(node);
                        let taint_state = if tainted {
                            TaintState::Tainted
                        } else if sanitized {
                            TaintState::Clean
                        } else {
                            TaintState::Clean
                        };
                        sg.add_definition(VarDef {
                            name: name.to_string(),
                            def_line: node.start_position().row as u32 + 1,
                            tainted,
                            taint_state,
                            scope_id: current_scope,
                        });
                    }
                }
            }
        }

        // 呼叫表達式 — 提取引數中的變數使用
        if kind == self.config.call_expression_kind() {
            self.extract_call_var_uses(node, current_scope, sg);
        }

        // 識別碼作為變數使用（在表達式上下文中）
        if kind == self.config.identifier_kind() {
            // 只在非宣告/非函數名稱的上下文中記錄
            if let Some(parent) = node.parent() {
                let parent_kind = parent.kind();
                // 跳過：函數名稱、變數宣告名稱、物件屬性名稱
                let is_name_field =
                    parent.child_by_field_name("name").is_some_and(|n| n.id() == node.id());
                if !is_name_field
                    && !self.config.variable_declaration_kinds().contains(&parent_kind)
                    && parent_kind != "variable_declarator"
                {
                    if let Some(name) = node_text(node, self.source) {
                        sg.add_use(VarUse {
                            name: name.to_string(),
                            use_line: node.start_position().row as u32 + 1,
                            resolved_def: None,
                        });
                    }
                }
            }
        }

        // 遞迴子節點（跳過巢狀函數）
        if !self.config.function_node_kinds().contains(&kind) || node.parent().is_none() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let child_kind = child.kind();
                // 不遞迴進入巢狀函數
                if self.config.function_node_kinds().contains(&child_kind) {
                    continue;
                }
                self.walk_node(child, current_scope, next_scope_id, sg);
            }
        }
    }

    /// 檢查變數宣告的初始值是否來自污染源。
    fn check_initializer_tainted(&self, decl_node: Node) -> bool {
        // 找到初始值表達式的文字
        let text = node_text(decl_node, self.source).unwrap_or("");
        self.text_matches_any_source(text)
    }

    /// 檢查賦值右側是否受污染。
    fn check_rhs_tainted(&self, assign_node: Node) -> bool {
        if let Some(right) = assign_node.child_by_field_name("right") {
            let text = node_text(right, self.source).unwrap_or("");
            return self.text_matches_any_source(text);
        }
        false
    }

    /// 檢查文字中是否包含任何污染源模式。
    fn text_matches_any_source(&self, text: &str) -> bool {
        self.taint_config
            .sources
            .iter()
            .any(|src| text.contains(&src.pattern))
    }

    /// 檢查變數宣告的初始值是否經過 sanitizer 處理。
    fn check_initializer_sanitized(&self, decl_node: Node) -> bool {
        let text = node_text(decl_node, self.source).unwrap_or("");
        self.text_matches_any_sanitizer(text)
    }

    /// 檢查賦值右側是否經過 sanitizer 處理。
    fn check_rhs_sanitized(&self, assign_node: Node) -> bool {
        if let Some(right) = assign_node.child_by_field_name("right") {
            let text = node_text(right, self.source).unwrap_or("");
            return self.text_matches_any_sanitizer(text);
        }
        false
    }

    /// 檢查文字中是否包含任何 sanitizer 函數呼叫。
    fn text_matches_any_sanitizer(&self, text: &str) -> bool {
        self.taint_config
            .sanitizers
            .iter()
            .any(|san| text.contains(&san.function))
    }

    /// 從呼叫表達式提取引數中的變數使用。
    fn extract_call_var_uses(&self, call_node: Node, _scope: u32, _sg: &mut ScopeGraph) {
        // 引數中的識別碼會被一般的 identifier 走訪捕捉，不需額外處理
        let _ = call_node;
    }
}

// ---------------------------------------------------------------------------
// 工具函數
// ---------------------------------------------------------------------------

/// 從節點取得原始碼文字。
fn node_text<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
    std::str::from_utf8(&source[node.byte_range()]).ok()
}

/// 在子節點中找到第一個符合指定 kind 的節點。
fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_lang::Language;

    #[test]
    fn typescript_config_function_nodes() {
        let config = TypeScriptL2Config;
        let kinds = config.function_node_kinds();
        assert!(kinds.contains(&"function_declaration"));
        assert!(kinds.contains(&"arrow_function"));
        assert!(kinds.contains(&"method_definition"));
    }

    #[test]
    fn java_config_variable_nodes() {
        let config = JavaL2Config;
        let kinds = config.variable_declaration_kinds();
        assert!(kinds.contains(&"local_variable_declaration"));
    }

    #[test]
    fn python_config_call_kind() {
        let config = PythonL2Config;
        assert_eq!(config.call_expression_kind(), "call");
    }

    #[test]
    fn csharp_config_template_literal() {
        let config = CSharpL2Config;
        assert_eq!(
            config.template_literal_kind(),
            Some("interpolated_string_expression")
        );
    }

    #[test]
    fn go_config_no_template_literal() {
        let config = GoL2Config;
        assert_eq!(config.template_literal_kind(), None);
    }

    #[test]
    fn all_languages_have_configs() {
        for lang in [
            Language::TypeScript,
            Language::JavaScript,
            Language::Java,
            Language::Python,
            Language::CSharp,
            Language::Go,
        ] {
            assert!(
                get_l2_config(lang).is_some(),
                "語言 {lang} 應有 L2 配置"
            );
        }
    }

    #[test]
    fn go_config_assignment_kinds() {
        let config = GoL2Config;
        let kinds = config.assignment_kinds();
        assert!(kinds.contains(&"assignment_statement"));
        assert!(kinds.contains(&"short_var_declaration"));
    }

    // --- ScopeGraphBuilder 整合測試（使用 TypeScript） ---

    #[test]
    fn build_scope_graph_simple_ts_function() {
        let source = br#"function handler(req) {
    const name = req.body.name;
    db.query(name);
}"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let taint_config = crate::l2_taint_config::load_taint_config(Language::TypeScript).unwrap();
        let config = TypeScriptL2Config;
        let builder = ScopeGraphBuilder::new(source, &config, &taint_config);
        let results = builder.build_all(&tree);

        assert_eq!(results.len(), 1, "應找到 1 個函數");
        let (name, sg) = &results[0];
        assert_eq!(name, "handler");
        // 應有至少一個 tainted 的 VarDef（name = req.body.name）
        assert!(
            sg.definitions.iter().any(|d| d.name == "name" && d.tainted),
            "name 變數應被標記為 tainted"
        );
    }

    #[test]
    fn build_scope_graph_empty_function() {
        let source = b"function empty() {}";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let taint_config = crate::l2_taint_config::load_taint_config(Language::TypeScript).unwrap();
        let config = TypeScriptL2Config;
        let builder = ScopeGraphBuilder::new(source, &config, &taint_config);
        let results = builder.build_all(&tree);

        assert_eq!(results.len(), 1);
        let (_, sg) = &results[0];
        assert!(sg.definitions.is_empty());
        assert!(sg.uses.is_empty());
    }

    #[test]
    fn build_scope_graph_block_scoping() {
        let source = br#"function test() {
    if (true) {
        const x = 1;
    }
    console.log(x);
}"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();

        let taint_config = crate::l2_taint_config::load_taint_config(Language::TypeScript).unwrap();
        let config = TypeScriptL2Config;
        let builder = ScopeGraphBuilder::new(source, &config, &taint_config);
        let results = builder.build_all(&tree);

        assert_eq!(results.len(), 1);
        let (_, sg) = &results[0];
        // 應有多個作用域（根 + if block）
        assert!(
            sg.scopes.len() >= 2,
            "應有至少 2 個作用域，實際: {}",
            sg.scopes.len()
        );
        // x 的定義應在子作用域
        let x_def = sg.definitions.iter().find(|d| d.name == "x");
        assert!(x_def.is_some(), "應找到 x 的定義");
        assert!(x_def.unwrap().scope_id > 0, "x 應在子作用域中");
    }
}
