//! L3 語言配置 — 擴展 L2 配置，提供 call graph 建構所需的額外 AST 節點映射。

use crate::l2_builder::L2LanguageConfig;

// ---------------------------------------------------------------------------
// L3LanguageConfig trait
// ---------------------------------------------------------------------------

/// 擴展 L2LanguageConfig，新增 L3 call graph 建構所需的 AST 節點類型。
pub trait L3LanguageConfig: L2LanguageConfig {
    /// 參數列表節點類型（如 formal_parameters, parameter_list）。
    fn parameter_list_kind(&self) -> &str;

    /// return 陳述句節點類型。
    fn return_statement_kind(&self) -> &str;

    /// import 語句節點類型（跨檔案解析用，可為空表示不支援跨檔案）。
    fn import_statement_kinds(&self) -> &[&str];

    /// export 語句節點類型（跨檔案解析用，可為空表示不支援跨檔案）。
    fn export_kinds(&self) -> &[&str];

    /// 從函數節點提取函數名稱。
    fn extract_function_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str>;

    /// 從參數列表節點提取參數名稱列表。
    fn extract_parameters<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// TypeScript / JavaScript
// ---------------------------------------------------------------------------

/// TypeScript / JavaScript L3 語言配置。
pub struct TypeScriptL3Config;

impl L2LanguageConfig for TypeScriptL3Config {
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
    fn extract_var_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        let declarator = find_child_by_kind(node, "variable_declarator")?;
        let name_node = declarator.child_by_field_name("name")?;
        node_text(name_node, source)
    }
    fn extract_call_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

impl L3LanguageConfig for TypeScriptL3Config {
    fn parameter_list_kind(&self) -> &str {
        "formal_parameters"
    }
    fn return_statement_kind(&self) -> &str {
        "return_statement"
    }
    fn import_statement_kinds(&self) -> &[&str] {
        &["import_statement"]
    }
    fn export_kinds(&self) -> &[&str] {
        &["export_statement"]
    }
    fn extract_function_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        // function_declaration → name (identifier)
        // method_definition → name (property_identifier)
        node.child_by_field_name("name")
            .and_then(|n| node_text(n, source))
    }
    fn extract_parameters<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Vec<String> {
        extract_param_identifiers(node, "formal_parameters", "identifier", source)
    }
}

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

/// Java L3 語言配置。
pub struct JavaL3Config;

impl L2LanguageConfig for JavaL3Config {
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
    fn extract_var_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        let declarator = find_child_by_kind(node, "variable_declarator")?;
        let name_node = declarator.child_by_field_name("name")?;
        node_text(name_node, source)
    }
    fn extract_call_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<String> {
        let name_node = node.child_by_field_name("name")?;
        let name = node_text(name_node, source)?;
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

impl L3LanguageConfig for JavaL3Config {
    fn parameter_list_kind(&self) -> &str {
        "formal_parameters"
    }
    fn return_statement_kind(&self) -> &str {
        "return_statement"
    }
    fn import_statement_kinds(&self) -> &[&str] {
        // Java: 暫不支援跨檔案解析
        &[]
    }
    fn export_kinds(&self) -> &[&str] {
        &[]
    }
    fn extract_function_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        node.child_by_field_name("name")
            .and_then(|n| node_text(n, source))
    }
    fn extract_parameters<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Vec<String> {
        // Java formal_parameters → formal_parameter → name
        let mut params = Vec::new();
        if let Some(param_list) = find_child_by_kind(node, "formal_parameters") {
            let mut cursor = param_list.walk();
            for child in param_list.children(&mut cursor) {
                if child.kind() == "formal_parameter" || child.kind() == "spread_parameter" {
                    if let Some(name) = child.child_by_field_name("name") {
                        if let Some(text) = node_text(name, source) {
                            params.push(text.to_string());
                        }
                    }
                }
            }
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

/// Python L3 語言配置。
pub struct PythonL3Config;

impl L2LanguageConfig for PythonL3Config {
    fn function_node_kinds(&self) -> &[&str] {
        &["function_definition"]
    }
    fn variable_declaration_kinds(&self) -> &[&str] {
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
        Some("string")
    }
    fn block_kinds(&self) -> &[&str] {
        &["block"]
    }
    fn extract_var_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        let left = node.child_by_field_name("left")?;
        if left.kind() == "identifier" {
            return node_text(left, source);
        }
        None
    }
    fn extract_call_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_operator"
    }
}

impl L3LanguageConfig for PythonL3Config {
    fn parameter_list_kind(&self) -> &str {
        "parameters"
    }
    fn return_statement_kind(&self) -> &str {
        "return_statement"
    }
    fn import_statement_kinds(&self) -> &[&str] {
        &["import_from_statement"]
    }
    fn export_kinds(&self) -> &[&str] {
        // Python 無明確 export — 所有頂層函數皆可 import
        &[]
    }
    fn extract_function_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        node.child_by_field_name("name")
            .and_then(|n| node_text(n, source))
    }
    fn extract_parameters<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Vec<String> {
        // Python parameters → identifier (直接子節點)
        extract_param_identifiers(node, "parameters", "identifier", source)
    }
}

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

/// C# L3 語言配置。
pub struct CSharpL3Config;

impl L2LanguageConfig for CSharpL3Config {
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
    fn extract_var_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        let var_decl = find_child_by_kind(node, "variable_declaration")?;
        let declarator = find_child_by_kind(var_decl, "variable_declarator")?;
        let name_node = find_child_by_kind(declarator, "identifier")?;
        node_text(name_node, source)
    }
    fn extract_call_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

impl L3LanguageConfig for CSharpL3Config {
    fn parameter_list_kind(&self) -> &str {
        "parameter_list"
    }
    fn return_statement_kind(&self) -> &str {
        "return_statement"
    }
    fn import_statement_kinds(&self) -> &[&str] {
        // C#: 暫不支援跨檔案解析
        &[]
    }
    fn export_kinds(&self) -> &[&str] {
        &[]
    }
    fn extract_function_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        node.child_by_field_name("name")
            .and_then(|n| node_text(n, source))
    }
    fn extract_parameters<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Vec<String> {
        // C# parameter_list → parameter → name
        let mut params = Vec::new();
        if let Some(param_list) = find_child_by_kind(node, "parameter_list") {
            let mut cursor = param_list.walk();
            for child in param_list.children(&mut cursor) {
                if child.kind() == "parameter" {
                    if let Some(name) = child.child_by_field_name("name") {
                        if let Some(text) = node_text(name, source) {
                            params.push(text.to_string());
                        }
                    }
                }
            }
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

/// Go L3 語言配置。
pub struct GoL3Config;

impl L2LanguageConfig for GoL3Config {
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
        None
    }
    fn block_kinds(&self) -> &[&str] {
        &["block"]
    }
    fn extract_var_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "expression_list" {
                let first = left.child(0)?;
                return node_text(first, source);
            }
            return node_text(left, source);
        }
        None
    }
    fn extract_call_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<String> {
        let func_node = node.child_by_field_name("function")?;
        Some(node_text(func_node, source)?.to_string())
    }
    fn binary_expression_kind(&self) -> &str {
        "binary_expression"
    }
}

impl L3LanguageConfig for GoL3Config {
    fn parameter_list_kind(&self) -> &str {
        "parameter_list"
    }
    fn return_statement_kind(&self) -> &str {
        "return_statement"
    }
    fn import_statement_kinds(&self) -> &[&str] {
        // Go: 暫不支援跨檔案解析
        &[]
    }
    fn export_kinds(&self) -> &[&str] {
        &[]
    }
    fn extract_function_name<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Option<&'a str> {
        node.child_by_field_name("name")
            .and_then(|n| node_text(n, source))
    }
    fn extract_parameters<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a [u8],
    ) -> Vec<String> {
        // Go parameter_list → parameter_declaration → name (identifier)
        let mut params = Vec::new();
        if let Some(param_list) = find_child_by_kind(node, "parameter_list") {
            let mut cursor = param_list.walk();
            for child in param_list.children(&mut cursor) {
                if child.kind() == "parameter_declaration" {
                    if let Some(name) = child.child_by_field_name("name") {
                        if let Some(text) = node_text(name, source) {
                            params.push(text.to_string());
                        }
                    }
                }
            }
        }
        params
    }
}

// ---------------------------------------------------------------------------
// 語言配置工廠
// ---------------------------------------------------------------------------

/// 根據語言取得對應的 L3 語言配置。
pub fn get_l3_config(
    language: atlas_lang::Language,
) -> Option<&'static dyn L3LanguageConfig> {
    match language {
        atlas_lang::Language::TypeScript | atlas_lang::Language::JavaScript => {
            Some(&TypeScriptL3Config)
        }
        atlas_lang::Language::Java => Some(&JavaL3Config),
        atlas_lang::Language::Python => Some(&PythonL3Config),
        atlas_lang::Language::CSharp => Some(&CSharpL3Config),
        atlas_lang::Language::Go => Some(&GoL3Config),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 輔助函式
// ---------------------------------------------------------------------------

/// 從 AST node 提取文字。
fn node_text<'a>(node: tree_sitter::Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    std::str::from_utf8(&source[node.byte_range()]).ok()
}

/// 搜尋某個 kind 的子節點。
fn find_child_by_kind<'a>(
    node: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|c| c.kind() == kind)
}

/// 通用參數提取 — 從參數列表節點遞迴搜尋 identifier。
///
/// 先嘗試 `parameters` field name，再 fallback 到 kind 搜尋。
fn extract_param_identifiers(
    func_node: tree_sitter::Node<'_>,
    param_list_kind: &str,
    identifier_kind: &str,
    source: &[u8],
) -> Vec<String> {
    let mut params = Vec::new();

    // 嘗試 field name "parameters" 或 kind 搜尋
    let param_list = func_node
        .child_by_field_name("parameters")
        .or_else(|| find_child_by_kind(func_node, param_list_kind));

    if let Some(param_list) = param_list {
        let mut cursor = param_list.walk();
        for child in param_list.children(&mut cursor) {
            // 直接是 identifier（如 TypeScript/Python 的簡單參數）
            if child.kind() == identifier_kind {
                if let Some(text) = node_text(child, source) {
                    // 跳過 self/this
                    if text != "self" && text != "this" {
                        params.push(text.to_string());
                    }
                }
            } else if child.kind() == "required_parameter"
                || child.kind() == "optional_parameter"
            {
                // TypeScript typed 參數: required_parameter → pattern (identifier)
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    if let Some(text) = node_text(pattern, source) {
                        params.push(text.to_string());
                    }
                } else if let Some(name) = child.child_by_field_name("name") {
                    if let Some(text) = node_text(name, source) {
                        params.push(text.to_string());
                    }
                }
            } else if let Some(name) = child.child_by_field_name("name") {
                if let Some(text) = node_text(name, source) {
                    params.push(text.to_string());
                }
            }
        }
    }
    params
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_l3_config_supported_languages() {
        assert!(get_l3_config(atlas_lang::Language::TypeScript).is_some());
        assert!(get_l3_config(atlas_lang::Language::JavaScript).is_some());
        assert!(get_l3_config(atlas_lang::Language::Java).is_some());
        assert!(get_l3_config(atlas_lang::Language::Python).is_some());
        assert!(get_l3_config(atlas_lang::Language::CSharp).is_some());
        assert!(get_l3_config(atlas_lang::Language::Go).is_some());
    }

    #[test]
    fn get_l3_config_unsupported_language() {
        assert!(get_l3_config(atlas_lang::Language::Ruby).is_none());
        assert!(get_l3_config(atlas_lang::Language::Php).is_none());
        assert!(get_l3_config(atlas_lang::Language::Kotlin).is_none());
    }

    #[test]
    fn typescript_l3_config_node_kinds() {
        let cfg = TypeScriptL3Config;
        assert_eq!(cfg.parameter_list_kind(), "formal_parameters");
        assert_eq!(cfg.return_statement_kind(), "return_statement");
        assert!(!cfg.import_statement_kinds().is_empty());
        assert!(!cfg.export_kinds().is_empty());
    }

    #[test]
    fn java_l3_config_no_cross_file() {
        let cfg = JavaL3Config;
        assert_eq!(cfg.parameter_list_kind(), "formal_parameters");
        assert!(cfg.import_statement_kinds().is_empty());
        assert!(cfg.export_kinds().is_empty());
    }

    #[test]
    fn python_l3_config_has_import() {
        let cfg = PythonL3Config;
        assert_eq!(cfg.parameter_list_kind(), "parameters");
        assert!(!cfg.import_statement_kinds().is_empty());
        assert!(cfg.export_kinds().is_empty()); // Python 無明確 export
    }

    #[test]
    fn go_l3_config_no_cross_file() {
        let cfg = GoL3Config;
        assert_eq!(cfg.parameter_list_kind(), "parameter_list");
        assert!(cfg.import_statement_kinds().is_empty());
    }
}
