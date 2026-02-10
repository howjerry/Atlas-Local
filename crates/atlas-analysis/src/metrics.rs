//! 程式碼品質指標引擎
//!
//! 提供 McCabe 循環複雜度、SonarSource 認知複雜度、LOC 統計等指標計算

use atlas_lang::Language;
use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};
use crate::finding::{Finding, FindingBuilder, LineRange};
use std::collections::HashSet;
use tree_sitter::{Node, Tree};

/// 指標配置
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// 循環複雜度上限 (McCabe)
    pub cyclomatic_max: u32,
    /// 認知複雜度上限 (SonarSource)
    pub cognitive_max: u32,
    /// 最小 token 數（低於此值不報告）
    pub min_tokens: u32,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            cyclomatic_max: 15,
            cognitive_max: 25,
            min_tokens: 100,
        }
    }
}

/// 檔案級別的指標資料
#[derive(Debug, Clone)]
pub struct FileMetricsData {
    pub path: String,
    pub total_lines: u32,
    pub code_lines: u32,
    pub blank_lines: u32,
    pub comment_lines: u32,
    pub functions: Vec<FunctionMetricsData>,
}

/// 函數級別的指標資料
#[derive(Debug, Clone)]
pub struct FunctionMetricsData {
    pub name: String,
    pub start_line: u32,
    pub end_line: u32,
    pub loc: u32,
    pub cyclomatic_complexity: u32,
    pub cognitive_complexity: u32,
    pub parameter_count: u32,
}

/// 每個語言的 AST 節點類型映射
pub trait MetricsLanguageConfig: Send + Sync {
    /// 函數/方法定義節點
    fn function_kinds(&self) -> &[&str];
    /// 決策點節點（if, for, while, case, catch 等）
    fn decision_kinds(&self) -> &[&str];
    /// 邏輯運算子節點
    fn logical_operator_kinds(&self) -> &[&str];
    /// 註解節點
    fn comment_kinds(&self) -> &[&str];

    /// 提取函數名稱（從函數定義節點）
    fn extract_function_name(&self, node: Node, source: &str) -> Option<String>;

    /// 檢查節點是否為邏輯 AND/OR
    fn is_logical_operator(&self, node: Node, source: &str) -> bool;
}

/// TypeScript 配置
struct TypeScriptMetricsConfig;

impl MetricsLanguageConfig for TypeScriptMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["function_declaration", "arrow_function", "method_definition"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_statement",
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
            "switch_case",
            "catch_clause",
            "ternary_expression",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["binary_expression"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        let kind = node.kind();
        if kind == "function_declaration" || kind == "method_definition" {
            node.child_by_field_name("name")
                .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
        } else if kind == "arrow_function" {
            Some("<arrow>".to_string())
        } else {
            None
        }
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "&&" || op_text == "||";
            }
        }
        false
    }
}

/// Java 配置
struct JavaMetricsConfig;

impl MetricsLanguageConfig for JavaMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["method_declaration", "constructor_declaration"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_statement",
            "for_statement",
            "enhanced_for_statement",
            "while_statement",
            "do_statement",
            "switch_label",
            "catch_clause",
            "ternary_expression",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["binary_expression"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["line_comment", "block_comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("name")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "&&" || op_text == "||";
            }
        }
        false
    }
}

/// Python 配置
struct PythonMetricsConfig;

impl MetricsLanguageConfig for PythonMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["function_definition"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_statement",
            "elif_clause",
            "for_statement",
            "while_statement",
            "except_clause",
            "conditional_expression",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["boolean_operator"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("name")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "boolean_operator" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "and" || op_text == "or";
            }
        }
        false
    }
}

/// Go 配置
struct GoMetricsConfig;

impl MetricsLanguageConfig for GoMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["function_declaration", "method_declaration"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_statement",
            "for_statement",
            "expression_case",
            "type_case",
            "communication_case",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["binary_expression"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("name")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "&&" || op_text == "||";
            }
        }
        false
    }
}

/// C# 配置
struct CSharpMetricsConfig;

impl MetricsLanguageConfig for CSharpMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["method_declaration", "constructor_declaration"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_statement",
            "for_statement",
            "for_each_statement",
            "while_statement",
            "do_statement",
            "switch_section",
            "catch_clause",
            "conditional_expression",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["binary_expression"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("name")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "&&" || op_text == "||";
            }
        }
        false
    }
}

/// Ruby 配置
struct RubyMetricsConfig;

impl MetricsLanguageConfig for RubyMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["method"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if",
            "elsif",
            "for",
            "while",
            "until",
            "when",
            "rescue",
            "conditional",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["binary"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("name")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "binary" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "&&" || op_text == "||";
            }
        }
        false
    }
}

/// PHP 配置
struct PhpMetricsConfig;

impl MetricsLanguageConfig for PhpMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["function_definition", "method_declaration"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_statement",
            "else_if_clause",
            "for_statement",
            "foreach_statement",
            "while_statement",
            "do_statement",
            "case_statement",
            "catch_clause",
            "conditional_expression",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["binary_expression"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("name")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
                return op_text == "&&" || op_text == "||";
            }
        }
        false
    }
}

/// Kotlin 配置
struct KotlinMetricsConfig;

impl MetricsLanguageConfig for KotlinMetricsConfig {
    fn function_kinds(&self) -> &[&str] {
        &["function_declaration"]
    }

    fn decision_kinds(&self) -> &[&str] {
        &[
            "if_expression",
            "for_statement",
            "while_statement",
            "do_while_statement",
            "when_entry",
            "catch_block",
        ]
    }

    fn logical_operator_kinds(&self) -> &[&str] {
        &["conjunction_expression", "disjunction_expression"]
    }

    fn comment_kinds(&self) -> &[&str] {
        &["line_comment", "multiline_comment"]
    }

    fn extract_function_name(&self, node: Node, source: &str) -> Option<String> {
        node.child_by_field_name("simple_identifier")
            .and_then(|n| Some(n.utf8_text(source.as_bytes()).ok()?.to_string()))
    }

    fn is_logical_operator(&self, node: Node, _source: &str) -> bool {
        node.kind() == "conjunction_expression" || node.kind() == "disjunction_expression"
    }
}

/// 取得語言對應的配置
pub fn get_language_config(language: Language) -> Option<Box<dyn MetricsLanguageConfig>> {
    match language {
        Language::TypeScript | Language::JavaScript => {
            Some(Box::new(TypeScriptMetricsConfig))
        }
        Language::Java => Some(Box::new(JavaMetricsConfig)),
        Language::Python => Some(Box::new(PythonMetricsConfig)),
        Language::Go => Some(Box::new(GoMetricsConfig)),
        Language::CSharp => Some(Box::new(CSharpMetricsConfig)),
        Language::Ruby => Some(Box::new(RubyMetricsConfig)),
        Language::Php => Some(Box::new(PhpMetricsConfig)),
        Language::Kotlin => Some(Box::new(KotlinMetricsConfig)),
    }
}

/// 指標計算引擎
pub struct MetricsEngine {
    config: MetricsConfig,
}

impl MetricsEngine {
    pub fn new(config: MetricsConfig) -> Self {
        Self { config }
    }

    /// 計算檔案級別指標
    pub fn compute_file_metrics(
        &self,
        tree: &Tree,
        source: &str,
        language: Language,
        path: &str,
    ) -> Option<FileMetricsData> {
        let lang_config = get_language_config(language)?;

        // 計算 LOC 統計
        let (total_lines, code_lines, blank_lines, comment_lines) =
            self.compute_loc(tree, source, lang_config.as_ref());

        // 提取函數並計算複雜度
        let functions = self.extract_functions(tree, source, lang_config.as_ref());

        Some(FileMetricsData {
            path: path.to_string(),
            total_lines,
            code_lines,
            blank_lines,
            comment_lines,
            functions,
        })
    }

    /// 計算 LOC（依註解節點位置分類每一行）
    fn compute_loc(
        &self,
        tree: &Tree,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
    ) -> (u32, u32, u32, u32) {
        let lines: Vec<&str> = source.lines().collect();
        let total_lines = lines.len() as u32;

        // 收集所有註解行
        let mut comment_lines_set = HashSet::new();
        self.collect_comment_lines(tree.root_node(), source, lang_config, &mut comment_lines_set);

        let mut blank_lines = 0;
        let mut code_lines = 0;

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                blank_lines += 1;
            } else if !comment_lines_set.contains(&line_num) {
                code_lines += 1;
            }
        }

        let comment_lines = comment_lines_set.len() as u32;

        (total_lines, code_lines, blank_lines, comment_lines)
    }

    /// 遞迴收集註解覆蓋的行號
    fn collect_comment_lines(
        &self,
        node: Node,
        _source: &str,
        lang_config: &dyn MetricsLanguageConfig,
        comment_lines: &mut HashSet<usize>,
    ) {
        let comment_kinds = lang_config.comment_kinds();

        if comment_kinds.contains(&node.kind()) {
            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;
            for line in start_line..=end_line {
                comment_lines.insert(line);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_comment_lines(child, _source, lang_config, comment_lines);
        }
    }

    /// 提取所有函數並計算其複雜度
    fn extract_functions(
        &self,
        tree: &Tree,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
    ) -> Vec<FunctionMetricsData> {
        let mut functions = Vec::new();
        self.walk_functions(tree.root_node(), source, lang_config, &mut functions);
        functions
    }

    /// 遞迴遍歷 AST，找出函數節點
    fn walk_functions(
        &self,
        node: Node,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
        functions: &mut Vec<FunctionMetricsData>,
    ) {
        let function_kinds = lang_config.function_kinds();

        if function_kinds.contains(&node.kind()) {
            if let Some(func_data) = self.compute_function_metrics(node, source, lang_config) {
                functions.push(func_data);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_functions(child, source, lang_config, functions);
        }
    }

    /// 計算單一函數的指標
    fn compute_function_metrics(
        &self,
        node: Node,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
    ) -> Option<FunctionMetricsData> {
        let name = lang_config.extract_function_name(node, source)?;
        let start_line = (node.start_position().row + 1) as u32;
        let end_line = (node.end_position().row + 1) as u32;
        let loc = end_line - start_line + 1;

        let cyclomatic = self.compute_cyclomatic(node, source, lang_config);
        let cognitive = self.compute_cognitive(node, source, lang_config, 0);
        let param_count = self.count_parameters(node, source);

        Some(FunctionMetricsData {
            name,
            start_line,
            end_line,
            loc,
            cyclomatic_complexity: cyclomatic,
            cognitive_complexity: cognitive,
            parameter_count: param_count,
        })
    }

    /// 計算循環複雜度（McCabe）：base 1 + 決策點數量
    fn compute_cyclomatic(
        &self,
        node: Node,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
    ) -> u32 {
        let mut complexity = 1; // 基礎複雜度
        self.walk_cyclomatic(node, source, lang_config, &mut complexity);
        complexity
    }

    /// 遞迴計算決策點
    fn walk_cyclomatic(
        &self,
        node: Node,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
        complexity: &mut u32,
    ) {
        let decision_kinds = lang_config.decision_kinds();

        // 檢查是否為決策點
        if decision_kinds.contains(&node.kind()) {
            *complexity += 1;
        }

        // 檢查邏輯運算子（&& 和 ||）
        if lang_config.is_logical_operator(node, source) {
            *complexity += 1;
        }

        // 遞迴處理子節點
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_cyclomatic(child, source, lang_config, complexity);
        }
    }

    /// 計算認知複雜度（SonarSource）：結構增量 + 巢狀懲罰
    fn compute_cognitive(
        &self,
        node: Node,
        source: &str,
        lang_config: &dyn MetricsLanguageConfig,
        nesting: u32,
    ) -> u32 {
        let mut complexity = 0;
        let decision_kinds = lang_config.decision_kinds();

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // 檢查是否為控制流結構
            if decision_kinds.contains(&child.kind()) {
                // 增量 = 1 + 當前巢狀層級
                complexity += 1 + nesting;
                // 遞迴計算子樹（巢狀層級 +1）
                complexity += self.compute_cognitive(child, source, lang_config, nesting + 1);
            } else if lang_config.is_logical_operator(child, source) {
                // 邏輯運算子也算一次增量（不增加巢狀）
                complexity += 1;
                complexity += self.compute_cognitive(child, source, lang_config, nesting);
            } else {
                // 一般節點不增加複雜度，但繼續遞迴
                complexity += self.compute_cognitive(child, source, lang_config, nesting);
            }
        }

        complexity
    }

    /// 計算參數數量（簡化版本：計算 parameter_list 子節點數）
    fn count_parameters(&self, node: Node, _source: &str) -> u32 {
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut count = 0;
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                // 過濾掉標點符號節點（括號、逗號等）
                if !child.is_named() {
                    continue;
                }
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    count += 1;
                }
            }
            count
        } else {
            0
        }
    }

    /// 取得引擎配置
    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }

    /// 檢查閾值並產生 Finding
    pub fn check_thresholds(
        &self,
        metrics: &FileMetricsData,
        file_path: &str,
        language: Language,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        // 取得語言名稱用於 rule_id
        let lang_name = format!("{}", language).to_lowercase();

        for func in &metrics.functions {
            let snippet_text = format!(
                "function {} (lines {}-{}): cyclomatic={}, cognitive={}",
                func.name, func.start_line, func.end_line,
                func.cyclomatic_complexity, func.cognitive_complexity
            );

            // 檢查循環複雜度
            if func.cyclomatic_complexity > self.config.cyclomatic_max {
                if let Ok(line_range) = LineRange::new(func.start_line, 0, func.end_line, 0) {
                    if let Ok(finding) = FindingBuilder::new()
                        .rule_id(format!("atlas/metrics/{lang_name}/cyclomatic-complexity"))
                        .file_path(file_path)
                        .severity(Severity::Medium)
                        .category(Category::Metrics)
                        .confidence(Confidence::High)
                        .analysis_level(AnalysisLevel::L1)
                        .line_range(line_range)
                        .description(format!(
                            "函數 '{}' 循環複雜度過高: {} (閾值: {})",
                            func.name, func.cyclomatic_complexity, self.config.cyclomatic_max
                        ))
                        .remediation("將複雜函數拆分為更小的函數以降低循環複雜度".to_string())
                        .snippet(&snippet_text)
                        .build()
                    {
                        findings.push(finding);
                    }
                }
            }

            // 檢查認知複雜度
            if func.cognitive_complexity > self.config.cognitive_max {
                if let Ok(line_range) = LineRange::new(func.start_line, 0, func.end_line, 0) {
                    if let Ok(finding) = FindingBuilder::new()
                        .rule_id(format!("atlas/metrics/{lang_name}/cognitive-complexity"))
                        .file_path(file_path)
                        .severity(Severity::Medium)
                        .category(Category::Metrics)
                        .confidence(Confidence::High)
                        .analysis_level(AnalysisLevel::L1)
                        .line_range(line_range)
                        .description(format!(
                            "函數 '{}' 認知複雜度過高: {} (閾值: {})",
                            func.name, func.cognitive_complexity, self.config.cognitive_max
                        ))
                        .remediation("減少巢狀層級和控制流複雜度以降低認知複雜度".to_string())
                        .snippet(&snippet_text)
                        .build()
                    {
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_lang::{JavaAdapter, LanguageAdapter, PythonAdapter};

    // -----------------------------------------------------------------------
    // 輔助函數：解析各語言原始碼
    // -----------------------------------------------------------------------

    /// 解析 TypeScript 原始碼（使用 dev-dependency tree-sitter-typescript）
    fn parse_ts(source: &[u8]) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    /// 解析 Java 原始碼（透過 atlas_lang adapter）
    fn parse_java(source: &[u8]) -> Tree {
        JavaAdapter.parse(source).unwrap()
    }

    /// 解析 Python 原始碼（透過 atlas_lang adapter）
    fn parse_python(source: &[u8]) -> Tree {
        PythonAdapter.parse(source).unwrap()
    }

    // -----------------------------------------------------------------------
    // 既有測試
    // -----------------------------------------------------------------------

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert_eq!(config.cyclomatic_max, 15);
        assert_eq!(config.cognitive_max, 25);
        assert_eq!(config.min_tokens, 100);
    }

    #[test]
    fn test_get_language_config_typescript() {
        let config = get_language_config(Language::TypeScript);
        assert!(config.is_some());
    }

    #[test]
    fn test_get_language_config_all_supported() {
        // 所有支援的語言都應有配置
        assert!(get_language_config(Language::Java).is_some());
        assert!(get_language_config(Language::Python).is_some());
        assert!(get_language_config(Language::Go).is_some());
        assert!(get_language_config(Language::CSharp).is_some());
        assert!(get_language_config(Language::Ruby).is_some());
        assert!(get_language_config(Language::Php).is_some());
        assert!(get_language_config(Language::Kotlin).is_some());
    }

    #[test]
    fn test_metrics_engine_creation() {
        let config = MetricsConfig::default();
        let _engine = MetricsEngine::new(config);
    }

    // =======================================================================
    // 6.1 Cyclomatic Complexity 測試
    // =======================================================================

    // --- TypeScript ---

    #[test]
    fn test_cyclomatic_simple_typescript() {
        // 沒有分支的簡單函數，CC 應為 1（基礎值）
        let source = b"function foo() { return 1; }";
        let tree = parse_ts(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::TypeScript,
                "test.ts",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "foo");
        assert_eq!(metrics.functions[0].cyclomatic_complexity, 1);
    }

    #[test]
    fn test_cyclomatic_branching_typescript() {
        // 含 if/else + for 迴圈，CC 應大於 1
        let source = br#"function bar(x: number) {
    if (x > 0) {
        return x;
    } else {
        for (let i = 0; i < x; i++) {
            console.log(i);
        }
    }
    return 0;
}"#;
        let tree = parse_ts(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::TypeScript,
                "test.ts",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "bar");
        // if + for = 2 個決策點，基礎值 1，合計至少 3
        assert!(
            metrics.functions[0].cyclomatic_complexity > 1,
            "帶分支的函數 CC 應 > 1，實際為 {}",
            metrics.functions[0].cyclomatic_complexity
        );
    }

    // --- Java ---

    #[test]
    fn test_cyclomatic_simple_java() {
        // 沒有分支的簡單方法，CC 應為 1
        let source = br#"public class Foo {
    public int getValue() {
        return 42;
    }
}"#;
        let tree = parse_java(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::Java,
                "Foo.java",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "getValue");
        assert_eq!(metrics.functions[0].cyclomatic_complexity, 1);
    }

    #[test]
    fn test_cyclomatic_branching_java() {
        // 含 if + for + catch，CC 應 > 1
        let source = br#"public class Bar {
    public void process(int x) {
        if (x > 0) {
            for (int i = 0; i < x; i++) {
                System.out.println(i);
            }
        }
        try {
            System.out.println("try");
        } catch (Exception e) {
            System.out.println("error");
        }
    }
}"#;
        let tree = parse_java(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::Java,
                "Bar.java",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "process");
        // if + for + catch = 3 個決策點，基礎值 1，合計至少 4
        assert!(
            metrics.functions[0].cyclomatic_complexity > 1,
            "帶分支的方法 CC 應 > 1，實際為 {}",
            metrics.functions[0].cyclomatic_complexity
        );
    }

    // --- Python ---

    #[test]
    fn test_cyclomatic_simple_python() {
        // 沒有分支的簡單函數，CC 應為 1
        let source = b"def hello():\n    return 42\n";
        let tree = parse_python(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::Python,
                "test.py",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "hello");
        assert_eq!(metrics.functions[0].cyclomatic_complexity, 1);
    }

    #[test]
    fn test_cyclomatic_branching_python() {
        // 含 if/elif + for + except，CC 應 > 1
        let source = br#"def process(x):
    if x > 0:
        for i in range(x):
            print(i)
    elif x == 0:
        print("zero")
    try:
        pass
    except Exception:
        print("error")
    return x
"#;
        let tree = parse_python(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::Python,
                "test.py",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "process");
        // if + for + elif + except = 4 個決策點，基礎值 1，合計至少 5
        assert!(
            metrics.functions[0].cyclomatic_complexity > 1,
            "帶分支的函數 CC 應 > 1，實際為 {}",
            metrics.functions[0].cyclomatic_complexity
        );
    }

    // =======================================================================
    // 6.2 Cognitive Complexity 測試
    // =======================================================================

    #[test]
    fn test_cognitive_no_nesting() {
        // 單層 if（無巢狀），cognitive = 1（增量 1，巢狀層級 0）
        let source = br#"function check(x: number) {
    if (x > 0) {
        return true;
    }
    return false;
}"#;
        let tree = parse_ts(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::TypeScript,
                "test.ts",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "check");
        // 單個 if，無巢狀：cognitive = 1
        assert_eq!(
            metrics.functions[0].cognitive_complexity, 1,
            "單層 if 的 cognitive 應為 1，實際為 {}",
            metrics.functions[0].cognitive_complexity
        );
    }

    #[test]
    fn test_cognitive_nested() {
        // 巢狀 if（if 內 if），cognitive 應 > 2
        // 外層 if：增量 1 + 巢狀 0 = 1
        // 內層 if：增量 1 + 巢狀 1 = 2
        // 合計 = 3
        let source = br#"function deepCheck(x: number, y: number) {
    if (x > 0) {
        if (y > 0) {
            return true;
        }
    }
    return false;
}"#;
        let tree = parse_ts(source);
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(
                &tree,
                std::str::from_utf8(source).unwrap(),
                Language::TypeScript,
                "test.ts",
            )
            .unwrap();

        assert_eq!(metrics.functions.len(), 1);
        assert_eq!(metrics.functions[0].name, "deepCheck");
        // 巢狀 if 結構：cognitive 應 > 2
        assert!(
            metrics.functions[0].cognitive_complexity > 2,
            "巢狀 if 的 cognitive 應 > 2，實際為 {}",
            metrics.functions[0].cognitive_complexity
        );
    }

    // =======================================================================
    // 6.3 LOC 統計測試
    // =======================================================================

    #[test]
    fn test_loc_basic_typescript() {
        // 驗證 total_lines / code_lines / blank_lines / comment_lines
        let source = "// 這是註解\nfunction foo() {\n    return 1;\n}\n\n// 另一個註解\n";
        let tree = parse_ts(source.as_bytes());
        let engine = MetricsEngine::new(MetricsConfig::default());
        let metrics = engine
            .compute_file_metrics(&tree, source, Language::TypeScript, "test.ts")
            .unwrap();

        // 共 7 行（含最後的空行）：
        //   第 1 行: // 這是註解       → 註解
        //   第 2 行: function foo() {  → 程式碼
        //   第 3 行:     return 1;     → 程式碼
        //   第 4 行: }                 → 程式碼
        //   第 5 行: (空行)            → 空行
        //   第 6 行: // 另一個註解      → 註解
        //   第 7 行: (空行)            → 空行（末尾換行產生）
        // 但 lines() 不包含最後空字串，所以 total = 6
        assert_eq!(
            metrics.total_lines, 6,
            "總行數應為 6，實際為 {}",
            metrics.total_lines
        );
        assert_eq!(
            metrics.comment_lines, 2,
            "註解行應為 2，實際為 {}",
            metrics.comment_lines
        );
        assert_eq!(
            metrics.blank_lines, 1,
            "空行應為 1，實際為 {}",
            metrics.blank_lines
        );
        assert_eq!(
            metrics.code_lines, 3,
            "程式碼行應為 3，實際為 {}",
            metrics.code_lines
        );
    }
}
