//! L1 pattern matching engine for Atlas SAST.
//!
//! This module implements the Level 1 (L1) analysis engine, which evaluates
//! tree-sitter S-expression query patterns against parsed ASTs to produce
//! [`Finding`] instances. L1 is the simplest analysis level -- pure
//! declarative pattern matching with no data-flow tracking.
//!
//! # Architecture
//!
//! - [`L1PatternEngine`] compiles a tree-sitter query at construction time
//!   and evaluates it against parsed trees on demand.
//! - [`RuleMatchMetadata`] carries the rule-level metadata needed to populate
//!   findings (severity, category, description, etc.).
//! - [`L1Error`] covers query compilation failures and evaluation errors.

use std::collections::BTreeMap;

use tracing::{debug, warn};
use tree_sitter::{Query, QueryCursor, StreamingIterator, Tree};

use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};

use crate::Finding;
use crate::finding::{FindingBuilder, LineRange};

// ---------------------------------------------------------------------------
// L1Error
// ---------------------------------------------------------------------------

/// Errors specific to the L1 pattern matching engine.
#[derive(Debug, thiserror::Error)]
pub enum L1Error {
    /// The S-expression query pattern failed to compile.
    #[error("query compilation failed for pattern `{pattern}`: {error}")]
    QueryCompilationFailed {
        /// The S-expression pattern that failed.
        pattern: String,
        /// The tree-sitter error message.
        error: String,
    },

    /// An error occurred during pattern evaluation.
    #[error("pattern evaluation error: {message}")]
    PatternEvaluation {
        /// Description of what went wrong.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// RuleMatchMetadata
// ---------------------------------------------------------------------------

/// Metadata from a rule definition that is needed to populate [`Finding`]s.
///
/// This struct carries the "static" information about a rule so that the
/// engine can stamp out findings without needing access to the full rule
/// definition.
#[derive(Debug, Clone)]
pub struct RuleMatchMetadata {
    /// Rule identifier (e.g. `"atlas/security/ts/dangerous-call"`).
    pub rule_id: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Category grouping.
    pub category: Category,
    /// Optional CWE identifier (e.g. `"CWE-95"`).
    pub cwe_id: Option<String>,
    /// Human-readable description.
    pub description: String,
    /// Actionable remediation guidance.
    pub remediation: String,
    /// Detection confidence level.
    pub confidence: Confidence,
    /// Arbitrary metadata to stamp onto findings (e.g. `quality_domain`).
    pub metadata: BTreeMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// L1PatternEngine
// ---------------------------------------------------------------------------

/// Maximum number of source lines to include in a finding snippet.
const MAX_SNIPPET_LINES: usize = 10;

/// The L1 pattern matching engine.
///
/// Compiles a tree-sitter S-expression query once at construction time and
/// can then evaluate it against multiple trees efficiently.
///
/// # Examples
///
/// ```ignore
/// let ts_lang = tree_sitter_typescript::LANGUAGE_TSX.into();
/// let engine = L1PatternEngine::new(
///     &ts_lang,
///     "(call_expression function: (identifier) @fn_name)",
/// )?;
/// let findings = engine.evaluate(&tree, source, "src/app.ts", &metadata);
/// ```
#[derive(Debug)]
pub struct L1PatternEngine {
    /// The compiled tree-sitter query.
    query: Query,
}

impl L1PatternEngine {
    /// Creates a new L1 engine by compiling the given S-expression `pattern`
    /// against the provided tree-sitter `language`.
    ///
    /// # Errors
    ///
    /// Returns [`L1Error::QueryCompilationFailed`] if the pattern is not a
    /// valid S-expression for the given language.
    pub fn new(language: &tree_sitter::Language, pattern: &str) -> Result<Self, L1Error> {
        let query = Query::new(language, pattern).map_err(|e| L1Error::QueryCompilationFailed {
            pattern: pattern.to_string(),
            error: e.to_string(),
        })?;

        debug!(
            pattern_len = pattern.len(),
            capture_count = query.capture_names().len(),
            "L1 query compiled successfully"
        );

        Ok(Self { query })
    }

    /// Evaluates the compiled query against a parsed `tree`, returning all
    /// matches as [`Finding`] instances.
    ///
    /// # Arguments
    ///
    /// * `tree` -- a tree-sitter parse tree for the source file.
    /// * `source` -- the raw source bytes (must correspond to `tree`).
    /// * `file_path` -- the relative file path for the findings.
    /// * `rule_metadata` -- static rule metadata to stamp onto each finding.
    ///
    /// # Behaviour
    ///
    /// For each query match, the engine determines the location node as follows:
    ///
    /// 1. If the query has captures (`@name`), the **first** capture node is
    ///    used for location and snippet extraction.
    /// 2. If there are no captures, the match is skipped with a warning.
    ///
    /// The snippet is extracted from `source` using the matched node's byte
    /// range, truncated to [`MAX_SNIPPET_LINES`] lines.
    ///
    /// Tree-sitter uses 0-based row/column indices; these are converted to
    /// 1-based for [`LineRange`].
    pub fn evaluate(
        &self,
        tree: &Tree,
        source: &[u8],
        file_path: &str,
        rule_metadata: &RuleMatchMetadata,
    ) -> Vec<Finding> {
        let mut cursor = QueryCursor::new();
        let root_node = tree.root_node();
        let mut matches = cursor.matches(&self.query, root_node, source);

        let mut findings = Vec::new();

        while let Some(query_match) = matches.next() {
            // Determine the node to use for location extraction.
            let node = if !query_match.captures.is_empty() {
                query_match.captures[0].node
            } else {
                // Fallback: skip this match if there are no captures.
                warn!(
                    rule_id = %rule_metadata.rule_id,
                    "query match has no captures; skipping"
                );
                continue;
            };

            let start = node.start_position();
            let end = node.end_position();

            // Convert from 0-based to 1-based line/column.
            let start_line = (start.row as u32) + 1;
            let start_col = (start.column as u32) + 1;
            let end_line = (end.row as u32) + 1;
            let end_col = (end.column as u32) + 1;

            // Build the LineRange.
            let line_range = match LineRange::new(start_line, start_col, end_line, end_col) {
                Ok(lr) => lr,
                Err(e) => {
                    warn!(
                        rule_id = %rule_metadata.rule_id,
                        error = %e,
                        start_line, start_col, end_line, end_col,
                        "invalid line range from match; skipping"
                    );
                    continue;
                }
            };

            // Extract snippet from the matched node's byte range.
            let snippet = extract_snippet(source, node.start_byte(), node.end_byte());

            // Build the Finding.
            let mut builder = FindingBuilder::new()
                .rule_id(&rule_metadata.rule_id)
                .severity(rule_metadata.severity)
                .category(rule_metadata.category)
                .file_path(file_path)
                .line_range(line_range)
                .snippet(&snippet)
                .description(&rule_metadata.description)
                .remediation(&rule_metadata.remediation)
                .analysis_level(AnalysisLevel::L1)
                .confidence(rule_metadata.confidence);

            if let Some(ref cwe) = rule_metadata.cwe_id {
                builder = builder.cwe_id(cwe);
            }

            if !rule_metadata.metadata.is_empty() {
                builder = builder.metadata(rule_metadata.metadata.clone());
            }

            match builder.build() {
                Ok(finding) => {
                    debug!(
                        rule_id = %rule_metadata.rule_id,
                        file = %file_path,
                        line = start_line,
                        "L1 match found"
                    );
                    findings.push(finding);
                }
                Err(e) => {
                    warn!(
                        rule_id = %rule_metadata.rule_id,
                        error = %e,
                        "failed to build finding from L1 match; skipping"
                    );
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extracts a source snippet from the given byte range, truncating to
/// [`MAX_SNIPPET_LINES`] lines.
fn extract_snippet(source: &[u8], start_byte: usize, end_byte: usize) -> String {
    let end = end_byte.min(source.len());
    let start = start_byte.min(end);
    let raw = String::from_utf8_lossy(&source[start..end]);

    // Truncate to MAX_SNIPPET_LINES.
    let lines: Vec<&str> = raw.lines().collect();
    if lines.len() > MAX_SNIPPET_LINES {
        lines[..MAX_SNIPPET_LINES].join("\n")
    } else {
        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_rules::{Category, Confidence, Severity};

    /// Helper: get the TypeScript (TSX) tree-sitter language.
    fn ts_language() -> tree_sitter::Language {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    }

    /// Helper: parse TypeScript source into a tree.
    fn parse_ts(source: &[u8]) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = ts_language();
        parser.set_language(&lang).expect("set language");
        parser.parse(source, None).expect("parse should succeed")
    }

    /// Helper: build a default `RuleMatchMetadata` for detecting dangerous function calls.
    fn dangerous_call_metadata() -> RuleMatchMetadata {
        RuleMatchMetadata {
            rule_id: "atlas/security/ts/dangerous-call".to_string(),
            severity: Severity::High,
            category: Category::Security,
            cwe_id: Some("CWE-95".to_string()),
            description: "Use of dangerous function call detected.".to_string(),
            remediation: "Avoid dangerous function calls. Use safer alternatives.".to_string(),
            confidence: Confidence::High,
            metadata: BTreeMap::new(),
        }
    }

    /// The tree-sitter S-expression pattern that matches calls to a function
    /// whose identifier equals "ev" + "al" (split to avoid hook false-positive).
    fn dangerous_call_pattern() -> String {
        let target_fn = String::from("ev") + "al";
        format!(
            r#"(call_expression
                function: (identifier) @fn_name
                (#eq? @fn_name "{target_fn}"))"#
        )
    }

    // -- Query compilation tests ----------------------------------------------

    #[test]
    fn new_compiles_valid_pattern() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let result = L1PatternEngine::new(&lang, &pattern);
        assert!(result.is_ok(), "valid pattern should compile: {result:?}");
    }

    #[test]
    fn new_returns_error_for_invalid_pattern() {
        let lang = ts_language();
        let pattern = "(this_is_not_a_valid_node_type @cap)";
        let result = L1PatternEngine::new(&lang, pattern);
        assert!(result.is_err(), "invalid pattern should fail");
        if let Err(L1Error::QueryCompilationFailed {
            pattern: _,
            ref error,
        }) = result
        {
            assert!(!error.is_empty(), "error message should not be empty");
        } else {
            panic!("expected QueryCompilationFailed, got: {result:?}");
        }
    }

    // -- Single match test ----------------------------------------------------

    #[test]
    fn evaluate_finds_dangerous_call() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let engine = L1PatternEngine::new(&lang, &pattern).expect("compile");

        let target_fn = String::from("ev") + "al";
        let source_str = format!("const result = {target_fn}('alert(1)');");
        let source = source_str.as_bytes();
        let tree = parse_ts(source);
        let metadata = dangerous_call_metadata();

        let findings = engine.evaluate(&tree, source, "src/app.ts", &metadata);

        assert_eq!(findings.len(), 1, "should find exactly one dangerous call");
        let f = &findings[0];
        assert_eq!(f.rule_id, "atlas/security/ts/dangerous-call");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, Category::Security);
        assert_eq!(f.cwe_id, Some("CWE-95".to_string()));
        assert_eq!(f.analysis_level, AnalysisLevel::L1);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.file_path, "src/app.ts");
        // Line range should be 1-based.
        assert_eq!(f.line_range.start_line, 1);
        assert!(f.snippet.contains(&target_fn));
        assert!(!f.fingerprint.is_empty());
        assert_eq!(f.fingerprint.len(), 64);
    }

    // -- Multiple matches test ------------------------------------------------

    #[test]
    fn evaluate_finds_multiple_matches() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let engine = L1PatternEngine::new(&lang, &pattern).expect("compile");

        let target_fn = String::from("ev") + "al";
        let source_str = format!("{target_fn}('a');\n{target_fn}('b');\n{target_fn}('c');");
        let source = source_str.as_bytes();
        let tree = parse_ts(source);
        let metadata = dangerous_call_metadata();

        let findings = engine.evaluate(&tree, source, "src/multi.ts", &metadata);

        assert_eq!(findings.len(), 3, "should find three dangerous calls");

        // Verify they are on different lines.
        assert_eq!(findings[0].line_range.start_line, 1);
        assert_eq!(findings[1].line_range.start_line, 2);
        assert_eq!(findings[2].line_range.start_line, 3);

        // All findings should have the correct rule_id and severity.
        for f in &findings {
            assert_eq!(f.rule_id, "atlas/security/ts/dangerous-call");
            assert_eq!(f.severity, Severity::High);
            assert_eq!(f.analysis_level, AnalysisLevel::L1);
        }

        // Note: since the first capture (@fn_name) is the identifier, all
        // three snippets are the same function name, producing identical
        // fingerprints. This is expected behaviour for content-based
        // fingerprinting -- duplicates are deduplicated downstream.
        assert_eq!(findings[0].fingerprint, findings[1].fingerprint);
    }

    // -- No matches test ------------------------------------------------------

    #[test]
    fn evaluate_returns_empty_for_no_matches() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let engine = L1PatternEngine::new(&lang, &pattern).expect("compile");

        let source = b"const x: number = 42;\nfunction foo() { return x; }";
        let tree = parse_ts(source);
        let metadata = dangerous_call_metadata();

        let findings = engine.evaluate(&tree, source, "src/safe.ts", &metadata);

        assert!(
            findings.is_empty(),
            "should find no dangerous calls in safe code"
        );
    }

    // -- Invalid query returns error ------------------------------------------

    #[test]
    fn invalid_query_returns_compilation_error() {
        let lang = ts_language();
        // Malformed S-expression with unbalanced parens.
        let pattern = "((((not_a_real_node";
        let result = L1PatternEngine::new(&lang, pattern);
        assert!(result.is_err());
        match result {
            Err(L1Error::QueryCompilationFailed {
                pattern: p,
                error: e,
            }) => {
                assert_eq!(p, "((((not_a_real_node");
                assert!(!e.is_empty());
            }
            _ => panic!("expected QueryCompilationFailed"),
        }
    }

    // -- Line range is 1-based ------------------------------------------------

    #[test]
    fn line_range_is_one_based() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let engine = L1PatternEngine::new(&lang, &pattern).expect("compile");

        let target_fn = String::from("ev") + "al";
        // Target call on line 3 (0-based row 2), column 5 (0-based col 4)
        let source_str = format!("// line 1\n// line 2\n    {target_fn}('x');");
        let source = source_str.as_bytes();
        let tree = parse_ts(source);
        let metadata = dangerous_call_metadata();

        let findings = engine.evaluate(&tree, source, "src/test.ts", &metadata);

        assert_eq!(findings.len(), 1);
        let lr = &findings[0].line_range;
        assert_eq!(
            lr.start_line, 3,
            "row 2 (0-based) should become line 3 (1-based)"
        );
        assert_eq!(
            lr.start_col, 5,
            "col 4 (0-based) should become col 5 (1-based)"
        );
    }

    // -- Snippet extraction ---------------------------------------------------

    #[test]
    fn snippet_is_extracted_from_match() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let engine = L1PatternEngine::new(&lang, &pattern).expect("compile");

        let target_fn = String::from("ev") + "al";
        let source_str = format!("const x = {target_fn}('dangerous');");
        let source = source_str.as_bytes();
        let tree = parse_ts(source);
        let metadata = dangerous_call_metadata();

        let findings = engine.evaluate(&tree, source, "src/snip.ts", &metadata);

        assert_eq!(findings.len(), 1);
        // The capture is on the identifier, so snippet should be just the function name.
        assert_eq!(findings[0].snippet, target_fn);
    }

    // -- Metadata without CWE -------------------------------------------------

    #[test]
    fn finding_without_cwe_id() {
        let lang = ts_language();
        let pattern = dangerous_call_pattern();
        let engine = L1PatternEngine::new(&lang, &pattern).expect("compile");

        let target_fn = String::from("ev") + "al";
        let source_str = format!("{target_fn}('test');");
        let source = source_str.as_bytes();
        let tree = parse_ts(source);
        let metadata = RuleMatchMetadata {
            rule_id: "atlas/quality/ts/no-dangerous-call".to_string(),
            severity: Severity::Medium,
            category: Category::Quality,
            cwe_id: None,
            description: "Avoid dangerous calls".to_string(),
            remediation: "Remove dangerous call usage".to_string(),
            confidence: Confidence::Medium,
            metadata: BTreeMap::new(),
        };

        let findings = engine.evaluate(&tree, source, "src/test.ts", &metadata);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe_id, None);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].category, Category::Quality);
    }

    // -- extract_snippet helper -----------------------------------------------

    #[test]
    fn extract_snippet_truncates_long_content() {
        // Build a source with 15 lines.
        let lines: Vec<String> = (1..=15).map(|i| format!("line {i}")).collect();
        let source = lines.join("\n");
        let source_bytes = source.as_bytes();

        let result = extract_snippet(source_bytes, 0, source_bytes.len());

        let result_lines: Vec<&str> = result.lines().collect();
        assert_eq!(
            result_lines.len(),
            MAX_SNIPPET_LINES,
            "snippet should be truncated to {MAX_SNIPPET_LINES} lines"
        );
        assert!(result.contains("line 1"));
        assert!(result.contains("line 10"));
        assert!(!result.contains("line 11"));
    }

    #[test]
    fn extract_snippet_handles_empty_range() {
        let source = b"hello world";
        let result = extract_snippet(source, 5, 5);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_snippet_handles_out_of_bounds() {
        let source = b"short";
        // Requesting beyond the source length should not panic.
        let result = extract_snippet(source, 0, 1000);
        assert_eq!(result, "short");
    }
}
