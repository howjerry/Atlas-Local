//! Finding and line-range types for Atlas SAST analysis results.
//!
//! This module defines the core data model for analysis findings, including:
//! - [`AnalysisError`] -- error type for analysis operations.
//! - [`LineRange`] -- a validated source-code location range.
//! - [`Finding`] -- a complete SAST finding with content-based fingerprinting.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};

// ---------------------------------------------------------------------------
// AnalysisError
// ---------------------------------------------------------------------------

/// Error type for the atlas-analysis crate.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    /// An invalid line range was specified.
    #[error("invalid line range: {0}")]
    InvalidLineRange(String),

    /// A required field is missing or empty.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Snippet exceeds the maximum allowed lines.
    #[error("snippet exceeds maximum of {max} lines (got {actual})")]
    SnippetTooLong {
        /// Maximum allowed lines.
        max: usize,
        /// Actual number of lines.
        actual: usize,
    },

    /// A generic analysis error.
    #[error("analysis error: {0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// LineRange
// ---------------------------------------------------------------------------

/// A 1-indexed source-code line and column range.
///
/// Invariants enforced at construction:
/// - `start_line >= 1` and `end_line >= 1`
/// - `start_line <= end_line`
/// - If `start_line == end_line`, then `start_col <= end_col`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LineRange {
    /// 1-indexed start line.
    pub start_line: u32,
    /// 1-indexed start column.
    pub start_col: u32,
    /// 1-indexed end line.
    pub end_line: u32,
    /// 1-indexed end column.
    pub end_col: u32,
}

impl LineRange {
    /// Creates a new `LineRange` after validating the invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AnalysisError::InvalidLineRange`] if validation fails.
    pub fn new(
        start_line: u32,
        start_col: u32,
        end_line: u32,
        end_col: u32,
    ) -> Result<Self, AnalysisError> {
        let range = Self {
            start_line,
            start_col,
            end_line,
            end_col,
        };
        range.validate()?;
        Ok(range)
    }

    /// Validates that the line range invariants hold.
    ///
    /// # Errors
    ///
    /// Returns [`AnalysisError::InvalidLineRange`] if:
    /// - `start_line` or `end_line` is zero (not 1-indexed).
    /// - `start_line > end_line`.
    /// - `start_line == end_line` and `start_col > end_col`.
    pub fn validate(&self) -> Result<(), AnalysisError> {
        if self.start_line == 0 {
            return Err(AnalysisError::InvalidLineRange(
                "start_line must be >= 1 (1-indexed)".to_string(),
            ));
        }
        if self.end_line == 0 {
            return Err(AnalysisError::InvalidLineRange(
                "end_line must be >= 1 (1-indexed)".to_string(),
            ));
        }
        if self.start_line > self.end_line {
            return Err(AnalysisError::InvalidLineRange(format!(
                "start_line ({}) must be <= end_line ({})",
                self.start_line, self.end_line
            )));
        }
        if self.start_line == self.end_line && self.start_col > self.end_col {
            return Err(AnalysisError::InvalidLineRange(format!(
                "on the same line ({}), start_col ({}) must be <= end_col ({})",
                self.start_line, self.start_col, self.end_col
            )));
        }
        Ok(())
    }

    /// Returns the number of lines spanned by this range (inclusive).
    #[must_use]
    pub const fn line_span(&self) -> u32 {
        self.end_line - self.start_line + 1
    }
}

impl fmt::Display for LineRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}-{}:{}",
            self.start_line, self.start_col, self.end_line, self.end_col
        )
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// Maximum number of lines allowed in a snippet.
const MAX_SNIPPET_LINES: usize = 10;

/// A single SAST finding produced by an analysis rule.
///
/// Findings are deterministically ordered by `(file_path, start_line, start_col, rule_id)`
/// to ensure stable, reproducible output across runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Content-based fingerprint: SHA-256 hex digest of
    /// `rule_id + relative_path + normalized_snippet`.
    pub fingerprint: String,

    /// Rule identifier in the format `atlas/{category}/{lang}/{name}`.
    pub rule_id: String,

    /// Severity of the finding.
    pub severity: Severity,

    /// Category grouping for the finding.
    pub category: Category,

    /// Optional CWE identifier (e.g. `"CWE-89"`).
    pub cwe_id: Option<String>,

    /// Relative file path using forward slashes, no leading `./`.
    pub file_path: String,

    /// 1-indexed source location range.
    pub line_range: LineRange,

    /// Source code snippet (max 10 lines).
    pub snippet: String,

    /// Human-readable description of the finding.
    pub description: String,

    /// Actionable remediation guidance.
    pub remediation: String,

    /// Analysis depth that produced this finding.
    pub analysis_level: AnalysisLevel,

    /// Confidence level of the detection.
    pub confidence: Confidence,

    /// Extensible metadata (deterministic ordering via `BTreeMap`).
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Finding {
    /// Computes a content-based fingerprint (SHA-256 hex digest).
    ///
    /// The input is the concatenation of:
    /// 1. `rule_id`
    /// 2. `relative_path`
    /// 3. Normalized snippet (trimmed whitespace, `\r\n` -> `\n`)
    #[must_use]
    pub fn compute_fingerprint(rule_id: &str, relative_path: &str, snippet: &str) -> String {
        let normalized = Self::normalize_snippet(snippet);
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(relative_path.as_bytes());
        hasher.update(normalized.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Normalizes a snippet for fingerprinting:
    /// - Replaces `\r\n` with `\n`
    /// - Trims leading/trailing whitespace from each line
    /// - Trims overall leading/trailing whitespace
    #[must_use]
    fn normalize_snippet(snippet: &str) -> String {
        snippet
            .replace("\r\n", "\n")
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string()
    }

    /// Normalizes the file path: converts backslashes to forward slashes and
    /// strips a leading `./` prefix.
    #[must_use]
    fn normalize_path(path: &str) -> String {
        let normalized = path.replace('\\', "/");
        normalized
            .strip_prefix("./")
            .unwrap_or(&normalized)
            .to_string()
    }

    /// Validates the snippet line count against [`MAX_SNIPPET_LINES`].
    fn validate_snippet(snippet: &str) -> Result<(), AnalysisError> {
        let line_count = snippet.lines().count();
        if line_count > MAX_SNIPPET_LINES {
            return Err(AnalysisError::SnippetTooLong {
                max: MAX_SNIPPET_LINES,
                actual: line_count,
            });
        }
        Ok(())
    }
}

/// Deterministic ordering: `(file_path, start_line, start_col, rule_id)`.
impl Ord for Finding {
    fn cmp(&self, other: &Self) -> Ordering {
        self.file_path
            .cmp(&other.file_path)
            .then_with(|| self.line_range.start_line.cmp(&other.line_range.start_line))
            .then_with(|| self.line_range.start_col.cmp(&other.line_range.start_col))
            .then_with(|| self.rule_id.cmp(&other.rule_id))
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {}:{} -- {}",
            self.severity, self.rule_id, self.file_path, self.line_range, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// FindingBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing [`Finding`] instances with validation.
///
/// All required fields must be set before calling [`FindingBuilder::build`].
#[derive(Debug, Default)]
pub struct FindingBuilder {
    rule_id: Option<String>,
    severity: Option<Severity>,
    category: Option<Category>,
    cwe_id: Option<String>,
    file_path: Option<String>,
    line_range: Option<LineRange>,
    snippet: Option<String>,
    description: Option<String>,
    remediation: Option<String>,
    analysis_level: Option<AnalysisLevel>,
    confidence: Option<Confidence>,
    metadata: BTreeMap<String, serde_json::Value>,
}

impl FindingBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the rule identifier.
    #[must_use]
    pub fn rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Sets the severity.
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Sets the category.
    #[must_use]
    pub fn category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self
    }

    /// Sets an optional CWE identifier (e.g. `"CWE-89"`).
    #[must_use]
    pub fn cwe_id(mut self, cwe_id: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe_id.into());
        self
    }

    /// Sets the relative file path.
    #[must_use]
    pub fn file_path(mut self, file_path: impl Into<String>) -> Self {
        self.file_path = Some(file_path.into());
        self
    }

    /// Sets the line range.
    #[must_use]
    pub fn line_range(mut self, line_range: LineRange) -> Self {
        self.line_range = Some(line_range);
        self
    }

    /// Sets the source code snippet.
    #[must_use]
    pub fn snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    /// Sets the human-readable description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the remediation guidance.
    #[must_use]
    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Sets the analysis level.
    #[must_use]
    pub fn analysis_level(mut self, analysis_level: AnalysisLevel) -> Self {
        self.analysis_level = Some(analysis_level);
        self
    }

    /// Sets the confidence level.
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Inserts a metadata key-value pair.
    #[must_use]
    pub fn meta(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Replaces the entire metadata map.
    #[must_use]
    pub fn metadata(mut self, metadata: BTreeMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Builds the [`Finding`], computing the fingerprint and validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`AnalysisError::MissingField`] if any required field is not set.
    /// Returns [`AnalysisError::SnippetTooLong`] if the snippet exceeds 10 lines.
    pub fn build(self) -> Result<Finding, AnalysisError> {
        let rule_id = self
            .rule_id
            .ok_or_else(|| AnalysisError::MissingField("rule_id".to_string()))?;
        let severity = self
            .severity
            .ok_or_else(|| AnalysisError::MissingField("severity".to_string()))?;
        let category = self
            .category
            .ok_or_else(|| AnalysisError::MissingField("category".to_string()))?;
        let file_path = self
            .file_path
            .ok_or_else(|| AnalysisError::MissingField("file_path".to_string()))?;
        let line_range = self
            .line_range
            .ok_or_else(|| AnalysisError::MissingField("line_range".to_string()))?;
        let snippet = self
            .snippet
            .ok_or_else(|| AnalysisError::MissingField("snippet".to_string()))?;
        let description = self
            .description
            .ok_or_else(|| AnalysisError::MissingField("description".to_string()))?;
        let remediation = self
            .remediation
            .ok_or_else(|| AnalysisError::MissingField("remediation".to_string()))?;
        let analysis_level = self
            .analysis_level
            .ok_or_else(|| AnalysisError::MissingField("analysis_level".to_string()))?;
        let confidence = self
            .confidence
            .ok_or_else(|| AnalysisError::MissingField("confidence".to_string()))?;

        // Validate snippet length.
        Finding::validate_snippet(&snippet)?;

        // Normalize file path.
        let file_path = Finding::normalize_path(&file_path);

        // Compute content-based fingerprint.
        let fingerprint = Finding::compute_fingerprint(&rule_id, &file_path, &snippet);

        Ok(Finding {
            fingerprint,
            rule_id,
            severity,
            category,
            cwe_id: self.cwe_id,
            file_path,
            line_range,
            snippet,
            description,
            remediation,
            analysis_level,
            confidence,
            metadata: self.metadata,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper ---------------------------------------------------------------

    /// Creates a minimal valid `LineRange` for testing.
    fn sample_line_range() -> LineRange {
        LineRange::new(10, 5, 12, 20).unwrap()
    }

    /// Creates a minimal valid `Finding` using the builder.
    fn sample_finding() -> Finding {
        FindingBuilder::new()
            .rule_id("atlas/security/js/sql-injection")
            .severity(Severity::High)
            .category(Category::Security)
            .cwe_id("CWE-89")
            .file_path("src/db/query.js")
            .line_range(sample_line_range())
            .snippet("const q = \"SELECT * FROM users WHERE id=\" + userId;")
            .description("SQL injection via string concatenation")
            .remediation("Use parameterized queries instead of string concatenation.")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap()
    }

    // -- LineRange tests ------------------------------------------------------

    #[test]
    fn line_range_valid() {
        let r = LineRange::new(1, 1, 5, 10);
        assert!(r.is_ok());
        let r = r.unwrap();
        assert_eq!(r.start_line, 1);
        assert_eq!(r.start_col, 1);
        assert_eq!(r.end_line, 5);
        assert_eq!(r.end_col, 10);
    }

    #[test]
    fn line_range_single_line_valid() {
        let r = LineRange::new(3, 5, 3, 20);
        assert!(r.is_ok());
        assert_eq!(r.unwrap().line_span(), 1);
    }

    #[test]
    fn line_range_single_position() {
        // start == end, same col
        let r = LineRange::new(1, 1, 1, 1);
        assert!(r.is_ok());
    }

    #[test]
    fn line_range_start_line_zero() {
        let r = LineRange::new(0, 1, 5, 1);
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(
            err.to_string().contains("start_line must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn line_range_end_line_zero() {
        let r = LineRange::new(1, 1, 0, 1);
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(
            err.to_string().contains("end_line must be >= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn line_range_start_after_end() {
        let r = LineRange::new(10, 1, 5, 1);
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(
            err.to_string()
                .contains("start_line (10) must be <= end_line (5)"),
            "got: {err}"
        );
    }

    #[test]
    fn line_range_same_line_col_reversed() {
        let r = LineRange::new(5, 20, 5, 10);
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(
            err.to_string()
                .contains("start_col (20) must be <= end_col (10)"),
            "got: {err}"
        );
    }

    #[test]
    fn line_range_different_lines_col_order_irrelevant() {
        // When on different lines, start_col > end_col is fine.
        let r = LineRange::new(1, 50, 2, 1);
        assert!(r.is_ok());
    }

    #[test]
    fn line_range_line_span() {
        let r = LineRange::new(3, 1, 7, 1).unwrap();
        assert_eq!(r.line_span(), 5);
    }

    #[test]
    fn line_range_display() {
        let r = LineRange::new(10, 5, 12, 20).unwrap();
        assert_eq!(r.to_string(), "10:5-12:20");
    }

    #[test]
    fn line_range_ordering() {
        let a = LineRange::new(1, 1, 1, 10).unwrap();
        let b = LineRange::new(1, 1, 2, 5).unwrap();
        let c = LineRange::new(2, 1, 3, 1).unwrap();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn line_range_serde_roundtrip() {
        let range = LineRange::new(5, 10, 8, 30).unwrap();
        let json = serde_json::to_string(&range).unwrap();
        let back: LineRange = serde_json::from_str(&json).unwrap();
        assert_eq!(range, back);
    }

    #[test]
    fn line_range_copy_semantics() {
        let a = LineRange::new(1, 1, 1, 1).unwrap();
        let b = a; // Copy
        assert_eq!(a, b); // `a` still usable
    }

    // -- Finding fingerprint tests -------------------------------------------

    #[test]
    fn fingerprint_deterministic() {
        let fp1 = Finding::compute_fingerprint("rule/a", "src/main.rs", "let x = 1;");
        let fp2 = Finding::compute_fingerprint("rule/a", "src/main.rs", "let x = 1;");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn fingerprint_changes_with_rule_id() {
        let fp1 = Finding::compute_fingerprint("rule/a", "file.rs", "code");
        let fp2 = Finding::compute_fingerprint("rule/b", "file.rs", "code");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_changes_with_path() {
        let fp1 = Finding::compute_fingerprint("rule/a", "src/a.rs", "code");
        let fp2 = Finding::compute_fingerprint("rule/a", "src/b.rs", "code");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_changes_with_snippet() {
        let fp1 = Finding::compute_fingerprint("rule/a", "file.rs", "let x = 1;");
        let fp2 = Finding::compute_fingerprint("rule/a", "file.rs", "let x = 2;");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_normalizes_crlf() {
        let fp1 = Finding::compute_fingerprint("rule/a", "file.rs", "line1\nline2");
        let fp2 = Finding::compute_fingerprint("rule/a", "file.rs", "line1\r\nline2");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_normalizes_whitespace() {
        let fp1 = Finding::compute_fingerprint("rule/a", "file.rs", "  let x = 1;  ");
        let fp2 = Finding::compute_fingerprint("rule/a", "file.rs", "let x = 1;");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_normalizes_multiline_whitespace() {
        let snippet1 = "  line1\n  line2  ";
        let snippet2 = "line1\nline2";
        let fp1 = Finding::compute_fingerprint("rule/a", "file.rs", snippet1);
        let fp2 = Finding::compute_fingerprint("rule/a", "file.rs", snippet2);
        assert_eq!(fp1, fp2);
    }

    // -- Finding builder tests ------------------------------------------------

    #[test]
    fn builder_creates_valid_finding() {
        let finding = sample_finding();
        assert_eq!(finding.rule_id, "atlas/security/js/sql-injection");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.category, Category::Security);
        assert_eq!(finding.cwe_id, Some("CWE-89".to_string()));
        assert_eq!(finding.file_path, "src/db/query.js");
        assert_eq!(finding.line_range.start_line, 10);
        assert_eq!(finding.analysis_level, AnalysisLevel::L1);
        assert_eq!(finding.confidence, Confidence::High);
        assert!(!finding.fingerprint.is_empty());
        assert_eq!(finding.fingerprint.len(), 64);
    }

    #[test]
    fn builder_missing_rule_id() {
        let result = FindingBuilder::new()
            .severity(Severity::High)
            .category(Category::Security)
            .file_path("src/main.rs")
            .line_range(sample_line_range())
            .snippet("code")
            .description("desc")
            .remediation("fix it")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rule_id"));
    }

    #[test]
    fn builder_missing_severity() {
        let result = FindingBuilder::new()
            .rule_id("atlas/security/js/test")
            .category(Category::Security)
            .file_path("src/main.rs")
            .line_range(sample_line_range())
            .snippet("code")
            .description("desc")
            .remediation("fix it")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("severity"));
    }

    #[test]
    fn builder_without_cwe_id() {
        let finding = FindingBuilder::new()
            .rule_id("atlas/quality/js/unused-var")
            .severity(Severity::Low)
            .category(Category::Quality)
            .file_path("src/utils.js")
            .line_range(LineRange::new(1, 1, 1, 20).unwrap())
            .snippet("const unused = 42;")
            .description("Unused variable")
            .remediation("Remove unused variable or prefix with underscore.")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::Medium)
            .build()
            .unwrap();
        assert_eq!(finding.cwe_id, None);
    }

    #[test]
    fn builder_with_metadata() {
        let finding = FindingBuilder::new()
            .rule_id("atlas/security/js/xss")
            .severity(Severity::Medium)
            .category(Category::Security)
            .cwe_id("CWE-79")
            .file_path("src/render.js")
            .line_range(LineRange::new(1, 1, 1, 30).unwrap())
            .snippet("el.textContent = userInput;")
            .description("Potential XSS")
            .remediation("Sanitize input.")
            .analysis_level(AnalysisLevel::L2)
            .confidence(Confidence::Medium)
            .meta("source", serde_json::json!("userInput"))
            .meta("sink", serde_json::json!("textContent"))
            .build()
            .unwrap();

        assert_eq!(finding.metadata.len(), 2);
        assert_eq!(finding.metadata["source"], serde_json::json!("userInput"));
        assert_eq!(finding.metadata["sink"], serde_json::json!("textContent"));
    }

    #[test]
    fn builder_normalizes_path_backslashes() {
        let finding = FindingBuilder::new()
            .rule_id("atlas/security/js/test")
            .severity(Severity::Low)
            .category(Category::Security)
            .file_path("src\\db\\query.js")
            .line_range(LineRange::new(1, 1, 1, 10).unwrap())
            .snippet("code")
            .description("desc")
            .remediation("fix")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap();
        assert_eq!(finding.file_path, "src/db/query.js");
    }

    #[test]
    fn builder_normalizes_path_leading_dot_slash() {
        let finding = FindingBuilder::new()
            .rule_id("atlas/security/js/test")
            .severity(Severity::Low)
            .category(Category::Security)
            .file_path("./src/main.js")
            .line_range(LineRange::new(1, 1, 1, 10).unwrap())
            .snippet("code")
            .description("desc")
            .remediation("fix")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap();
        assert_eq!(finding.file_path, "src/main.js");
    }

    #[test]
    fn builder_snippet_too_long() {
        let long_snippet = (1..=11)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let result = FindingBuilder::new()
            .rule_id("atlas/security/js/test")
            .severity(Severity::Low)
            .category(Category::Security)
            .file_path("src/main.js")
            .line_range(LineRange::new(1, 1, 11, 10).unwrap())
            .snippet(long_snippet)
            .description("desc")
            .remediation("fix")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn builder_snippet_exactly_10_lines() {
        let snippet = (1..=10)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let result = FindingBuilder::new()
            .rule_id("atlas/security/js/test")
            .severity(Severity::Low)
            .category(Category::Security)
            .file_path("src/main.js")
            .line_range(LineRange::new(1, 1, 10, 10).unwrap())
            .snippet(snippet)
            .description("desc")
            .remediation("fix")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build();
        assert!(result.is_ok());
    }

    // -- Finding ordering tests -----------------------------------------------

    #[test]
    fn finding_ordering_by_file_path() {
        let mut f1 = sample_finding();
        let mut f2 = sample_finding();
        f1.file_path = "aaa/file.js".to_string();
        f2.file_path = "zzz/file.js".to_string();
        assert!(f1 < f2);
    }

    #[test]
    fn finding_ordering_by_start_line() {
        let mut f1 = sample_finding();
        let mut f2 = sample_finding();
        f1.line_range = LineRange::new(1, 1, 1, 10).unwrap();
        f2.line_range = LineRange::new(5, 1, 5, 10).unwrap();
        assert!(f1 < f2);
    }

    #[test]
    fn finding_ordering_by_start_col() {
        let mut f1 = sample_finding();
        let mut f2 = sample_finding();
        f1.line_range = LineRange::new(1, 1, 1, 10).unwrap();
        f2.line_range = LineRange::new(1, 5, 1, 10).unwrap();
        assert!(f1 < f2);
    }

    #[test]
    fn finding_ordering_by_rule_id() {
        let mut f1 = sample_finding();
        let mut f2 = sample_finding();
        f1.line_range = LineRange::new(1, 1, 1, 10).unwrap();
        f2.line_range = LineRange::new(1, 1, 1, 10).unwrap();
        f1.rule_id = "atlas/security/js/aaa".to_string();
        f2.rule_id = "atlas/security/js/zzz".to_string();
        assert!(f1 < f2);
    }

    #[test]
    fn findings_sort_deterministically() {
        let line_a = LineRange::new(5, 1, 5, 10).unwrap();
        let line_b = LineRange::new(10, 1, 10, 10).unwrap();
        let line_c = LineRange::new(5, 1, 5, 10).unwrap();

        let build = |file: &str, lr: LineRange, rule: &str| {
            FindingBuilder::new()
                .rule_id(rule)
                .severity(Severity::High)
                .category(Category::Security)
                .file_path(file)
                .line_range(lr)
                .snippet("code")
                .description("desc")
                .remediation("fix")
                .analysis_level(AnalysisLevel::L1)
                .confidence(Confidence::High)
                .build()
                .unwrap()
        };

        let mut findings = [
            build("src/z.js", line_b, "atlas/security/js/b"),
            build("src/a.js", line_a, "atlas/security/js/b"),
            build("src/a.js", line_c, "atlas/security/js/a"),
        ];
        findings.sort();

        assert_eq!(findings[0].file_path, "src/a.js");
        assert_eq!(findings[0].rule_id, "atlas/security/js/a");
        assert_eq!(findings[1].file_path, "src/a.js");
        assert_eq!(findings[1].rule_id, "atlas/security/js/b");
        assert_eq!(findings[2].file_path, "src/z.js");
    }

    // -- Finding serde tests --------------------------------------------------

    #[test]
    fn finding_serde_roundtrip() {
        let finding = sample_finding();
        let json = serde_json::to_string_pretty(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    #[test]
    fn finding_serde_json_structure() {
        let finding = sample_finding();
        let value: serde_json::Value = serde_json::to_value(&finding).unwrap();

        // Verify key fields are present and have correct types.
        assert!(value["fingerprint"].is_string());
        assert!(value["rule_id"].is_string());
        assert!(value["severity"].is_string());
        assert!(value["category"].is_string());
        assert!(value["cwe_id"].is_string());
        assert!(value["file_path"].is_string());
        assert!(value["line_range"].is_object());
        assert!(value["snippet"].is_string());
        assert!(value["description"].is_string());
        assert!(value["remediation"].is_string());
        assert!(value["analysis_level"].is_string());
        assert!(value["confidence"].is_string());
        assert!(value["metadata"].is_object());
    }

    #[test]
    fn finding_serde_null_cwe() {
        let finding = FindingBuilder::new()
            .rule_id("atlas/quality/js/unused")
            .severity(Severity::Low)
            .category(Category::Quality)
            .file_path("src/main.js")
            .line_range(LineRange::new(1, 1, 1, 10).unwrap())
            .snippet("code")
            .description("desc")
            .remediation("fix")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::Low)
            .build()
            .unwrap();
        let value: serde_json::Value = serde_json::to_value(&finding).unwrap();
        assert!(value["cwe_id"].is_null());
    }

    // -- Finding display test -------------------------------------------------

    #[test]
    fn finding_display() {
        let finding = sample_finding();
        let display = finding.to_string();
        assert!(display.contains("high"));
        assert!(display.contains("atlas/security/js/sql-injection"));
        assert!(display.contains("src/db/query.js"));
        assert!(display.contains("SQL injection"));
    }

    // -- AnalysisError tests --------------------------------------------------

    #[test]
    fn analysis_error_display_invalid_line_range() {
        let err = AnalysisError::InvalidLineRange("test message".to_string());
        assert_eq!(err.to_string(), "invalid line range: test message");
    }

    #[test]
    fn analysis_error_display_missing_field() {
        let err = AnalysisError::MissingField("rule_id".to_string());
        assert_eq!(err.to_string(), "missing required field: rule_id");
    }

    #[test]
    fn analysis_error_display_snippet_too_long() {
        let err = AnalysisError::SnippetTooLong {
            max: 10,
            actual: 15,
        };
        assert_eq!(
            err.to_string(),
            "snippet exceeds maximum of 10 lines (got 15)"
        );
    }

    #[test]
    fn analysis_error_display_other() {
        let err = AnalysisError::Other("something went wrong".to_string());
        assert_eq!(err.to_string(), "analysis error: something went wrong");
    }

    // -- Fingerprint consistency test -----------------------------------------

    #[test]
    fn fingerprint_matches_builder_output() {
        let rule_id = "atlas/security/js/sql-injection";
        let file_path = "src/db/query.js";
        let snippet = "const q = \"SELECT * FROM users WHERE id=\" + userId;";

        let expected = Finding::compute_fingerprint(rule_id, file_path, snippet);
        let finding = FindingBuilder::new()
            .rule_id(rule_id)
            .severity(Severity::High)
            .category(Category::Security)
            .file_path(file_path)
            .line_range(sample_line_range())
            .snippet(snippet)
            .description("desc")
            .remediation("fix")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap();

        assert_eq!(finding.fingerprint, expected);
    }
}
