//! Atlas Core -- shared types, engine orchestration, file discovery, and scan coordination.
//!
//! This crate defines the shared enum types used throughout the Atlas Local SAST tool,
//! including severity levels, categories, analysis levels, confidence scores, supported
//! languages, and policy/gate types.

use serde::{Deserialize, Serialize};
use std::fmt;

// Future modules -- uncomment as they are implemented.
pub mod config;
pub mod engine;
pub mod scanner;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Top-level error type for the atlas-core crate.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// An I/O error occurred during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// A rule evaluation error.
    #[error("rule evaluation error: {0}")]
    RuleEvaluation(String),

    /// A policy evaluation error.
    #[error("policy evaluation error: {0}")]
    PolicyEvaluation(String),

    /// An unsupported language was encountered.
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),

    /// Tracing/logging initialization failed.
    #[error("tracing initialization error: {0}")]
    TracingInit(String),
}

/// Convenience alias for `Result<T, CoreError>`.
pub type CoreResult<T> = Result<T, CoreError>;

// ---------------------------------------------------------------------------
// Tracing / Logging
// ---------------------------------------------------------------------------

/// Initialize structured tracing with the given verbosity level.
///
/// # Behaviour
///
/// | `verbose` | `quiet` | `json_output` | Effect                                  |
/// |-----------|---------|---------------|-----------------------------------------|
/// | `true`    | _       | _             | TRACE level (most verbose)              |
/// | _         | `true`  | _             | ERROR level only                        |
/// | `false`   | `false` | _             | INFO level (default)                    |
/// | _         | _       | `true`        | JSON-formatted log lines (CI/CD)        |
/// | _         | _       | `false`       | Human-readable, compact log lines       |
///
/// The `RUST_LOG` environment variable, when set, takes precedence over the
/// programmatic level selection so that operators can fine-tune per-module
/// verbosity without recompiling.
///
/// # Errors
///
/// Returns [`CoreError::TracingInit`] if the global subscriber has already been
/// set (i.e. this function was called more than once in the same process).
pub fn init_tracing(verbose: bool, quiet: bool, json_output: bool) -> Result<(), CoreError> {
    use tracing_subscriber::{fmt, EnvFilter};

    // Determine the base log level from CLI flags.
    let default_level = if verbose {
        "trace"
    } else if quiet {
        "error"
    } else {
        "info"
    };

    // Allow RUST_LOG to override the programmatic default.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    if json_output {
        fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .try_init()
            .map_err(|e| CoreError::TracingInit(e.to_string()))
    } else {
        fmt()
            .compact()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .try_init()
            .map_err(|e| CoreError::TracingInit(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Finding severity levels, ordered from highest to lowest impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Critical severity -- must be fixed immediately.
    Critical,
    /// High severity -- should be fixed before release.
    High,
    /// Medium severity -- should be addressed in a timely manner.
    Medium,
    /// Low severity -- minor issue, fix when convenient.
    Low,
    /// Informational -- no direct risk, advisory only.
    Info,
}

impl Severity {
    /// Returns a numeric score for this severity level.
    ///
    /// Higher values indicate higher severity:
    /// - `Critical` = 4
    /// - `High` = 3
    /// - `Medium` = 2
    /// - `Low` = 1
    /// - `Info` = 0
    #[must_use]
    pub const fn numeric_score(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }

    /// Returns all severity variants in descending order (Critical first).
    #[must_use]
    pub const fn all() -> &'static [Severity] {
        &[
            Self::Critical,
            Self::High,
            Self::Medium,
            Self::Low,
            Self::Info,
        ]
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/// Finding category that groups rules by their detection domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Security vulnerabilities (SQL injection, XSS, etc.).
    Security,
    /// Code quality issues (unused variables, complexity, etc.).
    Quality,
    /// Hard-coded secrets and credentials.
    Secrets,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Security => "security",
            Self::Quality => "quality",
            Self::Secrets => "secrets",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// AnalysisLevel
// ---------------------------------------------------------------------------

/// Depth of analysis performed by a rule.
///
/// - **L1**: Pattern matching on the AST (declarative S-expression queries).
/// - **L2**: Intra-procedural data-flow analysis.
/// - **L3**: Inter-procedural / taint tracking analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalysisLevel {
    /// Level 1 -- AST pattern matching.
    L1,
    /// Level 2 -- Intra-procedural data-flow analysis.
    L2,
    /// Level 3 -- Inter-procedural taint tracking.
    L3,
}

impl AnalysisLevel {
    /// Returns a numeric depth for this level (1, 2, or 3).
    #[must_use]
    pub const fn depth(self) -> u8 {
        match self {
            Self::L1 => 1,
            Self::L2 => 2,
            Self::L3 => 3,
        }
    }
}

impl fmt::Display for AnalysisLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Confidence (re-exported from atlas-rules)
// ---------------------------------------------------------------------------

pub use atlas_rules::Confidence;

// ---------------------------------------------------------------------------
// Language (re-exported from atlas-lang to avoid circular dependencies)
// ---------------------------------------------------------------------------

pub use atlas_lang::Language;

// ---------------------------------------------------------------------------
// RuleType
// ---------------------------------------------------------------------------

/// Implementation strategy for a detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RuleType {
    /// Declarative S-expression pattern matching (L1 only).
    Declarative,
    /// Rhai-scripted analysis logic (L2/L3).
    Scripted,
    /// Compiled native plugin via cdylib (L2/L3).
    Compiled,
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Declarative => "Declarative",
            Self::Scripted => "Scripted",
            Self::Compiled => "Compiled",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Outcome of policy gate evaluation after a scan completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GateResult {
    /// All policy thresholds satisfied.
    Pass,
    /// One or more policy thresholds breached -- scan fails the gate.
    Fail,
    /// Warning thresholds reached but failure thresholds not breached.
    Warn,
}

impl GateResult {
    /// Returns `true` if the gate result indicates a passing scan.
    #[must_use]
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns `true` if the gate result indicates a failing scan.
    #[must_use]
    pub const fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for GateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// PolicyLevel
// ---------------------------------------------------------------------------

/// Hierarchical level at which a policy is defined.
///
/// Policies merge using specificity precedence: `Local > Project > Team > Organization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicyLevel {
    /// Organization-wide policy (least specific).
    Organization,
    /// Team-level policy.
    Team,
    /// Project-level policy.
    Project,
    /// Local developer override (most specific).
    Local,
}

impl PolicyLevel {
    /// Returns the specificity rank (higher = more specific).
    ///
    /// - `Organization` = 0
    /// - `Team` = 1
    /// - `Project` = 2
    /// - `Local` = 3
    #[must_use]
    pub const fn specificity(self) -> u8 {
        match self {
            Self::Organization => 0,
            Self::Team => 1,
            Self::Project => 2,
            Self::Local => 3,
        }
    }
}

impl fmt::Display for PolicyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Organization => "Organization",
            Self::Team => "Team",
            Self::Project => "Project",
            Self::Local => "Local",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// LicenseType
// ---------------------------------------------------------------------------

/// License entitlement model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LicenseType {
    /// Locked to a specific machine via hardware fingerprint.
    NodeLocked,
    /// Shared license pool managed by a license server.
    Floating,
}

impl fmt::Display for LicenseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::NodeLocked => "NodeLocked",
            Self::Floating => "Floating",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// FindingStatus
// ---------------------------------------------------------------------------

/// Status of a finding relative to a baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FindingStatus {
    /// Finding is new (not present in baseline); counts against policy gates.
    New,
    /// Finding fingerprint exists in baseline; excluded from gate evaluation.
    Baselined,
    /// Finding was in baseline but is no longer detected (fixed).
    Resolved,
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::New => "New",
            Self::Baselined => "Baselined",
            Self::Resolved => "Resolved",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_numeric_scores() {
        assert_eq!(Severity::Critical.numeric_score(), 4);
        assert_eq!(Severity::High.numeric_score(), 3);
        assert_eq!(Severity::Medium.numeric_score(), 2);
        assert_eq!(Severity::Low.numeric_score(), 1);
        assert_eq!(Severity::Info.numeric_score(), 0);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn severity_serde_roundtrip() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Severity::Critical);
    }

    #[test]
    fn category_serde_roundtrip() {
        let json = serde_json::to_string(&Category::Security).unwrap();
        assert_eq!(json, "\"security\"");
        let back: Category = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Category::Security);
    }

    #[test]
    fn category_display() {
        assert_eq!(Category::Security.to_string(), "security");
        assert_eq!(Category::Quality.to_string(), "quality");
        assert_eq!(Category::Secrets.to_string(), "secrets");
    }

    #[test]
    fn analysis_level_depth() {
        assert_eq!(AnalysisLevel::L1.depth(), 1);
        assert_eq!(AnalysisLevel::L2.depth(), 2);
        assert_eq!(AnalysisLevel::L3.depth(), 3);
    }

    #[test]
    fn analysis_level_serde_roundtrip() {
        let json = serde_json::to_string(&AnalysisLevel::L2).unwrap();
        assert_eq!(json, "\"L2\"");
        let back: AnalysisLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AnalysisLevel::L2);
    }

    #[test]
    fn confidence_display() {
        assert_eq!(Confidence::High.to_string(), "high");
        assert_eq!(Confidence::Medium.to_string(), "medium");
        assert_eq!(Confidence::Low.to_string(), "low");
    }

    #[test]
    fn confidence_serde_roundtrip() {
        let json = serde_json::to_string(&Confidence::Low).unwrap();
        assert_eq!(json, "\"low\"");
        let back: Confidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Confidence::Low);
    }

    #[test]
    fn language_extensions() {
        assert_eq!(Language::TypeScript.extensions(), &[".ts", ".tsx"]);
        assert_eq!(
            Language::JavaScript.extensions(),
            &[".js", ".jsx", ".mjs", ".cjs"]
        );
        assert_eq!(Language::Java.extensions(), &[".java"]);
        assert_eq!(Language::Python.extensions(), &[".py", ".pyi"]);
        assert_eq!(Language::Go.extensions(), &[".go"]);
        assert_eq!(Language::CSharp.extensions(), &[".cs"]);
    }

    #[test]
    fn language_from_extension() {
        assert_eq!(Language::from_extension(".ts"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension(".tsx"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension(".js"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".jsx"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".mjs"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".cjs"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".java"), Some(Language::Java));
        assert_eq!(Language::from_extension(".py"), Some(Language::Python));
        assert_eq!(Language::from_extension(".pyi"), Some(Language::Python));
        assert_eq!(Language::from_extension(".go"), Some(Language::Go));
        assert_eq!(Language::from_extension(".cs"), Some(Language::CSharp));
        assert_eq!(Language::from_extension(".rb"), None);
    }

    #[test]
    fn language_serde_roundtrip() {
        let json = serde_json::to_string(&Language::CSharp).unwrap();
        assert_eq!(json, "\"CSharp\"");
        let back: Language = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Language::CSharp);
    }

    #[test]
    fn rule_type_display() {
        assert_eq!(RuleType::Declarative.to_string(), "Declarative");
        assert_eq!(RuleType::Scripted.to_string(), "Scripted");
        assert_eq!(RuleType::Compiled.to_string(), "Compiled");
    }

    #[test]
    fn gate_result_serde_uppercase() {
        let json = serde_json::to_string(&GateResult::Pass).unwrap();
        assert_eq!(json, "\"PASS\"");
        let json = serde_json::to_string(&GateResult::Fail).unwrap();
        assert_eq!(json, "\"FAIL\"");
        let json = serde_json::to_string(&GateResult::Warn).unwrap();
        assert_eq!(json, "\"WARN\"");
    }

    #[test]
    fn gate_result_helpers() {
        assert!(GateResult::Pass.is_pass());
        assert!(!GateResult::Pass.is_fail());
        assert!(GateResult::Fail.is_fail());
        assert!(!GateResult::Fail.is_pass());
        assert!(!GateResult::Warn.is_pass());
        assert!(!GateResult::Warn.is_fail());
    }

    #[test]
    fn policy_level_specificity() {
        assert_eq!(PolicyLevel::Organization.specificity(), 0);
        assert_eq!(PolicyLevel::Team.specificity(), 1);
        assert_eq!(PolicyLevel::Project.specificity(), 2);
        assert_eq!(PolicyLevel::Local.specificity(), 3);
    }

    #[test]
    fn license_type_display() {
        assert_eq!(LicenseType::NodeLocked.to_string(), "NodeLocked");
        assert_eq!(LicenseType::Floating.to_string(), "Floating");
    }

    #[test]
    fn finding_status_display() {
        assert_eq!(FindingStatus::New.to_string(), "New");
        assert_eq!(FindingStatus::Baselined.to_string(), "Baselined");
        assert_eq!(FindingStatus::Resolved.to_string(), "Resolved");
    }

    #[test]
    fn severity_ordering() {
        // Derived Ord follows variant declaration order.
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn all_languages_covered() {
        let all = Language::all();
        assert_eq!(all.len(), 6);
        // Every language should resolve from at least one of its own extensions.
        for lang in all {
            let ext = lang.extensions()[0];
            assert_eq!(Language::from_extension(ext), Some(*lang));
        }
    }

    #[test]
    fn all_severities_covered() {
        let all = Severity::all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn tracing_init_error_display() {
        let err = CoreError::TracingInit("already initialized".to_string());
        assert!(err.to_string().contains("tracing initialization error"));
        assert!(err.to_string().contains("already initialized"));
    }

    // NOTE: `init_tracing` sets a global subscriber, so it can only succeed once
    // per process.  We verify the *second* call returns an appropriate error.
    // The first call is intentionally made with defaults so the test is
    // deterministic regardless of execution order.
    #[test]
    fn init_tracing_returns_error_on_double_init() {
        // First call -- may succeed or fail if another test already set the
        // global subscriber; either outcome is acceptable.
        let _ = init_tracing(false, false, false);

        // Second call must fail.
        let result = init_tracing(false, false, false);
        assert!(result.is_err());
        if let Err(CoreError::TracingInit(msg)) = result {
            assert!(!msg.is_empty());
        } else {
            panic!("expected CoreError::TracingInit");
        }
    }
}
