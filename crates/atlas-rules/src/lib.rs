//! Atlas Rules — rule system, rulepack loading, and Rhai scripting engine.
//!
//! This crate defines the [`Rule`] struct representing a single SAST detection rule,
//! along with supporting enums and validation logic. Rules can be declarative
//! (tree-sitter S-expression patterns), scripted (Rhai scripts), or compiled
//! (native cdylib plugins).
//!
//! # Note on shared enums
//!
//! The enums [`Severity`], [`Category`], [`Language`], [`AnalysisLevel`], and
//! [`RuleType`] are defined here because `atlas-core` depends on `atlas-rules`,
//! which prevents importing them from `atlas-core` (circular dependency).
//! `atlas-core` re-exports these types from its own module.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

// Future modules -- uncomment as they are implemented.
pub mod declarative;
// pub mod scripted;
// pub mod compiled;
// pub mod rulepack;

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
// Language (re-exported from atlas-lang to avoid duplication)
// ---------------------------------------------------------------------------

pub use atlas_lang::Language;

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
// Confidence
// ---------------------------------------------------------------------------

/// Confidence level of a finding's detection accuracy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// High confidence -- very likely a true positive.
    High,
    /// Medium confidence -- probable true positive.
    Medium,
    /// Low confidence -- may be a false positive.
    Low,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        };
        f.write_str(label)
    }
}

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
// RuleError
// ---------------------------------------------------------------------------

/// Errors arising from rule validation.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// Exactly one of `pattern`, `script`, or `plugin` must be `Some`.
    #[error(
        "invalid rule type for rule '{rule_id}': exactly one of pattern/script/plugin must be set, \
         but found {set_count} set"
    )]
    InvalidRuleType {
        /// The rule ID that failed validation.
        rule_id: String,
        /// How many of the three optional fields were set.
        set_count: u8,
    },

    /// The `analysis_level` does not match the `rule_type`.
    ///
    /// L1 requires `Declarative`; L2/L3 require `Scripted` or `Compiled`.
    #[error(
        "analysis level mismatch for rule '{rule_id}': analysis_level={analysis_level} \
         is incompatible with rule_type={rule_type}"
    )]
    AnalysisLevelMismatch {
        /// The rule ID that failed validation.
        rule_id: String,
        /// The analysis level that was set.
        analysis_level: AnalysisLevel,
        /// The rule type that was set.
        rule_type: RuleType,
    },

    /// The rule type field does not match which optional field is populated.
    ///
    /// For example, `rule_type` is `Declarative` but `script` is `Some` instead of `pattern`.
    #[error(
        "rule type / field mismatch for rule '{rule_id}': rule_type={rule_type} but the \
         populated field is '{populated_field}'"
    )]
    RuleTypeFieldMismatch {
        /// The rule ID that failed validation.
        rule_id: String,
        /// The declared rule type.
        rule_type: RuleType,
        /// Which optional field was actually populated.
        populated_field: String,
    },

    /// The rule `id` field is empty.
    #[error("rule id must not be empty")]
    EmptyId,

    /// The rule `version` field is not valid SemVer.
    #[error("invalid version '{version}' for rule '{rule_id}': expected SemVer (e.g. 1.0.0)")]
    InvalidVersion {
        /// The rule ID that failed validation.
        rule_id: String,
        /// The invalid version string.
        version: String,
    },
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/// A single SAST detection rule.
///
/// Each rule defines *what* to detect, *how* to detect it (pattern, script, or
/// plugin), and metadata for reporting, remediation, and categorization.
///
/// # Validation
///
/// Call [`Rule::validate`] to ensure all structural constraints hold:
///
/// - Exactly one of `pattern`, `script`, or `plugin` must be `Some`.
/// - The populated field must match `rule_type` (Declarative -> pattern,
///   Scripted -> script, Compiled -> plugin).
/// - `analysis_level` must be compatible with `rule_type` (L1 -> Declarative;
///   L2/L3 -> Scripted or Compiled).
///
/// # Ordering
///
/// `Rule` implements [`Ord`] by `id` for deterministic, reproducible ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier in the format `atlas/{category}/{lang}/{name}`.
    pub id: String,

    /// Human-readable rule name.
    pub name: String,

    /// What the rule detects.
    pub description: String,

    /// Default severity when the rule triggers a finding.
    pub severity: Severity,

    /// Rule category (Security, Quality, Secrets).
    pub category: Category,

    /// Target programming language.
    pub language: Language,

    /// Required analysis depth.
    pub analysis_level: AnalysisLevel,

    /// Implementation strategy.
    pub rule_type: RuleType,

    /// Tree-sitter S-expression pattern for declarative (L1) rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Rhai script path for scripted (L2/L3) rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,

    /// cdylib path for compiled (L2/L3) rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,

    /// Associated CWE identifier (e.g. "CWE-79").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,

    /// Remediation guidance.
    pub remediation: String,

    /// External reference links.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// Searchable tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Rule version in SemVer format (e.g. "1.0.0").
    pub version: String,
}

impl Rule {
    /// Validates all structural constraints on this rule.
    ///
    /// # Errors
    ///
    /// Returns a [`RuleError`] if any constraint is violated:
    ///
    /// - [`RuleError::EmptyId`] if `id` is empty.
    /// - [`RuleError::InvalidRuleType`] if not exactly one of pattern/script/plugin is `Some`.
    /// - [`RuleError::RuleTypeFieldMismatch`] if the populated field does not match `rule_type`.
    /// - [`RuleError::AnalysisLevelMismatch`] if `analysis_level` is incompatible with `rule_type`.
    /// - [`RuleError::InvalidVersion`] if `version` is not valid SemVer.
    pub fn validate(&self) -> Result<(), RuleError> {
        // 1. id must not be empty.
        if self.id.is_empty() {
            return Err(RuleError::EmptyId);
        }

        // 2. Exactly one of pattern/script/plugin must be Some.
        let set_count = u8::from(self.pattern.is_some())
            + u8::from(self.script.is_some())
            + u8::from(self.plugin.is_some());

        if set_count != 1 {
            return Err(RuleError::InvalidRuleType {
                rule_id: self.id.clone(),
                set_count,
            });
        }

        // 3. The populated field must match rule_type.
        match self.rule_type {
            RuleType::Declarative => {
                if self.pattern.is_none() {
                    let field = if self.script.is_some() {
                        "script"
                    } else {
                        "plugin"
                    };
                    return Err(RuleError::RuleTypeFieldMismatch {
                        rule_id: self.id.clone(),
                        rule_type: self.rule_type,
                        populated_field: field.to_owned(),
                    });
                }
            }
            RuleType::Scripted => {
                if self.script.is_none() {
                    let field = if self.pattern.is_some() {
                        "pattern"
                    } else {
                        "plugin"
                    };
                    return Err(RuleError::RuleTypeFieldMismatch {
                        rule_id: self.id.clone(),
                        rule_type: self.rule_type,
                        populated_field: field.to_owned(),
                    });
                }
            }
            RuleType::Compiled => {
                if self.plugin.is_none() {
                    let field = if self.pattern.is_some() {
                        "pattern"
                    } else {
                        "script"
                    };
                    return Err(RuleError::RuleTypeFieldMismatch {
                        rule_id: self.id.clone(),
                        rule_type: self.rule_type,
                        populated_field: field.to_owned(),
                    });
                }
            }
        }

        // 4. analysis_level must be compatible with rule_type.
        //    L1 -> Declarative; L2/L3 -> Scripted or Compiled.
        match self.analysis_level {
            AnalysisLevel::L1 => {
                if self.rule_type != RuleType::Declarative {
                    return Err(RuleError::AnalysisLevelMismatch {
                        rule_id: self.id.clone(),
                        analysis_level: self.analysis_level,
                        rule_type: self.rule_type,
                    });
                }
            }
            AnalysisLevel::L2 | AnalysisLevel::L3 => {
                if self.rule_type == RuleType::Declarative {
                    return Err(RuleError::AnalysisLevelMismatch {
                        rule_id: self.id.clone(),
                        analysis_level: self.analysis_level,
                        rule_type: self.rule_type,
                    });
                }
            }
        }

        // 5. version must look like SemVer (major.minor.patch).
        if !is_valid_semver(&self.version) {
            return Err(RuleError::InvalidVersion {
                rule_id: self.id.clone(),
                version: self.version.clone(),
            });
        }

        Ok(())
    }
}

/// Deterministic ordering by `id`.
impl Ord for Rule {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for Rule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] ({}, {}, {})",
            self.id, self.severity, self.category, self.language, self.rule_type
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Basic SemVer validation: must match `MAJOR.MINOR.PATCH` where each part is
/// a non-negative integer. Pre-release and build metadata are not supported.
fn is_valid_semver(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.parse::<u64>().is_ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a valid declarative (L1) rule for testing.
    fn make_declarative_rule() -> Rule {
        Rule {
            id: "atlas/security/typescript/sql-injection".to_owned(),
            name: "SQL Injection Detection".to_owned(),
            description: "Detects potential SQL injection via string concatenation".to_owned(),
            severity: Severity::High,
            category: Category::Security,
            language: Language::TypeScript,
            analysis_level: AnalysisLevel::L1,
            rule_type: RuleType::Declarative,
            pattern: Some("(binary_expression left: (identifier) @source right: (template_string) @sink)".to_owned()),
            script: None,
            plugin: None,
            cwe_id: Some("CWE-89".to_owned()),
            remediation: "Use parameterized queries instead of string concatenation.".to_owned(),
            references: vec!["https://cwe.mitre.org/data/definitions/89.html".to_owned()],
            tags: vec!["sql".to_owned(), "injection".to_owned()],
            version: "1.0.0".to_owned(),
        }
    }

    /// Helper to create a valid scripted (L2) rule for testing.
    fn make_scripted_rule() -> Rule {
        Rule {
            id: "atlas/security/python/taint-flow".to_owned(),
            name: "Taint Flow Analysis".to_owned(),
            description: "Intra-procedural taint tracking for user inputs".to_owned(),
            severity: Severity::Critical,
            category: Category::Security,
            language: Language::Python,
            analysis_level: AnalysisLevel::L2,
            rule_type: RuleType::Scripted,
            pattern: None,
            script: Some("rules/python/taint_flow.rhai".to_owned()),
            plugin: None,
            cwe_id: Some("CWE-79".to_owned()),
            remediation: "Sanitize all user inputs before use.".to_owned(),
            references: vec![],
            tags: vec!["taint".to_owned(), "xss".to_owned()],
            version: "2.1.0".to_owned(),
        }
    }

    /// Helper to create a valid compiled (L3) rule for testing.
    fn make_compiled_rule() -> Rule {
        Rule {
            id: "atlas/security/java/inter-proc-taint".to_owned(),
            name: "Inter-procedural Taint Tracking".to_owned(),
            description: "Cross-method taint propagation analysis".to_owned(),
            severity: Severity::Critical,
            category: Category::Security,
            language: Language::Java,
            analysis_level: AnalysisLevel::L3,
            rule_type: RuleType::Compiled,
            pattern: None,
            script: None,
            plugin: Some("plugins/java/inter_proc_taint.so".to_owned()),
            cwe_id: None,
            remediation: "Review all call chains for taint propagation.".to_owned(),
            references: vec![],
            tags: vec![],
            version: "0.1.0".to_owned(),
        }
    }

    // -----------------------------------------------------------------------
    // Valid rule tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_declarative_rule_passes_validation() {
        let rule = make_declarative_rule();
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn valid_scripted_rule_passes_validation() {
        let rule = make_scripted_rule();
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn valid_compiled_rule_passes_validation() {
        let rule = make_compiled_rule();
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // InvalidRuleType: wrong count of pattern/script/plugin
    // -----------------------------------------------------------------------

    #[test]
    fn validation_fails_when_no_field_is_set() {
        let mut rule = make_declarative_rule();
        rule.pattern = None;
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidRuleType { set_count: 0, .. }),
            "expected InvalidRuleType with set_count=0, got: {err}"
        );
    }

    #[test]
    fn validation_fails_when_two_fields_are_set() {
        let mut rule = make_declarative_rule();
        rule.script = Some("extra.rhai".to_owned());
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidRuleType { set_count: 2, .. }),
            "expected InvalidRuleType with set_count=2, got: {err}"
        );
    }

    #[test]
    fn validation_fails_when_all_three_fields_are_set() {
        let mut rule = make_declarative_rule();
        rule.script = Some("extra.rhai".to_owned());
        rule.plugin = Some("extra.so".to_owned());
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidRuleType { set_count: 3, .. }),
            "expected InvalidRuleType with set_count=3, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // RuleTypeFieldMismatch
    // -----------------------------------------------------------------------

    #[test]
    fn validation_fails_declarative_with_script() {
        let mut rule = make_declarative_rule();
        rule.pattern = None;
        rule.script = Some("misplaced.rhai".to_owned());
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(
                err,
                RuleError::RuleTypeFieldMismatch {
                    rule_type: RuleType::Declarative,
                    ..
                }
            ),
            "expected RuleTypeFieldMismatch for Declarative, got: {err}"
        );
    }

    #[test]
    fn validation_fails_scripted_with_pattern() {
        let mut rule = make_scripted_rule();
        rule.script = None;
        rule.pattern = Some("(identifier)".to_owned());
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(
                err,
                RuleError::RuleTypeFieldMismatch {
                    rule_type: RuleType::Scripted,
                    ..
                }
            ),
            "expected RuleTypeFieldMismatch for Scripted, got: {err}"
        );
    }

    #[test]
    fn validation_fails_compiled_with_script() {
        let mut rule = make_compiled_rule();
        rule.plugin = None;
        rule.script = Some("misplaced.rhai".to_owned());
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(
                err,
                RuleError::RuleTypeFieldMismatch {
                    rule_type: RuleType::Compiled,
                    ..
                }
            ),
            "expected RuleTypeFieldMismatch for Compiled, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // AnalysisLevelMismatch
    // -----------------------------------------------------------------------

    #[test]
    fn validation_fails_l1_with_scripted() {
        let mut rule = make_scripted_rule();
        rule.analysis_level = AnalysisLevel::L1;
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::AnalysisLevelMismatch { .. }),
            "expected AnalysisLevelMismatch, got: {err}"
        );
    }

    #[test]
    fn validation_fails_l1_with_compiled() {
        let mut rule = make_compiled_rule();
        rule.analysis_level = AnalysisLevel::L1;
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::AnalysisLevelMismatch { .. }),
            "expected AnalysisLevelMismatch, got: {err}"
        );
    }

    #[test]
    fn validation_fails_l2_with_declarative() {
        let mut rule = make_declarative_rule();
        rule.analysis_level = AnalysisLevel::L2;
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::AnalysisLevelMismatch { .. }),
            "expected AnalysisLevelMismatch, got: {err}"
        );
    }

    #[test]
    fn validation_fails_l3_with_declarative() {
        let mut rule = make_declarative_rule();
        rule.analysis_level = AnalysisLevel::L3;
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::AnalysisLevelMismatch { .. }),
            "expected AnalysisLevelMismatch, got: {err}"
        );
    }

    #[test]
    fn l2_with_scripted_is_valid() {
        let rule = make_scripted_rule();
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn l3_with_compiled_is_valid() {
        let rule = make_compiled_rule();
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn l3_with_scripted_is_valid() {
        let mut rule = make_scripted_rule();
        rule.analysis_level = AnalysisLevel::L3;
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn l2_with_compiled_is_valid() {
        let mut rule = make_compiled_rule();
        rule.analysis_level = AnalysisLevel::L2;
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // EmptyId
    // -----------------------------------------------------------------------

    #[test]
    fn validation_fails_with_empty_id() {
        let mut rule = make_declarative_rule();
        rule.id = String::new();
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::EmptyId),
            "expected EmptyId, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // InvalidVersion
    // -----------------------------------------------------------------------

    #[test]
    fn validation_fails_with_bad_version() {
        let mut rule = make_declarative_rule();
        rule.version = "not-semver".to_owned();
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidVersion { .. }),
            "expected InvalidVersion, got: {err}"
        );
    }

    #[test]
    fn validation_fails_with_two_part_version() {
        let mut rule = make_declarative_rule();
        rule.version = "1.0".to_owned();
        let err = rule.validate().unwrap_err();
        assert!(
            matches!(err, RuleError::InvalidVersion { .. }),
            "expected InvalidVersion, got: {err}"
        );
    }

    #[test]
    fn validation_passes_with_zero_version() {
        let mut rule = make_declarative_rule();
        rule.version = "0.0.0".to_owned();
        assert!(rule.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // Ordering
    // -----------------------------------------------------------------------

    #[test]
    fn rules_are_ordered_by_id() {
        let mut rules = vec![
            make_compiled_rule(),   // "atlas/security/java/inter-proc-taint"
            make_declarative_rule(), // "atlas/security/typescript/sql-injection"
            make_scripted_rule(),   // "atlas/security/python/taint-flow"
        ];
        rules.sort();
        assert_eq!(rules[0].id, "atlas/security/java/inter-proc-taint");
        assert_eq!(rules[1].id, "atlas/security/python/taint-flow");
        assert_eq!(rules[2].id, "atlas/security/typescript/sql-injection");
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    #[test]
    fn rule_display_includes_key_fields() {
        let rule = make_declarative_rule();
        let display = rule.to_string();
        assert!(display.contains("atlas/security/typescript/sql-injection"));
        assert!(display.contains("high"));
        assert!(display.contains("security"));
        assert!(display.contains("TypeScript"));
        assert!(display.contains("Declarative"));
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn rule_json_roundtrip() {
        let rule = make_declarative_rule();
        let json = serde_json::to_string_pretty(&rule).unwrap();
        let deserialized: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn rule_json_skips_none_and_empty_fields() {
        let rule = make_compiled_rule();
        let json = serde_json::to_string(&rule).unwrap();
        // pattern and script should not appear since they are None.
        assert!(!json.contains("\"pattern\""));
        assert!(!json.contains("\"script\""));
        // cwe_id is None so should not appear.
        assert!(!json.contains("\"cwe_id\""));
        // references and tags are empty so should not appear.
        assert!(!json.contains("\"references\""));
        assert!(!json.contains("\"tags\""));
    }

    #[test]
    fn rule_yaml_roundtrip() {
        let rule = make_scripted_rule();
        let yaml = serde_yml::to_string(&rule).unwrap();
        let deserialized: Rule = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(rule, deserialized);
    }

    // -----------------------------------------------------------------------
    // Enum Display
    // -----------------------------------------------------------------------

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn category_display() {
        assert_eq!(Category::Security.to_string(), "security");
        assert_eq!(Category::Quality.to_string(), "quality");
        assert_eq!(Category::Secrets.to_string(), "secrets");
    }

    #[test]
    fn analysis_level_display() {
        assert_eq!(AnalysisLevel::L1.to_string(), "L1");
        assert_eq!(AnalysisLevel::L2.to_string(), "L2");
        assert_eq!(AnalysisLevel::L3.to_string(), "L3");
    }

    #[test]
    fn rule_type_display() {
        assert_eq!(RuleType::Declarative.to_string(), "Declarative");
        assert_eq!(RuleType::Scripted.to_string(), "Scripted");
        assert_eq!(RuleType::Compiled.to_string(), "Compiled");
    }

    #[test]
    fn language_display() {
        assert_eq!(Language::TypeScript.to_string(), "TypeScript");
        assert_eq!(Language::JavaScript.to_string(), "JavaScript");
        assert_eq!(Language::Java.to_string(), "Java");
        assert_eq!(Language::Python.to_string(), "Python");
        assert_eq!(Language::Go.to_string(), "Go");
        assert_eq!(Language::CSharp.to_string(), "CSharp");
    }

    // -----------------------------------------------------------------------
    // RuleError Display
    // -----------------------------------------------------------------------

    #[test]
    fn rule_error_display_messages() {
        let err = RuleError::InvalidRuleType {
            rule_id: "test".to_owned(),
            set_count: 0,
        };
        assert!(err.to_string().contains("exactly one of pattern/script/plugin"));

        let err = RuleError::AnalysisLevelMismatch {
            rule_id: "test".to_owned(),
            analysis_level: AnalysisLevel::L1,
            rule_type: RuleType::Scripted,
        };
        assert!(err.to_string().contains("analysis level mismatch"));

        let err = RuleError::RuleTypeFieldMismatch {
            rule_id: "test".to_owned(),
            rule_type: RuleType::Declarative,
            populated_field: "script".to_owned(),
        };
        assert!(err.to_string().contains("rule type / field mismatch"));

        let err = RuleError::EmptyId;
        assert!(err.to_string().contains("must not be empty"));

        let err = RuleError::InvalidVersion {
            rule_id: "test".to_owned(),
            version: "bad".to_owned(),
        };
        assert!(err.to_string().contains("invalid version"));
    }

    // -----------------------------------------------------------------------
    // is_valid_semver helper
    // -----------------------------------------------------------------------

    #[test]
    fn semver_validation() {
        assert!(is_valid_semver("0.0.0"));
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("12.34.56"));
        assert!(!is_valid_semver("1.0"));
        assert!(!is_valid_semver("1.0.0.0"));
        assert!(!is_valid_semver("a.b.c"));
        assert!(!is_valid_semver("1.0.0-alpha"));
        assert!(!is_valid_semver(""));
        assert!(!is_valid_semver("..."));
    }
}
