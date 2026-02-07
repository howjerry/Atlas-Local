//! Policy definition, YAML loading, validation, and multi-policy merge.
//!
//! A [`Policy`] defines the quality gate thresholds that determine whether a
//! scan passes, warns, or fails. Policies are hierarchical: Organization,
//! Team, Project, and Local levels merge together with more-specific levels
//! overriding less-specific ones on a per-field basis.

use std::path::Path;

use atlas_core::PolicyLevel;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when loading or validating a policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// An I/O error occurred while reading a policy file.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// The YAML content could not be parsed.
    #[error("parse error: {0}")]
    ParseError(#[from] serde_yml::Error),

    /// The policy failed semantic validation.
    #[error("validation error: {0}")]
    ValidationError(String),
}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/// Numeric thresholds for finding counts by severity.
///
/// Each field is optional; `None` means "no limit" for that severity.
/// During merge the most-specific non-`None` value wins.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Maximum number of critical findings allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<u32>,

    /// Maximum number of high findings allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high: Option<u32>,

    /// Maximum number of medium findings allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<u32>,

    /// Maximum number of low findings allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low: Option<u32>,

    /// Maximum number of informational findings allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<u32>,

    /// Maximum total finding count allowed (across all severities).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
}

impl Thresholds {
    /// Merge two threshold sets. For each field, `other` (more specific)
    /// wins when it has a value; otherwise the value from `self` is kept.
    #[must_use]
    pub fn merge(&self, other: &Thresholds) -> Thresholds {
        Thresholds {
            critical: other.critical.or(self.critical),
            high: other.high.or(self.high),
            medium: other.medium.or(self.medium),
            low: other.low.or(self.low),
            info: other.info.or(self.info),
            total: other.total.or(self.total),
        }
    }
}

// ---------------------------------------------------------------------------
// CategoryOverrides
// ---------------------------------------------------------------------------

/// Per-category threshold overrides.
///
/// When present, findings in a given category are evaluated against these
/// thresholds instead of the top-level `fail_on` / `warn_on`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryOverrides {
    /// Overrides for the security category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Thresholds>,

    /// Overrides for the quality category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<Thresholds>,

    /// Overrides for the secrets category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Thresholds>,
}

impl CategoryOverrides {
    /// Deep-merge two `CategoryOverrides`. For each category, threshold
    /// fields from `other` (more specific) win when present.
    #[must_use]
    pub fn merge(&self, other: &CategoryOverrides) -> CategoryOverrides {
        CategoryOverrides {
            security: merge_optional_thresholds(&self.security, &other.security),
            quality: merge_optional_thresholds(&self.quality, &other.quality),
            secrets: merge_optional_thresholds(&self.secrets, &other.secrets),
        }
    }
}

/// Helper: merge two `Option<Thresholds>`.
fn merge_optional_thresholds(
    base: &Option<Thresholds>,
    overlay: &Option<Thresholds>,
) -> Option<Thresholds> {
    match (base, overlay) {
        (Some(b), Some(o)) => Some(b.merge(o)),
        (None, Some(o)) => Some(o.clone()),
        (Some(b), None) => Some(b.clone()),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A quality-gate policy that defines thresholds for scan findings.
///
/// Policies are loaded from YAML files and can be merged across hierarchy
/// levels (Organization -> Team -> Project -> Local).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version (must be `"1.0.0"`).
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Human-readable policy name.
    pub name: String,

    /// Hierarchy level at which this policy is defined.
    #[serde(default = "default_level")]
    pub level: PolicyLevel,

    /// Thresholds that cause the gate to FAIL.
    pub fail_on: Thresholds,

    /// Thresholds that cause the gate to WARN (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_on: Option<Thresholds>,

    /// Category-specific threshold overrides (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_overrides: Option<CategoryOverrides>,

    /// Path to a baseline file for delta evaluation (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,

    /// Rules to exclude from evaluation (unioned during merge).
    #[serde(default)]
    pub exclude_rules: Vec<String>,

    /// Rules to explicitly include in evaluation (unioned during merge).
    #[serde(default)]
    pub include_rules: Vec<String>,
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

fn default_level() -> PolicyLevel {
    PolicyLevel::Local
}

// ---------------------------------------------------------------------------
// Default policy
// ---------------------------------------------------------------------------

/// Returns the default policy applied when no `--policy` flag is provided.
///
/// The default policy fails on any critical-severity findings (threshold of 0),
/// meaning the gate will fail if even one critical finding is detected.
#[must_use]
pub fn default_policy() -> Policy {
    Policy {
        schema_version: "1.0.0".to_string(),
        name: "atlas-default".to_string(),
        level: PolicyLevel::Local,
        fail_on: Thresholds {
            critical: Some(0),
            ..Thresholds::default()
        },
        warn_on: None,
        category_overrides: None,
        baseline: None,
        exclude_rules: Vec::new(),
        include_rules: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Loading and validation
// ---------------------------------------------------------------------------

/// Load a [`Policy`] from a YAML file on disk.
///
/// # Errors
///
/// Returns [`PolicyError::IoError`] if the file cannot be read,
/// [`PolicyError::ParseError`] if the YAML is malformed, or
/// [`PolicyError::ValidationError`] if semantic validation fails.
pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    let content = std::fs::read_to_string(path)?;
    load_policy_from_str(&content)
}

/// Parse a [`Policy`] from a YAML string.
///
/// # Errors
///
/// Returns [`PolicyError::ParseError`] if the YAML is malformed, or
/// [`PolicyError::ValidationError`] if semantic validation fails.
pub fn load_policy_from_str(yaml: &str) -> Result<Policy, PolicyError> {
    let policy: Policy = serde_yml::from_str(yaml)?;
    validate_policy(&policy)?;
    Ok(policy)
}

/// Validate semantic invariants on a parsed policy.
fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    if policy.schema_version != "1.0.0" {
        return Err(PolicyError::ValidationError(format!(
            "unsupported schema_version '{}', expected '1.0.0'",
            policy.schema_version,
        )));
    }

    if policy.name.trim().is_empty() {
        return Err(PolicyError::ValidationError(
            "policy name must not be empty".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-policy merge
// ---------------------------------------------------------------------------

/// Merge multiple policies by specificity precedence.
///
/// Policies are sorted from least specific (`Organization`) to most specific
/// (`Local`), then merged left-to-right so that more-specific values override
/// less-specific ones.
///
/// - **Scalar fields** (`name`, `level`, `baseline`): most specific wins.
/// - **Threshold fields** (`fail_on`, `warn_on`): per-field most specific
///   non-`None` value wins.
/// - **Category overrides**: deep merge (per-category, per-threshold-field).
/// - **Rule lists** (`exclude_rules`, `include_rules`): unioned with no
///   duplicates.
///
/// # Panics
///
/// Panics if `policies` is empty.
#[must_use]
pub fn merge_policies(policies: &[Policy]) -> Policy {
    assert!(
        !policies.is_empty(),
        "merge_policies requires at least one policy"
    );

    // Sort by specificity (ascending: Organization=0 .. Local=3).
    let mut sorted: Vec<&Policy> = policies.iter().collect();
    sorted.sort_by_key(|p| p.level.specificity());

    let mut merged = sorted[0].clone();

    for policy in &sorted[1..] {
        // Scalar: most specific wins unconditionally.
        merged.name = policy.name.clone();
        merged.level = policy.level;
        merged.schema_version = policy.schema_version.clone();

        // Threshold merge: per-field override.
        merged.fail_on = merged.fail_on.merge(&policy.fail_on);
        merged.warn_on = merge_optional_thresholds(&merged.warn_on, &policy.warn_on);

        // Category overrides: deep merge.
        merged.category_overrides = match (&merged.category_overrides, &policy.category_overrides) {
            (Some(base), Some(overlay)) => Some(base.merge(overlay)),
            (None, Some(overlay)) => Some(overlay.clone()),
            (existing, None) => existing.clone(),
        };

        // Baseline: most specific non-None wins.
        if policy.baseline.is_some() {
            merged.baseline = policy.baseline.clone();
        }

        // Rule lists: union (no duplicates).
        for rule in &policy.exclude_rules {
            if !merged.exclude_rules.contains(rule) {
                merged.exclude_rules.push(rule.clone());
            }
        }
        for rule in &policy.include_rules {
            if !merged.include_rules.contains(rule) {
                merged.include_rules.push(rule.clone());
            }
        }
    }

    merged
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    // -- T030: struct defaults -------------------------------------------------

    #[test]
    fn thresholds_default_all_none() {
        let t = Thresholds::default();
        assert_eq!(t.critical, None);
        assert_eq!(t.high, None);
        assert_eq!(t.medium, None);
        assert_eq!(t.low, None);
        assert_eq!(t.info, None);
        assert_eq!(t.total, None);
    }

    #[test]
    fn category_overrides_default_all_none() {
        let co = CategoryOverrides::default();
        assert_eq!(co.security, None);
        assert_eq!(co.quality, None);
        assert_eq!(co.secrets, None);
    }

    // -- T031: YAML deserialization --------------------------------------------

    fn minimal_yaml() -> &'static str {
        r#"
schema_version: "1.0.0"
name: test-policy
fail_on:
  critical: 0
"#
    }

    #[test]
    fn load_minimal_policy_from_str() {
        let policy = load_policy_from_str(minimal_yaml()).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.schema_version, "1.0.0");
        assert_eq!(policy.level, PolicyLevel::Local); // default
        assert_eq!(policy.fail_on.critical, Some(0));
        assert_eq!(policy.fail_on.high, None);
        assert_eq!(policy.warn_on, None);
        assert_eq!(policy.category_overrides, None);
        assert_eq!(policy.baseline, None);
        assert!(policy.exclude_rules.is_empty());
        assert!(policy.include_rules.is_empty());
    }

    #[test]
    fn load_full_policy_from_str() {
        let yaml = r#"
schema_version: "1.0.0"
name: full-policy
level: Organization
fail_on:
  critical: 0
  high: 3
  medium: 10
  low: 50
  info: 100
  total: 200
warn_on:
  critical: 0
  high: 1
category_overrides:
  security:
    critical: 0
    high: 0
  quality:
    medium: 20
  secrets:
    critical: 0
baseline: ".atlas-baseline.json"
exclude_rules:
  - "RULE-001"
  - "RULE-002"
include_rules:
  - "RULE-100"
"#;
        let policy = load_policy_from_str(yaml).unwrap();
        assert_eq!(policy.name, "full-policy");
        assert_eq!(policy.level, PolicyLevel::Organization);
        assert_eq!(policy.fail_on.critical, Some(0));
        assert_eq!(policy.fail_on.high, Some(3));
        assert_eq!(policy.fail_on.medium, Some(10));
        assert_eq!(policy.fail_on.low, Some(50));
        assert_eq!(policy.fail_on.info, Some(100));
        assert_eq!(policy.fail_on.total, Some(200));
        let warn = policy.warn_on.as_ref().unwrap();
        assert_eq!(warn.critical, Some(0));
        assert_eq!(warn.high, Some(1));
        assert_eq!(warn.medium, None);
        let co = policy.category_overrides.as_ref().unwrap();
        let sec = co.security.as_ref().unwrap();
        assert_eq!(sec.critical, Some(0));
        assert_eq!(sec.high, Some(0));
        let qual = co.quality.as_ref().unwrap();
        assert_eq!(qual.medium, Some(20));
        let secrets = co.secrets.as_ref().unwrap();
        assert_eq!(secrets.critical, Some(0));
        assert_eq!(policy.baseline, Some(".atlas-baseline.json".to_string()));
        assert_eq!(policy.exclude_rules, vec!["RULE-001", "RULE-002"]);
        assert_eq!(policy.include_rules, vec!["RULE-100"]);
    }

    #[test]
    fn load_policy_from_file() {
        let yaml = minimal_yaml();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        file.flush().unwrap();

        let policy = load_policy(file.path()).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.fail_on.critical, Some(0));
    }

    // -- T031: validation errors -----------------------------------------------

    #[test]
    fn validation_rejects_bad_schema_version() {
        let yaml = r#"
schema_version: "2.0.0"
name: bad-version
fail_on:
  critical: 0
"#;
        let err = load_policy_from_str(yaml).unwrap_err();
        match err {
            PolicyError::ValidationError(msg) => {
                assert!(msg.contains("unsupported schema_version"));
                assert!(msg.contains("2.0.0"));
            }
            other => panic!("expected ValidationError, got: {other}"),
        }
    }

    #[test]
    fn validation_rejects_empty_name() {
        let yaml = r#"
schema_version: "1.0.0"
name: ""
fail_on:
  critical: 0
"#;
        let err = load_policy_from_str(yaml).unwrap_err();
        match err {
            PolicyError::ValidationError(msg) => {
                assert!(msg.contains("name must not be empty"));
            }
            other => panic!("expected ValidationError, got: {other}"),
        }
    }

    #[test]
    fn validation_rejects_whitespace_only_name() {
        let yaml = r#"
schema_version: "1.0.0"
name: "   "
fail_on:
  critical: 0
"#;
        let err = load_policy_from_str(yaml).unwrap_err();
        match err {
            PolicyError::ValidationError(msg) => {
                assert!(msg.contains("name must not be empty"));
            }
            other => panic!("expected ValidationError, got: {other}"),
        }
    }

    #[test]
    fn parse_error_on_invalid_yaml() {
        let yaml = "this is: [not: valid: yaml: {{{}}}";
        let err = load_policy_from_str(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::ParseError(_)));
    }

    #[test]
    fn io_error_on_missing_file() {
        let err = load_policy(Path::new("/nonexistent/policy.yaml")).unwrap_err();
        assert!(matches!(err, PolicyError::IoError(_)));
    }

    // -- T031: default values --------------------------------------------------

    #[test]
    fn default_schema_version_applied() {
        // schema_version omitted -- should default to "1.0.0"
        let yaml = r#"
name: no-schema
fail_on:
  critical: 0
"#;
        let policy = load_policy_from_str(yaml).unwrap();
        assert_eq!(policy.schema_version, "1.0.0");
    }

    #[test]
    fn default_level_is_local() {
        let policy = load_policy_from_str(minimal_yaml()).unwrap();
        assert_eq!(policy.level, PolicyLevel::Local);
    }

    // -- T032: merge -----------------------------------------------------------

    #[test]
    fn merge_single_policy_returns_clone() {
        let policy = load_policy_from_str(minimal_yaml()).unwrap();
        let merged = merge_policies(std::slice::from_ref(&policy));
        assert_eq!(merged, policy);
    }

    #[test]
    fn merge_specificity_precedence() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org-policy
level: Organization
fail_on:
  critical: 5
  high: 10
"#,
        )
        .unwrap();

        let local = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: local-policy
level: Local
fail_on:
  critical: 0
"#,
        )
        .unwrap();

        let merged = merge_policies(&[local.clone(), org.clone()]);

        // Name and level come from most specific (Local).
        assert_eq!(merged.name, "local-policy");
        assert_eq!(merged.level, PolicyLevel::Local);

        // critical: Local overrides with 0.
        assert_eq!(merged.fail_on.critical, Some(0));
        // high: Organization provides 10; Local has None, so org value survives.
        assert_eq!(merged.fail_on.high, Some(10));
    }

    #[test]
    fn merge_threshold_field_level() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org
level: Organization
fail_on:
  critical: 5
  high: 10
  medium: 20
  low: 50
  info: 100
  total: 200
"#,
        )
        .unwrap();

        let project = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: project
level: Project
fail_on:
  critical: 0
  high: 5
"#,
        )
        .unwrap();

        let merged = merge_policies(&[org, project]);

        assert_eq!(merged.fail_on.critical, Some(0));
        assert_eq!(merged.fail_on.high, Some(5));
        assert_eq!(merged.fail_on.medium, Some(20));
        assert_eq!(merged.fail_on.low, Some(50));
        assert_eq!(merged.fail_on.info, Some(100));
        assert_eq!(merged.fail_on.total, Some(200));
    }

    #[test]
    fn merge_exclude_include_rules_union() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org
level: Organization
fail_on:
  critical: 0
exclude_rules:
  - "RULE-001"
  - "RULE-002"
include_rules:
  - "RULE-100"
"#,
        )
        .unwrap();

        let local = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: local
level: Local
fail_on:
  critical: 0
exclude_rules:
  - "RULE-002"
  - "RULE-003"
include_rules:
  - "RULE-100"
  - "RULE-200"
"#,
        )
        .unwrap();

        let merged = merge_policies(&[org, local]);

        // Union with no duplicates.
        assert_eq!(merged.exclude_rules.len(), 3);
        assert!(merged.exclude_rules.contains(&"RULE-001".to_string()));
        assert!(merged.exclude_rules.contains(&"RULE-002".to_string()));
        assert!(merged.exclude_rules.contains(&"RULE-003".to_string()));

        assert_eq!(merged.include_rules.len(), 2);
        assert!(merged.include_rules.contains(&"RULE-100".to_string()));
        assert!(merged.include_rules.contains(&"RULE-200".to_string()));
    }

    #[test]
    fn merge_baseline_most_specific_wins() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org
level: Organization
fail_on:
  critical: 0
baseline: "org-baseline.json"
"#,
        )
        .unwrap();

        let project = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: project
level: Project
fail_on:
  critical: 0
baseline: "project-baseline.json"
"#,
        )
        .unwrap();

        let local_no_baseline = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: local
level: Local
fail_on:
  critical: 0
"#,
        )
        .unwrap();

        let merged = merge_policies(&[org, project, local_no_baseline]);

        // Project has baseline, Local does not, so project's baseline survives.
        assert_eq!(merged.baseline, Some("project-baseline.json".to_string()));
    }

    #[test]
    fn merge_category_overrides_deep() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org
level: Organization
fail_on:
  critical: 0
category_overrides:
  security:
    critical: 0
    high: 5
  quality:
    medium: 30
"#,
        )
        .unwrap();

        let project = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: project
level: Project
fail_on:
  critical: 0
category_overrides:
  security:
    high: 2
  secrets:
    critical: 0
"#,
        )
        .unwrap();

        let merged = merge_policies(&[org, project]);
        let co = merged.category_overrides.as_ref().unwrap();

        // security: critical from org (0), high overridden by project (2).
        let sec = co.security.as_ref().unwrap();
        assert_eq!(sec.critical, Some(0));
        assert_eq!(sec.high, Some(2));

        // quality: untouched from org.
        let qual = co.quality.as_ref().unwrap();
        assert_eq!(qual.medium, Some(30));

        // secrets: new from project.
        let secrets = co.secrets.as_ref().unwrap();
        assert_eq!(secrets.critical, Some(0));
    }

    #[test]
    fn merge_warn_on_field_level() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org
level: Organization
fail_on:
  critical: 0
warn_on:
  critical: 0
  high: 5
"#,
        )
        .unwrap();

        let local = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: local
level: Local
fail_on:
  critical: 0
warn_on:
  high: 2
  medium: 10
"#,
        )
        .unwrap();

        let merged = merge_policies(&[org, local]);
        let warn = merged.warn_on.as_ref().unwrap();
        // critical: org has 0, local has None -> org value kept.
        assert_eq!(warn.critical, Some(0));
        // high: local overrides to 2.
        assert_eq!(warn.high, Some(2));
        // medium: new from local.
        assert_eq!(warn.medium, Some(10));
    }

    // -- T036: default policy --------------------------------------------------

    #[test]
    fn default_policy_fails_on_critical() {
        let policy = super::default_policy();
        assert_eq!(policy.name, "atlas-default");
        assert_eq!(policy.schema_version, "1.0.0");
        assert_eq!(policy.level, PolicyLevel::Local);
        assert_eq!(policy.fail_on.critical, Some(0));
        assert_eq!(policy.fail_on.high, None);
        assert_eq!(policy.fail_on.medium, None);
        assert_eq!(policy.fail_on.low, None);
        assert_eq!(policy.fail_on.info, None);
        assert_eq!(policy.fail_on.total, None);
        assert!(policy.warn_on.is_none());
        assert!(policy.category_overrides.is_none());
        assert!(policy.exclude_rules.is_empty());
        assert!(policy.include_rules.is_empty());
    }

    #[test]
    fn thresholds_merge_overlay_wins() {
        let base = Thresholds {
            critical: Some(5),
            high: Some(10),
            medium: None,
            low: None,
            info: None,
            total: Some(100),
        };
        let overlay = Thresholds {
            critical: Some(0),
            high: None,
            medium: Some(20),
            low: None,
            info: None,
            total: None,
        };
        let merged = base.merge(&overlay);
        assert_eq!(merged.critical, Some(0)); // overlay wins
        assert_eq!(merged.high, Some(10)); // base kept
        assert_eq!(merged.medium, Some(20)); // overlay provides
        assert_eq!(merged.low, None); // both None
        assert_eq!(merged.info, None);
        assert_eq!(merged.total, Some(100)); // base kept
    }

    #[test]
    fn policy_serde_roundtrip_yaml() {
        let yaml = r#"
schema_version: "1.0.0"
name: roundtrip
level: Team
fail_on:
  critical: 0
  high: 3
warn_on:
  critical: 0
exclude_rules:
  - "RULE-X"
include_rules:
  - "RULE-Y"
"#;
        let policy = load_policy_from_str(yaml).unwrap();
        let serialized = serde_yml::to_string(&policy).unwrap();
        let deserialized: Policy = serde_yml::from_str(&serialized).unwrap();
        assert_eq!(policy, deserialized);
    }

    #[test]
    fn merge_three_levels() {
        let org = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: org
level: Organization
fail_on:
  critical: 10
  high: 20
  medium: 30
baseline: "org-baseline.json"
exclude_rules:
  - "RULE-A"
"#,
        )
        .unwrap();

        let team = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: team
level: Team
fail_on:
  critical: 5
  high: 15
exclude_rules:
  - "RULE-B"
"#,
        )
        .unwrap();

        let local = load_policy_from_str(
            r#"
schema_version: "1.0.0"
name: local
level: Local
fail_on:
  critical: 0
baseline: "local-baseline.json"
exclude_rules:
  - "RULE-A"
  - "RULE-C"
"#,
        )
        .unwrap();

        let merged = merge_policies(&[local, org, team]);

        assert_eq!(merged.name, "local");
        assert_eq!(merged.level, PolicyLevel::Local);
        assert_eq!(merged.fail_on.critical, Some(0)); // local
        assert_eq!(merged.fail_on.high, Some(15)); // team
        assert_eq!(merged.fail_on.medium, Some(30)); // org
        assert_eq!(merged.baseline, Some("local-baseline.json".to_string()));

        assert_eq!(merged.exclude_rules.len(), 3);
        assert!(merged.exclude_rules.contains(&"RULE-A".to_string()));
        assert!(merged.exclude_rules.contains(&"RULE-B".to_string()));
        assert!(merged.exclude_rules.contains(&"RULE-C".to_string()));
    }
}
