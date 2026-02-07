//! Atlas Findings JSON v1.0.0 report formatter.
//!
//! Produces a deterministic JSON report containing scan metadata, findings,
//! summary counts, and gate results. The output schema is versioned at `1.0.0`
//! and designed for machine consumption by CI/CD pipelines, dashboards, and
//! downstream tooling.
//!
//! # Determinism guarantees
//!
//! - Findings arrive pre-sorted by `(file_path, start_line, start_col, rule_id)`.
//! - The `Finding.metadata` field uses `BTreeMap` for stable key ordering.
//! - Timestamps are disabled by default (`include_timestamp = false`).
//! - The scan ID is a SHA-256 digest of `(target_path, engine_version, config_hash, rules_version)`.
//! - Optional fields are omitted via `skip_serializing_if` when unset or zero.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use atlas_analysis::Finding;
use atlas_core::config::AtlasConfig;
use atlas_core::engine::ScanResult;
use atlas_rules::{Rule, Severity};

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current schema version for the Atlas Findings JSON format.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Engine version extracted from this crate's Cargo.toml.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Report structs
// ---------------------------------------------------------------------------

/// Top-level Atlas Findings JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasReport {
    /// Schema version identifier (always `"1.0.0"`).
    pub schema_version: String,

    /// Metadata about the scan that produced this report.
    pub scan: ScanMetadata,

    /// All findings produced by the scan, in deterministic order.
    pub findings: Vec<Finding>,

    /// Summary counts by severity level.
    pub findings_count: FindingsSummary,

    /// Overall gate result.
    pub gate_result: GateResultReport,

    /// Detailed gate evaluation breakdown (reserved for future use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_details: Option<GateDetails>,

    /// Baseline diff results (reserved for future use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_diff: Option<BaselineDiff>,

    /// Scan performance statistics (reserved for future use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<ScanStats>,
}

/// Metadata describing the scan environment and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Deterministic scan ID (SHA-256 hex digest).
    pub id: String,

    /// ISO 8601 timestamp of when the scan was performed.
    /// Omitted by default for deterministic output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    /// Version of the Atlas engine that performed the scan.
    pub engine_version: String,

    /// Absolute path to the scan target directory.
    pub target_path: String,

    /// Number of source files successfully scanned.
    pub files_scanned: u32,

    /// Number of source files skipped due to errors or filters.
    #[serde(skip_serializing_if = "is_zero")]
    pub files_skipped: Option<u32>,

    /// Lowercase names of programming languages detected.
    pub languages_detected: Vec<String>,

    /// SHA-256 hash of sorted rule IDs and versions.
    pub rules_version: String,

    /// SHA-256 hash of serialized configuration.
    pub config_hash: String,

    /// Name of the policy applied during this scan, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_applied: Option<String>,

    /// Path to the baseline file applied, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_applied: Option<String>,
}

/// Summary counts of findings by severity level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingsSummary {
    /// Number of critical-severity findings.
    pub critical: u32,
    /// Number of high-severity findings.
    pub high: u32,
    /// Number of medium-severity findings.
    pub medium: u32,
    /// Number of low-severity findings.
    pub low: u32,
    /// Number of informational findings.
    pub info: u32,
    /// Total number of findings across all severity levels.
    pub total: u32,
}

/// Gate evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResultReport {
    /// Gate status: `"PASS"`, `"FAIL"`, or `"WARN"`.
    pub status: String,
}

/// Gate evaluation details showing which thresholds were breached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDetails {
    /// All thresholds that were breached during evaluation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub breached_thresholds: Vec<GateBreachedThreshold>,
}

/// A single threshold breach in the gate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateBreachedThreshold {
    /// The severity level or `"total"`.
    pub severity: String,
    /// Optional category for category-specific overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The configured maximum-allowed count.
    pub threshold: u32,
    /// The actual count of findings.
    pub actual: u32,
    /// `"fail"` or `"warn"`.
    pub level: String,
}

/// Baseline diff results showing new, baselined, and resolved findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    /// Number of new findings (not in baseline).
    pub new_count: u32,
    /// Number of baselined findings (already in baseline, excluded from gate).
    pub baselined_count: u32,
    /// Number of resolved findings (in baseline but no longer detected).
    pub resolved_count: u32,
}

/// Placeholder for future scan performance statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {}

// ---------------------------------------------------------------------------
// Helper: skip_serializing_if predicate
// ---------------------------------------------------------------------------

/// Returns `true` if the optional `u32` is `None` or `Some(0)`.
fn is_zero(val: &Option<u32>) -> bool {
    matches!(val, None | Some(0))
}

// ---------------------------------------------------------------------------
// Deterministic computation functions
// ---------------------------------------------------------------------------

/// Computes a deterministic scan ID as a SHA-256 hex digest.
///
/// The ID is derived from the combination of:
/// - `target_path` -- the absolute path being scanned
/// - `engine_version` -- the Atlas engine version
/// - `config_hash` -- hash of the effective configuration
/// - `rules_version` -- hash of the rule set
///
/// Same inputs always produce the same scan ID.
#[must_use]
pub fn compute_scan_id(
    target_path: &str,
    engine_version: &str,
    config_hash: &str,
    rules_version: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target_path.as_bytes());
    hasher.update(engine_version.as_bytes());
    hasher.update(config_hash.as_bytes());
    hasher.update(rules_version.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes a deterministic rules version hash.
///
/// Sorts rules by ID, then hashes the concatenation of `id:version` pairs.
/// This ensures the hash is stable regardless of the order rules were loaded.
#[must_use]
pub fn compute_rules_version(rules: &[Rule]) -> String {
    let mut hasher = Sha256::new();
    // Collect and sort to ensure deterministic ordering.
    let mut sorted_keys: BTreeSet<(&str, &str)> = BTreeSet::new();
    for rule in rules {
        sorted_keys.insert((&rule.id, &rule.version));
    }
    for (id, version) in &sorted_keys {
        hasher.update(id.as_bytes());
        hasher.update(b":");
        hasher.update(version.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Computes a deterministic configuration hash.
///
/// Serializes the configuration to JSON (which uses deterministic key ordering
/// for `BTreeMap` fields) and hashes the result.
#[must_use]
pub fn compute_config_hash(config: &AtlasConfig) -> String {
    let mut hasher = Sha256::new();
    // serde_json serialization is deterministic for structs.
    let json = serde_json::to_string(config).unwrap_or_default();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes a summary of findings counts by severity level.
#[must_use]
pub fn compute_findings_summary(findings: &[Finding]) -> FindingsSummary {
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut info = 0u32;

    for finding in findings {
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    let total = critical + high + medium + low + info;

    FindingsSummary {
        critical,
        high,
        medium,
        low,
        info,
        total,
    }
}

/// Options for report generation that extend beyond the core scan result.
#[derive(Debug, Default)]
pub struct ReportOptions<'a> {
    /// Include an ISO 8601 timestamp in the report.
    pub include_timestamp: bool,
    /// Gate result status (defaults to "PASS" if not provided).
    pub gate_status: Option<&'a str>,
    /// Gate evaluation details (breached thresholds).
    pub gate_details: Option<GateDetails>,
    /// Name of the policy applied during this scan.
    pub policy_name: Option<&'a str>,
    /// Path to the baseline file applied, if any.
    pub baseline_applied: Option<&'a str>,
    /// Baseline diff results, if a baseline was used.
    pub baseline_diff: Option<BaselineDiff>,
}

/// Formats a complete Atlas Findings JSON v1.0.0 report.
///
/// # Arguments
///
/// - `scan_result` -- the scan pipeline result containing findings and statistics.
/// - `target_path` -- the absolute path to the scanned directory.
/// - `rules` -- the rules that were evaluated during the scan.
/// - `config` -- the effective configuration used for the scan.
/// - `include_timestamp` -- whether to include an ISO 8601 timestamp.
///
/// # Returns
///
/// A pretty-printed JSON string representing the full report.
///
/// # Determinism
///
/// When `include_timestamp` is `false`, calling this function with identical
/// inputs will always produce byte-identical output.
#[must_use]
pub fn format_report(
    scan_result: &ScanResult,
    target_path: &str,
    rules: &[Rule],
    config: &AtlasConfig,
    include_timestamp: bool,
) -> String {
    format_report_with_options(
        scan_result,
        target_path,
        rules,
        config,
        &ReportOptions {
            include_timestamp,
            ..Default::default()
        },
    )
}

/// Formats a complete Atlas Findings JSON v1.0.0 report with extended options.
///
/// This is the full version of [`format_report`] that accepts gate evaluation
/// results and policy metadata.
#[must_use]
pub fn format_report_with_options(
    scan_result: &ScanResult,
    target_path: &str,
    rules: &[Rule],
    config: &AtlasConfig,
    options: &ReportOptions<'_>,
) -> String {
    let rules_version = compute_rules_version(rules);
    let config_hash = compute_config_hash(config);
    let engine_version = ENGINE_VERSION.to_string();
    let scan_id = compute_scan_id(target_path, &engine_version, &config_hash, &rules_version);

    let timestamp = if options.include_timestamp {
        Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    } else {
        None
    };

    let languages_detected: Vec<String> = scan_result
        .languages_detected
        .iter()
        .map(|lang| lang.to_string().to_lowercase())
        .collect();

    let files_skipped = if scan_result.files_skipped > 0 {
        Some(scan_result.files_skipped)
    } else {
        None
    };

    let findings_count = compute_findings_summary(&scan_result.findings);

    let scan = ScanMetadata {
        id: scan_id,
        timestamp,
        engine_version,
        target_path: target_path.to_string(),
        files_scanned: scan_result.files_scanned,
        files_skipped,
        languages_detected,
        rules_version,
        config_hash,
        policy_applied: options.policy_name.map(String::from),
        baseline_applied: options.baseline_applied.map(String::from),
    };

    let gate_result = GateResultReport {
        status: options.gate_status.unwrap_or("PASS").to_string(),
    };

    let report = AtlasReport {
        schema_version: SCHEMA_VERSION.to_string(),
        scan,
        findings: scan_result.findings.clone(),
        findings_count,
        gate_result,
        gate_details: options.gate_details.clone(),
        baseline_diff: options.baseline_diff.clone(),
        stats: None,
    };

    serde_json::to_string_pretty(&report).expect("report serialization must not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use atlas_analysis::{FindingBuilder, LineRange};
    use atlas_core::Language;
    use atlas_core::config::AtlasConfig;
    use atlas_core::engine::ScanResult;
    use atlas_rules::{AnalysisLevel, Category, Confidence, Rule, RuleType, Severity};

    // -- Test helpers ---------------------------------------------------------

    /// Creates a minimal declarative rule for testing.
    fn make_rule(id: &str, version: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("Test Rule {id}"),
            description: "A test rule".to_string(),
            severity: atlas_rules::Severity::High,
            category: Category::Security,
            language: atlas_rules::Language::TypeScript,
            analysis_level: AnalysisLevel::L1,
            rule_type: RuleType::Declarative,
            pattern: Some("(identifier) @id".to_string()),
            script: None,
            plugin: None,
            cwe_id: Some("CWE-89".to_string()),
            remediation: "Fix it.".to_string(),
            references: vec![],
            tags: vec![],
            version: version.to_string(),
        }
    }

    /// Creates a sample Finding with the given severity.
    fn make_finding(severity: Severity, rule_id: &str) -> Finding {
        FindingBuilder::new()
            .rule_id(rule_id)
            .severity(severity)
            .category(Category::Security)
            .cwe_id("CWE-89")
            .file_path("src/app.ts")
            .line_range(LineRange::new(10, 1, 12, 30).unwrap())
            .snippet("const q = sql + input;")
            .description("SQL injection risk")
            .remediation("Use parameterized queries.")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap()
    }

    /// Creates a ScanResult with the given findings.
    fn make_scan_result(findings: Vec<Finding>) -> ScanResult {
        let summary = atlas_core::engine::FindingsSummary::from_findings(&findings);
        ScanResult {
            findings,
            files_scanned: 5,
            files_skipped: 1,
            languages_detected: vec![Language::TypeScript, Language::JavaScript],
            summary,
            stats: atlas_core::engine::ScanStats::default(),
        }
    }

    // -- Scan ID tests --------------------------------------------------------

    #[test]
    fn scan_id_is_deterministic() {
        let id1 = compute_scan_id("/project/src", "0.1.0", "confighash", "ruleshash");
        let id2 = compute_scan_id("/project/src", "0.1.0", "confighash", "ruleshash");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn scan_id_changes_with_target_path() {
        let id1 = compute_scan_id("/project/a", "0.1.0", "cfg", "rules");
        let id2 = compute_scan_id("/project/b", "0.1.0", "cfg", "rules");
        assert_ne!(id1, id2);
    }

    #[test]
    fn scan_id_changes_with_engine_version() {
        let id1 = compute_scan_id("/project", "0.1.0", "cfg", "rules");
        let id2 = compute_scan_id("/project", "0.2.0", "cfg", "rules");
        assert_ne!(id1, id2);
    }

    #[test]
    fn scan_id_changes_with_config_hash() {
        let id1 = compute_scan_id("/project", "0.1.0", "cfg-a", "rules");
        let id2 = compute_scan_id("/project", "0.1.0", "cfg-b", "rules");
        assert_ne!(id1, id2);
    }

    #[test]
    fn scan_id_changes_with_rules_version() {
        let id1 = compute_scan_id("/project", "0.1.0", "cfg", "rules-a");
        let id2 = compute_scan_id("/project", "0.1.0", "cfg", "rules-b");
        assert_ne!(id1, id2);
    }

    // -- Rules version tests --------------------------------------------------

    #[test]
    fn rules_version_is_deterministic() {
        let rules = vec![
            make_rule("atlas/security/ts/xss", "1.0.0"),
            make_rule("atlas/security/ts/sqli", "2.0.0"),
        ];
        let v1 = compute_rules_version(&rules);
        let v2 = compute_rules_version(&rules);
        assert_eq!(v1, v2);
    }

    #[test]
    fn rules_version_order_independent() {
        let rules_a = vec![
            make_rule("atlas/security/ts/xss", "1.0.0"),
            make_rule("atlas/security/ts/sqli", "2.0.0"),
        ];
        let rules_b = vec![
            make_rule("atlas/security/ts/sqli", "2.0.0"),
            make_rule("atlas/security/ts/xss", "1.0.0"),
        ];
        assert_eq!(
            compute_rules_version(&rules_a),
            compute_rules_version(&rules_b)
        );
    }

    #[test]
    fn rules_version_changes_with_version() {
        let rules_a = vec![make_rule("atlas/test", "1.0.0")];
        let rules_b = vec![make_rule("atlas/test", "1.0.1")];
        assert_ne!(
            compute_rules_version(&rules_a),
            compute_rules_version(&rules_b)
        );
    }

    #[test]
    fn rules_version_empty_rules() {
        let v = compute_rules_version(&[]);
        assert_eq!(v.len(), 64);
    }

    // -- Config hash tests ----------------------------------------------------

    #[test]
    fn config_hash_is_deterministic() {
        let config = AtlasConfig::default();
        let h1 = compute_config_hash(&config);
        let h2 = compute_config_hash(&config);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn config_hash_changes_with_config() {
        let config_a = AtlasConfig::default();
        let mut config_b = AtlasConfig::default();
        config_b.scan.max_file_size_kb = 9999;
        assert_ne!(
            compute_config_hash(&config_a),
            compute_config_hash(&config_b)
        );
    }

    // -- Findings summary tests -----------------------------------------------

    #[test]
    fn findings_summary_empty() {
        let summary = compute_findings_summary(&[]);
        assert_eq!(
            summary,
            FindingsSummary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                total: 0,
            }
        );
    }

    #[test]
    fn findings_summary_counts_match() {
        let findings = vec![
            make_finding(Severity::Critical, "atlas/a"),
            make_finding(Severity::Critical, "atlas/b"),
            make_finding(Severity::High, "atlas/c"),
            make_finding(Severity::Medium, "atlas/d"),
            make_finding(Severity::Medium, "atlas/e"),
            make_finding(Severity::Medium, "atlas/f"),
            make_finding(Severity::Low, "atlas/g"),
            make_finding(Severity::Info, "atlas/h"),
        ];
        let summary = compute_findings_summary(&findings);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 3);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.total, 8);
    }

    // -- Report format tests --------------------------------------------------

    #[test]
    fn report_produces_valid_json() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project/src", &rules, &config, false);

        // Must parse as valid JSON.
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("report must be valid JSON");

        // Top-level structure.
        assert_eq!(parsed["schema_version"], "1.0.0");
        assert!(parsed["scan"].is_object());
        assert!(parsed["findings"].is_array());
        assert!(parsed["findings_count"].is_object());
        assert!(parsed["gate_result"].is_object());
        assert_eq!(parsed["gate_result"]["status"], "PASS");
    }

    #[test]
    fn report_without_timestamp_is_deterministic() {
        let findings = vec![
            make_finding(Severity::High, "atlas/security/ts/sqli"),
            make_finding(Severity::Medium, "atlas/quality/ts/unused"),
        ];
        let scan_result = make_scan_result(findings);
        let rules = vec![
            make_rule("atlas/security/ts/sqli", "1.0.0"),
            make_rule("atlas/quality/ts/unused", "1.0.0"),
        ];
        let config = AtlasConfig::default();

        let json1 = format_report(&scan_result, "/project/src", &rules, &config, false);
        let json2 = format_report(&scan_result, "/project/src", &rules, &config, false);

        assert_eq!(
            json1, json2,
            "two runs without timestamp must produce identical output"
        );
    }

    #[test]
    fn report_without_timestamp_omits_field() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project/src", &rules, &config, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            parsed["scan"]["timestamp"].is_null(),
            "timestamp should be omitted (null) when include_timestamp is false"
        );
    }

    #[test]
    fn report_with_timestamp_includes_iso8601() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project/src", &rules, &config, true);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let ts = parsed["scan"]["timestamp"]
            .as_str()
            .expect("timestamp should be a string");
        // ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.contains('T'), "timestamp should be ISO 8601 format");
        assert!(ts.ends_with('Z'), "timestamp should end with Z (UTC)");
    }

    #[test]
    fn report_findings_summary_matches_findings() {
        let findings = vec![
            make_finding(Severity::Critical, "atlas/a"),
            make_finding(Severity::High, "atlas/b"),
            make_finding(Severity::High, "atlas/c"),
            make_finding(Severity::Low, "atlas/d"),
        ];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/test", "1.0.0")];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project/src", &rules, &config, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["findings_count"]["critical"], 1);
        assert_eq!(parsed["findings_count"]["high"], 2);
        assert_eq!(parsed["findings_count"]["medium"], 0);
        assert_eq!(parsed["findings_count"]["low"], 1);
        assert_eq!(parsed["findings_count"]["info"], 0);
        assert_eq!(parsed["findings_count"]["total"], 4);
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn report_scan_metadata_populated() {
        let scan_result = make_scan_result(vec![]);
        let rules = vec![make_rule("atlas/test", "1.0.0")];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project/src", &rules, &config, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let scan = &parsed["scan"];
        assert!(scan["id"].is_string());
        assert_eq!(scan["id"].as_str().unwrap().len(), 64);
        assert_eq!(scan["engine_version"], ENGINE_VERSION);
        assert_eq!(scan["target_path"], "/project/src");
        assert_eq!(scan["files_scanned"], 5);
        assert_eq!(scan["files_skipped"], 1);
        assert!(scan["languages_detected"].is_array());
        assert!(scan["rules_version"].is_string());
        assert!(scan["config_hash"].is_string());
    }

    #[test]
    fn report_files_skipped_omitted_when_zero() {
        let scan_result = ScanResult {
            findings: vec![],
            files_scanned: 3,
            files_skipped: 0,
            languages_detected: vec![],
            summary: atlas_core::engine::FindingsSummary::default(),
            stats: atlas_core::engine::ScanStats::default(),
        };
        let rules: Vec<Rule> = vec![];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project", &rules, &config, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // files_skipped should not appear in the output when 0.
        assert!(
            parsed["scan"]["files_skipped"].is_null(),
            "files_skipped should be omitted when zero"
        );
    }

    #[test]
    fn report_reserved_fields_omitted() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project", &rules, &config, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // gate_details, baseline_diff, and stats should all be omitted (null).
        assert!(parsed["gate_details"].is_null());
        assert!(parsed["baseline_diff"].is_null());
        assert!(parsed["stats"].is_null());
    }

    #[test]
    fn report_roundtrip_deserialization() {
        let findings = vec![make_finding(Severity::Medium, "atlas/quality/ts/unused")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/quality/ts/unused", "1.0.0")];
        let config = AtlasConfig::default();

        let json = format_report(&scan_result, "/project/src", &rules, &config, false);

        // Must deserialize back into AtlasReport.
        let report: AtlasReport =
            serde_json::from_str(&json).expect("report must deserialize back to AtlasReport");

        assert_eq!(report.schema_version, "1.0.0");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings_count.medium, 1);
        assert_eq!(report.findings_count.total, 1);
        assert_eq!(report.gate_result.status, "PASS");
        assert!(report.gate_details.is_none());
        assert!(report.baseline_diff.is_none());
        assert!(report.stats.is_none());
    }

    #[test]
    fn report_scan_id_matches_manual_computation() {
        let rules = vec![make_rule("atlas/test", "1.0.0")];
        let config = AtlasConfig::default();

        let rules_version = compute_rules_version(&rules);
        let config_hash = compute_config_hash(&config);
        let expected_id =
            compute_scan_id("/project/src", ENGINE_VERSION, &config_hash, &rules_version);

        let scan_result = make_scan_result(vec![]);
        let json = format_report(&scan_result, "/project/src", &rules, &config, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["scan"]["id"].as_str().unwrap(), expected_id);
    }
}
