//! SARIF v2.1.0 report formatter.
//!
//! Produces an OASIS SARIF v2.1.0 report from Atlas scan results. The output
//! conforms to the SARIF specification and is suitable for consumption by
//! GitHub Code Scanning, Azure DevOps, and other SARIF-compatible tools.
//!
//! # Determinism guarantees
//!
//! - Rules are deduplicated and sorted by ID.
//! - Findings are pre-sorted by `(file_path, start_line, start_col, rule_id)`.
//! - Fingerprints use `BTreeMap` for stable key ordering.
//! - All output is deterministic given the same inputs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use atlas_analysis::Finding;
use atlas_core::engine::ScanResult;
use atlas_rules::{Rule, Severity};

use crate::ENGINE_VERSION;

// ---------------------------------------------------------------------------
// SARIF schema constants
// ---------------------------------------------------------------------------

/// SARIF specification version.
const SARIF_VERSION: &str = "2.1.0";

/// SARIF JSON schema URL.
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

/// Tool driver name.
const TOOL_NAME: &str = "Atlas Local SAST";

// ---------------------------------------------------------------------------
// SARIF structs
// ---------------------------------------------------------------------------

/// Top-level SARIF v2.1.0 report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    /// SARIF version string, always `"2.1.0"`.
    pub version: String,

    /// JSON schema URL for SARIF v2.1.0.
    #[serde(rename = "$schema")]
    pub schema: String,

    /// One or more tool runs contained in the report.
    pub runs: Vec<SarifRun>,
}

/// A single tool run within the SARIF report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    /// The tool that produced the results.
    pub tool: SarifTool,

    /// The analysis results (findings).
    pub results: Vec<SarifResult>,
}

/// SARIF tool descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    /// The primary tool component (driver).
    pub driver: SarifToolComponent,
}

/// SARIF tool component (driver) with rules metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifToolComponent {
    /// Tool name.
    pub name: String,

    /// Tool version.
    pub version: String,

    /// Rules evaluated by the tool.
    pub rules: Vec<SarifReportingDescriptor>,
}

/// A rule descriptor in SARIF format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptor {
    /// Rule identifier.
    pub id: String,

    /// Human-readable rule name.
    pub name: String,

    /// Short description of what the rule detects.
    pub short_description: SarifMessage,

    /// Default configuration including severity level.
    pub default_configuration: SarifReportingConfiguration,

    /// URL to help documentation for the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,

    /// Custom properties including CWE identifiers.
    pub properties: SarifDescriptorProperties,
}

/// Default configuration for a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReportingConfiguration {
    /// SARIF level: `"error"`, `"warning"`, `"note"`, or `"none"`.
    pub level: String,
}

/// A single analysis result (finding) in SARIF format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    /// The rule that produced this result.
    pub rule_id: String,

    /// SARIF severity level.
    pub level: String,

    /// Human-readable message describing the finding.
    pub message: SarifMessage,

    /// Source code locations where the finding was detected.
    pub locations: Vec<SarifLocation>,

    /// Content-based fingerprints for result matching.
    pub fingerprints: BTreeMap<String, String>,

    /// Atlas-specific custom properties.
    pub properties: SarifResultProperties,
}

/// A text message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    /// The message text.
    pub text: String,
}

/// A source code location.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    /// The physical location in source code.
    pub physical_location: SarifPhysicalLocation,
}

/// A physical location in a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    /// The artifact (file) location.
    pub artifact_location: SarifArtifactLocation,

    /// The region within the artifact.
    pub region: SarifRegion,
}

/// An artifact (file) location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    /// Relative file path URI.
    pub uri: String,
}

/// A region within a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    /// 1-indexed start line.
    pub start_line: u32,

    /// 1-indexed start column.
    pub start_column: u32,

    /// 1-indexed end line.
    pub end_line: u32,

    /// 1-indexed end column.
    pub end_column: u32,

    /// Source code snippet at the location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

/// Artifact content (snippet text).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    /// The text content.
    pub text: String,
}

/// Custom properties for a rule descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDescriptorProperties {
    /// CWE identifier, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// Compliance framework mappings from rule metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<Vec<serde_json::Value>>,
}

/// Custom properties for a result (finding).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResultProperties {
    /// Atlas finding category.
    pub atlas_category: String,

    /// Atlas finding confidence.
    pub atlas_confidence: String,

    /// Atlas analysis level.
    pub atlas_analysis_level: String,

    /// CWE identifier, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,

    /// Diff status for diff-aware scans ("new" or "context").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_status: Option<String>,
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

/// Maps an Atlas severity to a SARIF level string.
fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Converts an `atlas_rules::Rule` to a `SarifReportingDescriptor`.
fn rule_to_descriptor(rule: &Rule) -> SarifReportingDescriptor {
    let help_uri = rule.references.first().cloned();

    let compliance = rule
        .metadata
        .get("compliance")
        .and_then(|v| v.as_array())
        .cloned();

    SarifReportingDescriptor {
        id: rule.id.clone(),
        name: rule.name.clone(),
        short_description: SarifMessage {
            text: rule.description.clone(),
        },
        default_configuration: SarifReportingConfiguration {
            level: severity_to_sarif_level(&rule.severity).to_string(),
        },
        help_uri,
        properties: SarifDescriptorProperties {
            cwe: rule.cwe_id.clone(),
            compliance,
        },
    }
}

/// Converts an `atlas_analysis::Finding` to a `SarifResult`.
fn finding_to_result(finding: &Finding) -> SarifResult {
    let snippet = if finding.snippet.is_empty() {
        None
    } else {
        Some(SarifArtifactContent {
            text: finding.snippet.clone(),
        })
    };

    let mut fingerprints = BTreeMap::new();
    fingerprints.insert("atlasFingerprint".to_string(), finding.fingerprint.clone());

    SarifResult {
        rule_id: finding.rule_id.clone(),
        level: severity_to_sarif_level(&finding.severity).to_string(),
        message: SarifMessage {
            text: finding.description.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: finding.file_path.clone(),
                },
                region: SarifRegion {
                    start_line: finding.line_range.start_line,
                    start_column: finding.line_range.start_col,
                    end_line: finding.line_range.end_line,
                    end_column: finding.line_range.end_col,
                    snippet,
                },
            },
        }],
        fingerprints,
        properties: SarifResultProperties {
            atlas_category: finding.category.to_string(),
            atlas_confidence: finding.confidence.to_string(),
            atlas_analysis_level: finding.analysis_level.to_string(),
            cwe: finding.cwe_id.clone(),
            diff_status: finding.diff_status.as_ref().map(|s| s.to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Formats Atlas scan results as a SARIF v2.1.0 JSON report.
///
/// # Arguments
///
/// - `scan_result` -- the scan pipeline result containing findings.
/// - `rules` -- the rules that were evaluated during the scan.
///
/// # Returns
///
/// A pretty-printed JSON string conforming to SARIF v2.1.0.
///
/// # Determinism
///
/// The output is fully deterministic: calling this function with identical
/// inputs will always produce byte-identical output.
#[must_use]
pub fn format_sarif(scan_result: &ScanResult, rules: &[Rule]) -> String {
    // Collect unique rule IDs used in findings.
    let used_rule_ids: BTreeSet<&str> = scan_result
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();

    // Build rule descriptors for rules that appear in findings,
    // maintaining deterministic order via BTreeSet.
    let mut rule_descriptors: Vec<SarifReportingDescriptor> = Vec::new();
    let mut seen_rule_ids: BTreeSet<&str> = BTreeSet::new();

    // Sort rules by id for deterministic output.
    let mut sorted_rules: Vec<&Rule> = rules.iter().collect();
    sorted_rules.sort_by_key(|r| &r.id);

    for rule in &sorted_rules {
        if used_rule_ids.contains(rule.id.as_str()) && seen_rule_ids.insert(&rule.id) {
            rule_descriptors.push(rule_to_descriptor(rule));
        }
    }

    // Convert findings to SARIF results.
    let results: Vec<SarifResult> = scan_result.findings.iter().map(finding_to_result).collect();

    let report = SarifReport {
        version: SARIF_VERSION.to_string(),
        schema: SARIF_SCHEMA.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: TOOL_NAME.to_string(),
                    version: ENGINE_VERSION.to_string(),
                    rules: rule_descriptors,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&report).expect("SARIF report serialization must not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use atlas_analysis::{FindingBuilder, LineRange};
    use atlas_core::Language;
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
            confidence: Confidence::Medium,
            metadata: std::collections::BTreeMap::new(),
            skip_test_files: false,
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
            file_metrics: vec![],
            duplication: None,
            inline_suppressed: 0,
        }
    }

    // -- SARIF report tests ---------------------------------------------------

    #[test]
    fn sarif_produces_valid_json() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("SARIF report must be valid JSON");

        assert!(parsed.is_object());
        assert!(parsed["runs"].is_array());
    }

    #[test]
    fn sarif_version_is_2_1_0() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn sarif_schema_url_correct() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["$schema"],
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        );
    }

    #[test]
    fn sarif_tool_name_correct() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["name"],
            "Atlas Local SAST"
        );
    }

    #[test]
    fn sarif_severity_mapping_critical() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
    }

    #[test]
    fn sarif_severity_mapping_high() {
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
    }

    #[test]
    fn sarif_severity_mapping_medium() {
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
    }

    #[test]
    fn sarif_severity_mapping_low() {
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
    }

    #[test]
    fn sarif_severity_mapping_info() {
        assert_eq!(severity_to_sarif_level(&Severity::Info), "none");
    }

    #[test]
    fn sarif_result_locations_populated() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let location = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(location["region"]["startLine"], 10);
        assert_eq!(location["region"]["startColumn"], 1);
        assert_eq!(location["region"]["endLine"], 12);
        assert_eq!(location["region"]["endColumn"], 30);
        assert_eq!(location["artifactLocation"]["uri"], "src/app.ts");
    }

    #[test]
    fn sarif_fingerprint_included() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let fingerprints = &parsed["runs"][0]["results"][0]["fingerprints"];
        assert!(
            fingerprints["atlasFingerprint"].is_string(),
            "atlasFingerprint must be present and be a string"
        );
        assert_eq!(
            fingerprints["atlasFingerprint"].as_str().unwrap().len(),
            64,
            "fingerprint must be a 64-char SHA-256 hex digest"
        );
    }

    #[test]
    fn sarif_empty_findings_produces_empty_results() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn sarif_result_properties_populated() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let properties = &parsed["runs"][0]["results"][0]["properties"];
        assert_eq!(properties["atlasCategory"], "security");
        assert_eq!(properties["atlasConfidence"], "high");
        assert_eq!(properties["atlasAnalysisLevel"], "L1");
        assert_eq!(properties["cwe"], "CWE-89");
    }

    #[test]
    fn sarif_deterministic_output() {
        let findings = vec![
            make_finding(Severity::High, "atlas/security/ts/sqli"),
            make_finding(Severity::Medium, "atlas/quality/ts/unused"),
        ];
        let scan_result = make_scan_result(findings);
        let rules = vec![
            make_rule("atlas/security/ts/sqli", "1.0.0"),
            make_rule("atlas/quality/ts/unused", "1.0.0"),
        ];

        let json1 = format_sarif(&scan_result, &rules);
        let json2 = format_sarif(&scan_result, &rules);

        assert_eq!(json1, json2, "two runs must produce identical output");
    }

    #[test]
    fn sarif_rules_deduplication() {
        // Two findings reference the same rule.
        let f1 = make_finding(Severity::High, "atlas/security/ts/sqli");
        let f2 = FindingBuilder::new()
            .rule_id("atlas/security/ts/sqli")
            .severity(Severity::High)
            .category(Category::Security)
            .cwe_id("CWE-89")
            .file_path("src/other.ts")
            .line_range(LineRange::new(5, 1, 5, 20).unwrap())
            .snippet("const q2 = sql + input;")
            .description("Another SQL injection risk")
            .remediation("Use parameterized queries.")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap();

        let scan_result = make_scan_result(vec![f1, f2]);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Two results but only one rule descriptor.
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);

        let rule_descriptors = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(
            rule_descriptors.len(),
            1,
            "same rule in multiple findings should only appear once in rules"
        );
    }

    #[test]
    fn sarif_roundtrip_deserialization() {
        let findings = vec![make_finding(Severity::Medium, "atlas/quality/ts/unused")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/quality/ts/unused", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);

        // Must deserialize back into SarifReport.
        let report: SarifReport =
            serde_json::from_str(&json).expect("SARIF report must deserialize back");

        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].tool.driver.name, "Atlas Local SAST");
    }

    #[test]
    fn sarif_result_level_matches_severity() {
        let findings = vec![
            make_finding(Severity::Critical, "atlas/a"),
            make_finding(Severity::High, "atlas/b"),
            make_finding(Severity::Medium, "atlas/c"),
            make_finding(Severity::Low, "atlas/d"),
            make_finding(Severity::Info, "atlas/e"),
        ];
        let scan_result = make_scan_result(findings);
        let rules = vec![
            make_rule("atlas/a", "1.0.0"),
            make_rule("atlas/b", "1.0.0"),
            make_rule("atlas/c", "1.0.0"),
            make_rule("atlas/d", "1.0.0"),
            make_rule("atlas/e", "1.0.0"),
        ];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error"); // Critical
        assert_eq!(results[1]["level"], "error"); // High
        assert_eq!(results[2]["level"], "warning"); // Medium
        assert_eq!(results[3]["level"], "note"); // Low
        assert_eq!(results[4]["level"], "none"); // Info
    }

    #[test]
    fn sarif_rule_help_uri_from_references() {
        let mut rule = make_rule("atlas/security/ts/sqli", "1.0.0");
        rule.references = vec![
            "https://example.com/help".to_string(),
            "https://example.com/other".to_string(),
        ];

        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);

        let json = format_sarif(&scan_result, &[rule]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let rule_desc = &parsed["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule_desc["helpUri"], "https://example.com/help");
    }

    #[test]
    fn sarif_rule_no_help_uri_when_no_references() {
        let scan_result =
            make_scan_result(vec![make_finding(Severity::High, "atlas/security/ts/sqli")]);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let rule_desc = &parsed["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(
            rule_desc.get("helpUri").is_none() || rule_desc["helpUri"].is_null(),
            "helpUri should be omitted when no references exist"
        );
    }

    #[test]
    fn sarif_snippet_included_in_region() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["snippet"]["text"], "const q = sql + input;");
    }

    #[test]
    fn sarif_tool_version_matches_engine() {
        let scan_result = make_scan_result(vec![]);
        let rules: Vec<Rule> = vec![];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["version"],
            ENGINE_VERSION
        );
    }

    #[test]
    fn sarif_diff_status_included_when_present() {
        use atlas_analysis::DiffStatus;

        let mut finding = make_finding(Severity::High, "atlas/security/ts/sqli");
        finding.diff_status = Some(DiffStatus::New);

        let scan_result = make_scan_result(vec![finding]);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let properties = &parsed["runs"][0]["results"][0]["properties"];
        assert_eq!(
            properties["diffStatus"], "new",
            "diff_status should be present as 'new' in SARIF properties"
        );
    }

    #[test]
    fn sarif_rule_compliance_included_when_present() {
        let mut rule = make_rule("atlas/security/ts/sqli", "1.0.0");
        rule.metadata.insert(
            "compliance".to_string(),
            serde_json::json!([
                { "framework": "owasp-top-10-2021", "requirement": "A03:2021", "description": "Injection" },
                { "framework": "pci-dss-4.0", "requirement": "6.2.4", "description": "Prevention of Common Software Attacks" }
            ]),
        );

        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);

        let json = format_sarif(&scan_result, &[rule]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let rule_props = &parsed["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        let compliance = rule_props["compliance"].as_array().unwrap();
        assert_eq!(compliance.len(), 2);
        assert_eq!(compliance[0]["framework"], "owasp-top-10-2021");
        assert_eq!(compliance[1]["framework"], "pci-dss-4.0");
    }

    #[test]
    fn sarif_rule_compliance_omitted_when_absent() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let rule_props = &parsed["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        assert!(
            rule_props.get("compliance").is_none() || rule_props["compliance"].is_null(),
            "compliance should be omitted when rule has no compliance metadata"
        );
    }

    #[test]
    fn sarif_diff_status_omitted_when_none() {
        let finding = make_finding(Severity::High, "atlas/security/ts/sqli");
        assert!(finding.diff_status.is_none());

        let scan_result = make_scan_result(vec![finding]);
        let rules = vec![make_rule("atlas/security/ts/sqli", "1.0.0")];

        let json = format_sarif(&scan_result, &rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let properties = &parsed["runs"][0]["results"][0]["properties"];
        assert!(
            properties.get("diffStatus").is_none() || properties["diffStatus"].is_null(),
            "diffStatus should be omitted when diff_status is None"
        );
    }
}
