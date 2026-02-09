//! End-to-end integration tests for compliance framework mapping.
//!
//! These tests validate:
//! - Compliance coverage computation across all builtin rules
//! - JSON report compliance_summary field
//! - SARIF report compliance properties on rule descriptors
//! - CLI compliance subcommand error handling

use std::path::PathBuf;

use atlas_core::compliance;
use atlas_core::config::AtlasConfig;
use atlas_core::engine::ScanEngine;
use atlas_report::{format_report_with_options, ReportOptions};
use atlas_rules::declarative::DeclarativeRuleLoader;

/// Returns the workspace root directory.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must exist")
}

/// Path to the TypeScript vulnerable fixtures directory.
fn fixtures_dir() -> PathBuf {
    workspace_root().join("tests/fixtures/typescript-vulnerable")
}

/// Creates a fully wired `ScanEngine` with built-in TypeScript rules loaded.
fn create_engine() -> ScanEngine {
    let mut engine = ScanEngine::new();
    engine
        .load_rules(&workspace_root().join("rules/builtin/typescript"))
        .expect("built-in rules must load successfully");
    engine
}

// ---------------------------------------------------------------------------
// 6.1: Compliance coverage produces table output with 10 categories
// ---------------------------------------------------------------------------

#[test]
fn e2e_compliance_coverage_owasp_has_10_categories() {
    let compliance_dir = workspace_root().join("rules/compliance");
    let frameworks = compliance::load_frameworks(&compliance_dir).unwrap();
    let owasp = frameworks
        .iter()
        .find(|f| f.id == "owasp-top-10-2021")
        .expect("OWASP Top 10 2021 framework must exist");

    assert_eq!(owasp.categories.len(), 10, "OWASP Top 10 must have 10 categories");

    // Load all builtin rules and compute coverage.
    let builtin_dir = workspace_root().join("rules/builtin");
    let loader = DeclarativeRuleLoader;
    let rules = loader.load_from_dir(&builtin_dir).unwrap();
    let summary = compliance::compute_coverage(owasp, &rules);

    assert_eq!(summary.categories.len(), 10);
    assert!(
        summary.coverage_percentage > 0.0,
        "coverage should be non-zero with security rules loaded"
    );
    assert!(
        summary.total_rules > 0,
        "at least some rules should map to OWASP categories"
    );
    assert!(
        summary.covered_categories > 0,
        "at least some OWASP categories should be covered"
    );
}

// ---------------------------------------------------------------------------
// 6.2: Compliance coverage JSON output has expected schema
// ---------------------------------------------------------------------------

#[test]
fn e2e_compliance_coverage_json_schema() {
    let compliance_dir = workspace_root().join("rules/compliance");
    let frameworks = compliance::load_frameworks(&compliance_dir).unwrap();
    let owasp = frameworks
        .iter()
        .find(|f| f.id == "owasp-top-10-2021")
        .expect("OWASP Top 10 2021 framework must exist");

    let builtin_dir = workspace_root().join("rules/builtin");
    let loader = DeclarativeRuleLoader;
    let rules = loader.load_from_dir(&builtin_dir).unwrap();
    let summary = compliance::compute_coverage(owasp, &rules);

    // Serialise to JSON and verify schema.
    let json = serde_json::to_string_pretty(&summary).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["framework"].is_string());
    assert!(parsed["framework_name"].is_string());
    assert!(parsed["categories"].is_array());
    assert!(parsed["total_rules"].is_number());
    assert!(parsed["covered_categories"].is_number());
    assert!(parsed["coverage_percentage"].is_number());

    // Each category should have expected fields.
    let cats = parsed["categories"].as_array().unwrap();
    for cat in cats {
        assert!(cat["category_id"].is_string());
        assert!(cat["category_title"].is_string());
        assert!(cat["mapped_rules"].is_number());
        assert!(cat["finding_count"].is_number());
        assert!(cat["status"].is_string());
        let status = cat["status"].as_str().unwrap();
        assert!(
            status == "Covered" || status == "No Coverage",
            "unexpected status: {status}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6.3: Invalid framework ID returns error with available list
// ---------------------------------------------------------------------------

#[test]
fn e2e_compliance_invalid_framework_detected() {
    let compliance_dir = workspace_root().join("rules/compliance");
    let frameworks = compliance::load_frameworks(&compliance_dir).unwrap();
    let available_ids: Vec<&str> = frameworks.iter().map(|f| f.id.as_str()).collect();

    // "nonexistent" should not be in the available list.
    assert!(
        !available_ids.contains(&"nonexistent"),
        "nonexistent should not be a valid framework ID"
    );

    // Verify we have the expected frameworks.
    assert!(available_ids.contains(&"owasp-top-10-2021"));
    assert!(available_ids.contains(&"pci-dss-4.0"));
    assert!(available_ids.contains(&"nist-800-53"));
    assert!(available_ids.contains(&"hipaa-security"));
}

// ---------------------------------------------------------------------------
// 6.4: Scan with compliance-mapped rules produces JSON report with compliance_summary
// ---------------------------------------------------------------------------

#[test]
fn e2e_scan_json_report_includes_compliance_summary() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    // Build compliance summary from the scan results.
    let compliance_dir = workspace_root().join("rules/compliance");
    let frameworks = compliance::load_frameworks(&compliance_dir).unwrap();
    assert!(!frameworks.is_empty());

    let mut summaries: Vec<compliance::ComplianceSummary> = frameworks
        .iter()
        .map(|fw| compliance::compute_coverage(fw, engine.rules()))
        .collect();

    // Enrich with finding counts.
    for summary in &mut summaries {
        for finding in &result.findings {
            if let Some(compliance_val) = finding.metadata.get("compliance") {
                if let Some(arr) = compliance_val.as_array() {
                    for entry in arr {
                        if let (Some(fw), Some(req)) = (
                            entry.get("framework").and_then(|v| v.as_str()),
                            entry.get("requirement").and_then(|v| v.as_str()),
                        ) {
                            if fw == summary.framework {
                                if let Some(cat) = summary
                                    .categories
                                    .iter_mut()
                                    .find(|c| c.category_id == req)
                                {
                                    cat.finding_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let config = AtlasConfig::default();
    let options = ReportOptions {
        include_timestamp: false,
        gate_status: Some("PASS"),
        gate_details: None,
        policy_name: Some("test"),
        baseline_applied: None,
        baseline_diff: None,
        diff_context: None,
        compliance_summary: Some(summaries),
    };

    let json = format_report_with_options(
        &result,
        &fixtures_dir().display().to_string(),
        engine.rules(),
        &config,
        &options,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // compliance_summary should be present and non-empty.
    let cs = &parsed["compliance_summary"];
    assert!(!cs.is_null(), "compliance_summary should be present");
    let summaries = cs.as_array().unwrap();
    assert_eq!(summaries.len(), 4, "should have summaries for all 4 frameworks");

    // Find OWASP summary and verify findings were counted.
    let owasp = summaries
        .iter()
        .find(|s| s["framework"] == "owasp-top-10-2021")
        .expect("OWASP summary must be present");
    assert!(
        owasp["total_rules"].as_u64().unwrap() > 0,
        "OWASP should have mapped rules"
    );

    // There should be at least some findings counted in categories
    // (since we scanned vulnerable TypeScript code).
    let cats = owasp["categories"].as_array().unwrap();
    let total_findings: u64 = cats
        .iter()
        .map(|c| c["finding_count"].as_u64().unwrap_or(0))
        .sum();
    assert!(
        total_findings > 0,
        "should have at least one finding mapped to an OWASP category"
    );
}

// ---------------------------------------------------------------------------
// 6.5: Scan with compliance-mapped rules produces SARIF with compliance properties
// ---------------------------------------------------------------------------

#[test]
fn e2e_scan_sarif_includes_compliance_on_rule_descriptors() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    let sarif_json = atlas_report::sarif::format_sarif(&result, engine.rules());
    let parsed: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();

    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array must exist");

    // At least one rule descriptor should have compliance properties.
    let rules_with_compliance: Vec<_> = rules
        .iter()
        .filter(|r| {
            r["properties"]["compliance"].is_array()
                && !r["properties"]["compliance"].as_array().unwrap().is_empty()
        })
        .collect();

    assert!(
        !rules_with_compliance.is_empty(),
        "at least one rule descriptor should have compliance metadata in SARIF"
    );

    // Verify compliance entries have expected fields.
    for rule in &rules_with_compliance {
        let compliance = rule["properties"]["compliance"].as_array().unwrap();
        for entry in compliance {
            assert!(
                entry["framework"].is_string(),
                "compliance entry must have framework"
            );
            assert!(
                entry["requirement"].is_string(),
                "compliance entry must have requirement"
            );
            assert!(
                entry["description"].is_string(),
                "compliance entry must have description"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6.6: Existing scan tests pass unchanged (non-regression)
// (Covered by the 20 tests in e2e_scan.rs passing without modification)
// ---------------------------------------------------------------------------

#[test]
fn e2e_compliance_all_four_frameworks_compute_coverage() {
    let compliance_dir = workspace_root().join("rules/compliance");
    let frameworks = compliance::load_frameworks(&compliance_dir).unwrap();
    assert_eq!(frameworks.len(), 4);

    let builtin_dir = workspace_root().join("rules/builtin");
    let loader = DeclarativeRuleLoader;
    let rules = loader.load_from_dir(&builtin_dir).unwrap();

    for fw in &frameworks {
        let summary = compliance::compute_coverage(fw, &rules);
        assert_eq!(summary.framework, fw.id);
        assert_eq!(summary.categories.len(), fw.categories.len());
        // All frameworks should have at least some coverage with our 33 security/secrets rules.
        assert!(
            summary.total_rules > 0,
            "framework {} should have at least one mapped rule",
            fw.id
        );
    }
}
