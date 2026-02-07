//! End-to-end integration tests for the Atlas scan pipeline.
//!
//! These tests validate the full pipeline: discover files -> parse TypeScript ->
//! run L1 rules -> produce Atlas JSON report, using the real fixture files in
//! `tests/fixtures/typescript-vulnerable/`.

use std::path::PathBuf;

use atlas_core::config::AtlasConfig;
use atlas_core::engine::{ScanEngine, ScanOptions};
use atlas_core::{Category, GateResult, Severity};
use atlas_policy::gate::{self, GateFinding};
use atlas_report::{
    format_report, format_report_with_options, AtlasReport, GateBreachedThreshold, GateDetails,
    ReportOptions, SCHEMA_VERSION,
};

/// Returns the workspace root directory.
fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points to crates/atlas-cli, so go up two levels.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must exist")
}

/// Path to the TypeScript vulnerable fixtures directory.
fn fixtures_dir() -> PathBuf {
    workspace_root().join("tests/fixtures/typescript-vulnerable")
}

/// Path to the built-in TypeScript rules.
fn builtin_rules_dir() -> PathBuf {
    workspace_root().join("rules/builtin/typescript")
}

/// Creates a fully wired `ScanEngine` with built-in TypeScript rules loaded.
fn create_engine() -> ScanEngine {
    let mut engine = ScanEngine::new();
    engine
        .load_rules(&builtin_rules_dir())
        .expect("built-in rules must load successfully");
    engine
}

// ---------------------------------------------------------------------------
// End-to-end scan produces findings
// ---------------------------------------------------------------------------

#[test]
fn e2e_scan_finds_vulnerabilities_in_fixtures() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    // We expect findings from: sql-injection.ts, xss-vulnerability.ts,
    // code-injection.ts. We do NOT expect findings from safe-code.ts.
    assert!(
        !result.findings.is_empty(),
        "scan must produce findings for vulnerable fixtures"
    );
    assert!(result.files_scanned >= 4, "should scan at least 4 .ts files");
}

// ---------------------------------------------------------------------------
// Specific vulnerability detection
// ---------------------------------------------------------------------------

#[test]
fn e2e_detects_sql_injection() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    let sqli_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "atlas/security/typescript/sql-injection")
        .collect();

    assert!(
        !sqli_findings.is_empty(),
        "must detect SQL injection in sql-injection.ts"
    );
    assert!(sqli_findings.iter().all(|f| f.file_path == "sql-injection.ts"));
}

#[test]
fn e2e_detects_xss_innerhtml() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    let xss_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "atlas/security/typescript/xss-innerhtml")
        .collect();

    assert!(
        xss_findings.len() >= 2,
        "must detect at least 2 innerHTML assignments in xss-vulnerability.ts"
    );
}

#[test]
fn e2e_detects_code_injection() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    // Check for code injection findings (both rule IDs)
    let code_injection_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id.starts_with("atlas/security/typescript/code-injection"))
        .collect();

    assert!(
        code_injection_findings.len() >= 3,
        "must detect at least 3 code injection findings in code-injection.ts"
    );
}

#[test]
fn e2e_detects_function_constructor() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    let fn_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "atlas/security/typescript/code-injection-function-constructor")
        .collect();

    assert!(
        !fn_findings.is_empty(),
        "must detect Function constructor in code-injection.ts"
    );
}

// ---------------------------------------------------------------------------
// No false positives on safe code
// ---------------------------------------------------------------------------

#[test]
fn e2e_no_findings_in_safe_code() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    let safe_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.file_path == "safe-code.ts")
        .collect();

    assert!(
        safe_findings.is_empty(),
        "safe-code.ts must not produce any findings, got: {safe_findings:?}"
    );
}

// ---------------------------------------------------------------------------
// Atlas Findings JSON v1.0.0 report format
// ---------------------------------------------------------------------------

#[test]
fn e2e_report_conforms_to_schema_v1() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();
    let config = AtlasConfig::default();

    let json = format_report(
        &result,
        &fixtures_dir().display().to_string(),
        engine.rules(),
        &config,
        false,
    );

    // Must parse as valid JSON.
    let report: AtlasReport =
        serde_json::from_str(&json).expect("report must deserialize to AtlasReport");

    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert!(!report.scan.id.is_empty());
    assert_eq!(report.scan.id.len(), 64, "scan ID must be SHA-256 hex");
    assert!(!report.scan.engine_version.is_empty());
    assert!(!report.scan.rules_version.is_empty());
    assert!(!report.scan.config_hash.is_empty());
    assert!(report.findings_count.total > 0);
    assert_eq!(
        report.findings_count.total as usize,
        report.findings.len(),
        "total count must match findings array length"
    );
    assert_eq!(report.gate_result.status, "PASS");
}

// ---------------------------------------------------------------------------
// Deterministic output
// ---------------------------------------------------------------------------

#[test]
fn e2e_report_is_deterministic() {
    let config = AtlasConfig::default();
    let target = fixtures_dir().display().to_string();

    let engine = create_engine();
    let result1 = engine.scan(&fixtures_dir(), None).unwrap();
    let json1 = format_report(&result1, &target, engine.rules(), &config, false);

    let engine2 = create_engine();
    let result2 = engine2.scan(&fixtures_dir(), None).unwrap();
    let json2 = format_report(&result2, &target, engine2.rules(), &config, false);

    assert_eq!(json1, json2, "two runs must produce byte-identical output");
}

// ---------------------------------------------------------------------------
// Parallel scan produces same results
// ---------------------------------------------------------------------------

#[test]
fn e2e_parallel_scan_matches_serial() {
    let engine = create_engine();

    let fixtures = fixtures_dir();
    let serial_result = engine
        .scan_with_options(
            &fixtures,
            None,
            &ScanOptions {
                jobs: Some(1),
                ..Default::default()
            },
        )
        .unwrap();

    let parallel_result = engine
        .scan_with_options(
            &fixtures,
            None,
            &ScanOptions {
                jobs: Some(4),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(serial_result.findings.len(), parallel_result.findings.len());
    assert_eq!(serial_result.files_scanned, parallel_result.files_scanned);

    // Findings should be identical after deterministic sort.
    for (s, p) in serial_result
        .findings
        .iter()
        .zip(parallel_result.findings.iter())
    {
        assert_eq!(s.fingerprint, p.fingerprint);
        assert_eq!(s.rule_id, p.rule_id);
        assert_eq!(s.file_path, p.file_path);
    }
}

// ---------------------------------------------------------------------------
// Gate evaluation with default policy
// ---------------------------------------------------------------------------

/// Adapter to bridge atlas_rules types to atlas_core types for gate evaluation.
struct FindingAdapter<'a>(&'a atlas_analysis::Finding);

impl GateFinding for FindingAdapter<'_> {
    fn severity(&self) -> Severity {
        match self.0.severity {
            atlas_rules::Severity::Critical => Severity::Critical,
            atlas_rules::Severity::High => Severity::High,
            atlas_rules::Severity::Medium => Severity::Medium,
            atlas_rules::Severity::Low => Severity::Low,
            atlas_rules::Severity::Info => Severity::Info,
        }
    }

    fn category(&self) -> Category {
        match self.0.category {
            atlas_rules::Category::Security => Category::Security,
            atlas_rules::Category::Quality => Category::Quality,
            atlas_rules::Category::Secrets => Category::Secrets,
        }
    }
}

#[test]
fn e2e_default_policy_fails_on_critical_findings() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    let policy = atlas_policy::default_policy();
    let adapted: Vec<FindingAdapter<'_>> = result.findings.iter().map(FindingAdapter).collect();
    let gate_eval = gate::evaluate_gate(
        &adapted,
        &policy.fail_on,
        policy.warn_on.as_ref(),
        policy.category_overrides.as_ref(),
    );

    // The fixtures contain critical findings (eval, Function constructor, SQL injection),
    // so the default policy (fail on critical > 0) should produce FAIL.
    assert_eq!(
        gate_eval.result,
        GateResult::Fail,
        "default policy must FAIL when critical findings are present"
    );
    assert!(
        !gate_eval.breached_thresholds.is_empty(),
        "must have breached thresholds"
    );
}

#[test]
fn e2e_report_with_gate_result() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();
    let config = AtlasConfig::default();

    let policy = atlas_policy::default_policy();
    let adapted: Vec<FindingAdapter<'_>> = result.findings.iter().map(FindingAdapter).collect();
    let gate_eval = gate::evaluate_gate(
        &adapted,
        &policy.fail_on,
        policy.warn_on.as_ref(),
        policy.category_overrides.as_ref(),
    );

    let gate_status = gate_eval.result.to_string();
    let report_gate_details = if gate_eval.breached_thresholds.is_empty() {
        None
    } else {
        Some(GateDetails {
            breached_thresholds: gate_eval
                .breached_thresholds
                .iter()
                .map(|b| GateBreachedThreshold {
                    severity: b.severity.clone(),
                    category: b.category.clone(),
                    threshold: b.threshold,
                    actual: b.actual,
                    level: b.level.clone(),
                })
                .collect(),
        })
    };

    let options = ReportOptions {
        include_timestamp: false,
        gate_status: Some(&gate_status),
        gate_details: report_gate_details,
        policy_name: Some(&policy.name),
    };

    let json = format_report_with_options(
        &result,
        &fixtures_dir().display().to_string(),
        engine.rules(),
        &config,
        &options,
    );

    let report: AtlasReport =
        serde_json::from_str(&json).expect("report must deserialize to AtlasReport");

    assert_eq!(report.gate_result.status, "FAIL");
    assert_eq!(report.scan.policy_applied.as_deref(), Some("atlas-default"));
    assert!(report.gate_details.is_some());
}

// ---------------------------------------------------------------------------
// Exit code validation
// ---------------------------------------------------------------------------

#[test]
fn e2e_scan_returns_zero_exit_for_pass() {
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None);
    assert!(result.is_ok(), "scan of valid fixture dir must succeed");
}
