//! End-to-end integration tests for the Atlas scan pipeline.
//!
//! These tests validate the full pipeline: discover files -> parse TypeScript ->
//! run L1 rules -> produce Atlas JSON report, using the real fixture files in
//! `tests/fixtures/typescript-vulnerable/`.

use std::path::PathBuf;

use atlas_analysis::DiffStatus;
use atlas_core::config::AtlasConfig;
use atlas_core::diff;
use atlas_core::engine::{ScanEngine, ScanOptions};
use atlas_core::{Category, GateResult, Severity};
use atlas_policy::gate::{self, GateFinding};
use atlas_report::{
    AtlasReport, DiffContextReport, GateBreachedThreshold, GateDetails, ReportOptions,
    SCHEMA_VERSION, format_report, format_report_with_options,
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
    assert!(
        result.files_scanned >= 4,
        "should scan at least 4 .ts files"
    );
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
    assert!(
        sqli_findings
            .iter()
            .all(|f| f.file_path == "sql-injection.ts")
    );
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
        .filter(|f| {
            f.rule_id
                .starts_with("atlas/security/typescript/code-injection")
        })
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

/// Thin wrapper for orphan-rule compliance. No conversion needed — types are
/// unified via re-exports from `atlas-rules`.
struct FindingAdapter<'a>(&'a atlas_analysis::Finding);

impl GateFinding for FindingAdapter<'_> {
    fn severity(&self) -> Severity {
        self.0.severity
    }

    fn category(&self) -> Category {
        self.0.category
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
        baseline_applied: None,
        baseline_diff: None,
        diff_context: None,
        compliance_summary: None,
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

// ---------------------------------------------------------------------------
// Diff-aware scanning e2e tests
// ---------------------------------------------------------------------------

/// Helper to run a git command in a directory and return stdout.
fn git_cmd(dir: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git must be available");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Returns TypeScript code that triggers atlas/security/typescript/sql-injection.
/// Intentionally vulnerable — this is a SAST scanner test fixture.
fn vuln_sql_code() -> String {
    // String concatenation in SQL query — triggers sql-injection rule.
    "const q = \"SELECT * FROM users WHERE id = \" + userInput;\nconsole.log(q);\n".to_string()
}

/// Returns TypeScript code that triggers atlas/security/typescript/path-traversal.
fn vuln_path_code() -> String {
    "import * as fs from 'fs';\nconst data = fs.readFileSync(userInput);\nconsole.log(data);\n"
        .to_string()
}

/// Creates a temporary git repo with TypeScript files, commits them,
/// then modifies some files to create a diff against HEAD.
///
/// Returns `(tmp_dir, engine)` where `tmp_dir` owns the temp directory
/// lifetime and `engine` has rules loaded.
fn setup_diff_repo() -> (tempfile::TempDir, ScanEngine) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Init git repo.
    git_cmd(dir, &["init"]);
    git_cmd(dir, &["config", "user.email", "test@test.com"]);
    git_cmd(dir, &["config", "user.name", "Test"]);

    // Create 5 TypeScript files, initially all safe.
    std::fs::write(dir.join("safe1.ts"), "const x = 1;\nconsole.log(x);\n").unwrap();
    std::fs::write(dir.join("safe2.ts"), "const y = 2;\nconsole.log(y);\n").unwrap();
    std::fs::write(dir.join("safe3.ts"), "const z = 3;\nconsole.log(z);\n").unwrap();
    std::fs::write(dir.join("vuln1.ts"), "const a = 1;\nconsole.log(a);\n").unwrap();
    std::fs::write(dir.join("vuln2.ts"), "const b = 2;\nconsole.log(b);\n").unwrap();

    git_cmd(dir, &["add", "."]);
    git_cmd(dir, &["commit", "-m", "initial"]);

    // Now modify vuln1.ts and vuln2.ts to introduce vulnerabilities.
    std::fs::write(dir.join("vuln1.ts"), vuln_sql_code()).unwrap();
    std::fs::write(dir.join("vuln2.ts"), vuln_path_code()).unwrap();

    // Stage the changes so git diff HEAD can see them.
    git_cmd(dir, &["add", "."]);

    let mut engine = ScanEngine::new();
    engine
        .load_rules(&builtin_rules_dir())
        .expect("rules must load");

    (tmp, engine)
}

#[test]
fn e2e_diff_aware_scan_only_scans_changed_files() {
    let (tmp, engine) = setup_diff_repo();
    let dir = tmp.path();

    let dc = diff::compute_diff(dir, "HEAD").expect("compute_diff must succeed");
    assert!(!dc.is_fallback, "should be a valid git repo");
    assert_eq!(dc.changed_files.len(), 2, "should have 2 changed files");

    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    // Only 2 files should be scanned (the changed ones).
    assert_eq!(
        result.files_scanned, 2,
        "diff-aware scan should only scan changed files"
    );
}

#[test]
fn e2e_diff_aware_findings_have_diff_status() {
    let (tmp, engine) = setup_diff_repo();
    let dir = tmp.path();

    let dc = diff::compute_diff(dir, "HEAD").expect("compute_diff must succeed");
    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    // All findings should have a diff_status set.
    for finding in &result.findings {
        assert!(
            finding.diff_status.is_some(),
            "finding in {} should have diff_status set",
            finding.file_path
        );
    }

    // At least one finding should be New (on a changed line).
    let new_count = result
        .findings
        .iter()
        .filter(|f| f.diff_status == Some(DiffStatus::New))
        .count();
    assert!(
        new_count > 0,
        "should have at least one finding with New diff_status"
    );
}

#[test]
fn e2e_clean_working_tree_diff_produces_zero_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    git_cmd(dir, &["init"]);
    git_cmd(dir, &["config", "user.email", "test@test.com"]);
    git_cmd(dir, &["config", "user.name", "Test"]);

    std::fs::write(dir.join("clean.ts"), "const x = 1;\n").unwrap();
    git_cmd(dir, &["add", "."]);
    git_cmd(dir, &["commit", "-m", "initial"]);

    // No changes after commit — diff should be empty.
    let dc = diff::compute_diff(dir, "HEAD").expect("compute_diff must succeed");
    assert!(dc.changed_files.is_empty(), "clean tree should have no changed files");

    let mut engine = ScanEngine::new();
    engine.load_rules(&builtin_rules_dir()).unwrap();

    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(result.files_scanned, 0, "clean tree should scan 0 files");
    assert!(result.findings.is_empty(), "clean tree should have no findings");
}

#[test]
fn e2e_non_git_directory_falls_back_to_full_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Not a git repo — just a regular directory with a vulnerable file.
    std::fs::write(dir.join("app.ts"), vuln_sql_code()).unwrap();

    let dc = diff::compute_diff(dir, "HEAD").expect("compute_diff must succeed for non-git");
    assert!(dc.is_fallback, "non-git dir should produce fallback");

    let mut engine = ScanEngine::new();
    engine.load_rules(&builtin_rules_dir()).unwrap();

    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    // Fallback means full scan — all files should be scanned.
    assert!(
        result.files_scanned >= 1,
        "fallback should scan all files, got {}",
        result.files_scanned
    );
}

#[test]
fn e2e_delete_only_diff_produces_zero_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    git_cmd(dir, &["init"]);
    git_cmd(dir, &["config", "user.email", "test@test.com"]);
    git_cmd(dir, &["config", "user.name", "Test"]);

    std::fs::write(dir.join("a.ts"), "const a = 1;\n").unwrap();
    std::fs::write(dir.join("b.ts"), "const b = 2;\n").unwrap();
    git_cmd(dir, &["add", "."]);
    git_cmd(dir, &["commit", "-m", "initial"]);

    // Delete one file.
    std::fs::remove_file(dir.join("a.ts")).unwrap();
    git_cmd(dir, &["add", "."]);

    let dc = diff::compute_diff(dir, "HEAD").expect("compute_diff must succeed");
    // git diff --diff-filter=ACMR excludes deletions, so changed_files should be empty.
    assert!(
        dc.changed_files.is_empty(),
        "delete-only diff should have no changed files"
    );

    let mut engine = ScanEngine::new();
    engine.load_rules(&builtin_rules_dir()).unwrap();

    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(result.files_scanned, 0, "delete-only diff should scan 0 files");
}

#[test]
fn e2e_diff_aware_json_report_includes_diff_context() {
    let (tmp, engine) = setup_diff_repo();
    let dir = tmp.path();
    let config = AtlasConfig::default();

    let dc = diff::compute_diff(dir, "HEAD").unwrap();
    let git_ref = dc.git_ref.clone();
    let changed_count = dc.changed_files.len() as u32;

    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    let total_new = result
        .findings
        .iter()
        .filter(|f| f.diff_status == Some(DiffStatus::New))
        .count() as u32;
    let total_context = result
        .findings
        .iter()
        .filter(|f| f.diff_status == Some(DiffStatus::Context))
        .count() as u32;

    let options = ReportOptions {
        diff_context: Some(DiffContextReport {
            git_ref,
            changed_files_count: changed_count,
            total_new_findings: total_new,
            total_context_findings: total_context,
        }),
        ..Default::default()
    };

    let json = format_report_with_options(
        &result,
        &dir.display().to_string(),
        engine.rules(),
        &config,
        &options,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify diff_context section in report.
    let dc_section = &parsed["diff_context"];
    assert!(!dc_section.is_null(), "diff_context should be present in JSON report");
    assert_eq!(dc_section["changed_files_count"], changed_count);
    assert!(dc_section["git_ref"].is_string());

    // Verify per-finding diff_status.
    for finding_json in parsed["findings"].as_array().unwrap() {
        let ds = &finding_json["diff_status"];
        assert!(
            ds.as_str() == Some("new") || ds.as_str() == Some("context"),
            "each finding should have diff_status 'new' or 'context', got: {ds}"
        );
    }
}

#[test]
fn e2e_diff_aware_sarif_includes_diff_status() {
    let (tmp, engine) = setup_diff_repo();
    let dir = tmp.path();

    let dc = diff::compute_diff(dir, "HEAD").unwrap();
    let result = engine
        .scan_with_options(
            dir,
            None,
            &ScanOptions {
                diff_context: Some(dc),
                ..Default::default()
            },
        )
        .unwrap();

    let sarif_json = atlas_report::sarif::format_sarif(&result, engine.rules());
    let parsed: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();

    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty(), "should have SARIF results");

    for sarif_result in results {
        let ds = &sarif_result["properties"]["diffStatus"];
        assert!(
            ds.as_str() == Some("new") || ds.as_str() == Some("context"),
            "SARIF result should have diffStatus in properties, got: {ds}"
        );
    }
}

#[test]
fn e2e_existing_tests_pass_without_modification() {
    // This test verifies that the existing scan pipeline still works
    // without diff context (regression test).
    let engine = create_engine();
    let result = engine.scan(&fixtures_dir(), None).unwrap();

    // All findings should have diff_status == None.
    for finding in &result.findings {
        assert!(
            finding.diff_status.is_none(),
            "findings without diff context should have diff_status == None"
        );
    }

    assert!(
        !result.findings.is_empty(),
        "existing fixtures must still produce findings"
    );
}
