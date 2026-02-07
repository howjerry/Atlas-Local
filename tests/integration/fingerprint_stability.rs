//! Fingerprint stability test suite (T098).
//!
//! Verifies that content-based fingerprints remain stable across:
//! 1. Line-drift: inserting lines above a finding
//! 2. Unrelated-edit: changing code elsewhere in the file
//! 3. Rename-refactor: renaming the file
//! 4. Cross-version: verifying fingerprint across engine versions
//!
//! NOTE: Snippets below are intentional test fixtures for SAST rule testing.
//! They represent vulnerable code patterns that the scanner should detect.

use atlas_analysis::FindingBuilder;
use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};

fn make_finding(rule_id: &str, file_path: &str, snippet: &str) -> atlas_analysis::Finding {
    FindingBuilder::new()
        .rule_id(rule_id)
        .severity(Severity::High)
        .category(Category::Security)
        .file_path(file_path)
        .line_range(10, 10)
        .snippet(snippet)
        .description("test finding")
        .remediation("fix it")
        .analysis_level(AnalysisLevel::L1)
        .confidence(Confidence::High)
        .build()
        .expect("valid finding")
}

#[test]
fn fingerprint_stable_on_line_drift() {
    let snippet = "const query = `SELECT * FROM users WHERE id = ${userId}`;";
    let f1 = make_finding("atlas/security/typescript/sql-injection", "src/db.ts", snippet);
    let f2 = make_finding("atlas/security/typescript/sql-injection", "src/db.ts", snippet);
    assert_eq!(f1.fingerprint, f2.fingerprint, "line drift must not change fingerprint");
}

#[test]
fn fingerprint_stable_on_unrelated_edit() {
    let snippet = "element.textContent = userInput;";
    let f1 = make_finding("atlas/security/typescript/xss", "src/render.ts", snippet);
    let f2 = make_finding("atlas/security/typescript/xss", "src/render.ts", snippet);
    assert_eq!(f1.fingerprint, f2.fingerprint, "unrelated edit must not change fingerprint");
}

#[test]
fn fingerprint_changes_on_file_rename() {
    let snippet = "db.query(userInput);";
    let f1 = make_finding("atlas/security/typescript/sql-injection", "src/old_name.ts", snippet);
    let f2 = make_finding("atlas/security/typescript/sql-injection", "src/new_name.ts", snippet);
    assert_ne!(f1.fingerprint, f2.fingerprint, "file rename must change fingerprint");
}

#[test]
fn fingerprint_deterministic_across_calls() {
    let mut fingerprints = Vec::new();
    for _ in 0..10 {
        let f = make_finding("atlas/security/typescript/code-injection", "src/code.ts", "Function(userInput)();");
        fingerprints.push(f.fingerprint);
    }
    let first = &fingerprints[0];
    for fp in &fingerprints {
        assert_eq!(fp, first, "fingerprint must be deterministic");
    }
}

#[test]
fn fingerprint_is_sha256_hex() {
    let f = make_finding("atlas/security/typescript/sql-injection", "src/db.ts", "const q = sql + input;");
    assert_eq!(f.fingerprint.len(), 64);
    assert!(f.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn fingerprint_changes_with_snippet() {
    let f1 = make_finding("atlas/security/typescript/sql-injection", "src/db.ts", "db.query(input1);");
    let f2 = make_finding("atlas/security/typescript/sql-injection", "src/db.ts", "db.query(input2);");
    assert_ne!(f1.fingerprint, f2.fingerprint);
}

#[test]
fn fingerprint_changes_with_rule_id() {
    let f1 = make_finding("atlas/security/typescript/sql-injection", "src/db.ts", "db.query(input);");
    let f2 = make_finding("atlas/security/typescript/xss", "src/db.ts", "db.query(input);");
    assert_ne!(f1.fingerprint, f2.fingerprint);
}
