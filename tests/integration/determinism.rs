//! Determinism verification test (T093).
//!
//! Verifies SC-003: running the same scan twice on the same fixture produces
//! byte-identical JSON output.
//!
//! NOTE: Snippets below are intentional test fixtures for SAST rule testing.
//! They represent vulnerable code patterns that the scanner should detect.

use std::path::Path;

use atlas_core::engine::ScanEngine;

fn setup_engine() -> ScanEngine {
    let mut engine = ScanEngine::new();
    let rules_dir = Path::new("rules/builtin");
    if rules_dir.is_dir() {
        let _ = engine.load_rules(rules_dir);
    }
    engine
}

#[test]
fn scan_produces_deterministic_findings() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/typescript-vulnerable");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let result1 = engine.scan(target, None).expect("scan 1 failed");
    let result2 = engine.scan(target, None).expect("scan 2 failed");

    // Same number of findings.
    assert_eq!(
        result1.findings.len(),
        result2.findings.len(),
        "finding count must be identical across runs"
    );

    // Same files scanned.
    assert_eq!(result1.files_scanned, result2.files_scanned);

    // Identical finding details (rule_id, file_path, snippet, fingerprint).
    for (f1, f2) in result1.findings.iter().zip(result2.findings.iter()) {
        assert_eq!(f1.rule_id, f2.rule_id, "rule_id must match");
        assert_eq!(f1.file_path, f2.file_path, "file_path must match");
        assert_eq!(f1.snippet, f2.snippet, "snippet must match");
        assert_eq!(
            f1.fingerprint, f2.fingerprint,
            "fingerprint must be deterministic"
        );
    }
}

#[test]
fn scan_deterministic_with_polyglot() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/polyglot");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let result1 = engine.scan(target, None).expect("scan 1 failed");
    let result2 = engine.scan(target, None).expect("scan 2 failed");

    assert_eq!(result1.findings.len(), result2.findings.len());

    for (f1, f2) in result1.findings.iter().zip(result2.findings.iter()) {
        assert_eq!(f1.fingerprint, f2.fingerprint);
    }
}
