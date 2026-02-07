//! Quickstart validation test (T092).
//!
//! Verifies that the core CLI commands documented in quickstart.md work
//! as expected end-to-end. Tests the scan command with various flags.
//!
//! NOTE: This test exercises the library API equivalent of CLI commands,
//! since integration tests cannot easily invoke the binary with all flags.

use std::path::Path;

use atlas_core::engine::{ScanEngine, ScanOptions};

fn setup_engine() -> ScanEngine {
    let mut engine = ScanEngine::new();
    let rules_dir = Path::new("rules/builtin");
    if rules_dir.is_dir() {
        let _ = engine.load_rules(rules_dir);
    }
    engine
}

/// Validates: `atlas scan <target>` (basic scan).
#[test]
fn quickstart_basic_scan() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/typescript-vulnerable");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let result = engine.scan(target, None).expect("basic scan must succeed");
    assert!(result.files_scanned > 0);
}

/// Validates: `atlas scan <target> --lang typescript` (language filter).
#[test]
fn quickstart_scan_with_language_filter() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/polyglot");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let ts_only = &[atlas_core::Language::TypeScript];
    let result = engine
        .scan(target, Some(ts_only))
        .expect("filtered scan must succeed");

    // Should only scan TypeScript files.
    for lang in &result.languages_detected {
        assert_eq!(*lang, atlas_core::Language::TypeScript);
    }
}

/// Validates: `atlas scan <target> --jobs 2` (parallel execution).
#[test]
fn quickstart_scan_with_jobs() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/typescript-vulnerable");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let options = ScanOptions {
        jobs: Some(2),
        ..Default::default()
    };
    let result = engine
        .scan_with_options(target, None, &options)
        .expect("parallel scan must succeed");
    assert!(result.files_scanned > 0);
}

/// Validates: `atlas scan <target> --no-cache` (cache bypass).
#[test]
fn quickstart_scan_no_cache() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/typescript-vulnerable");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let options = ScanOptions {
        no_cache: true,
        ..Default::default()
    };
    let result = engine
        .scan_with_options(target, None, &options)
        .expect("no-cache scan must succeed");
    assert!(result.files_scanned > 0);
    // cache_hit_rate should be None when cache is disabled.
    assert!(result.stats.cache_hit_rate.is_none());
}

/// Validates scan result includes summary (T089 integration).
#[test]
fn quickstart_scan_includes_summary() {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/typescript-vulnerable");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    let result = engine.scan(target, None).expect("scan must succeed");
    // Summary total must equal findings count.
    assert_eq!(result.summary.total as usize, result.findings.len());
    // Stats must include duration.
    assert!(result.stats.duration_ms < 60_000, "scan should complete within 60s");
}
