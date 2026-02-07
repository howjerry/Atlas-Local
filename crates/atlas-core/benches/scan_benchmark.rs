//! Criterion benchmark suite for Atlas Local SAST (T099).
//!
//! Measures L1 scan performance against reference fixtures.
//! SLA target (SC-002): 100K LOC scanned in under 30 seconds.
//!
//! Run with: `cargo bench`

use criterion::{Criterion, criterion_group, criterion_main};
use std::path::Path;

use atlas_core::engine::ScanEngine;

/// Sets up a scan engine with built-in rules loaded.
fn setup_engine() -> ScanEngine {
    let mut engine = ScanEngine::new();
    let rules_dir = Path::new("rules/builtin");
    if rules_dir.is_dir() {
        let _ = engine.load_rules(rules_dir);
    }
    engine
}

/// Benchmark: scan the small TypeScript fixture (~100 LOC).
fn bench_scan_small(c: &mut Criterion) {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/typescript-vulnerable");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    c.bench_function("scan_small_fixture", |b| {
        b.iter(|| {
            let _ = engine.scan(target, None);
        })
    });
}

/// Benchmark: scan the polyglot fixture (multiple languages).
fn bench_scan_polyglot(c: &mut Criterion) {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/polyglot");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    c.bench_function("scan_polyglot_fixture", |b| {
        b.iter(|| {
            let _ = engine.scan(target, None);
        })
    });
}

/// Benchmark: scan the secrets fixture.
fn bench_scan_secrets(c: &mut Criterion) {
    let engine = setup_engine();
    let target = Path::new("tests/fixtures/secrets");

    if !target.is_dir() {
        eprintln!("Fixture not found: {}", target.display());
        return;
    }

    c.bench_function("scan_secrets_fixture", |b| {
        b.iter(|| {
            let _ = engine.scan(target, None);
        })
    });
}

criterion_group!(
    benches,
    bench_scan_small,
    bench_scan_polyglot,
    bench_scan_secrets
);
criterion_main!(benches);
