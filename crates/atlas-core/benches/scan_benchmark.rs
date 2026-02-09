//! Criterion benchmark suite for Atlas Local SAST (T099).
//!
//! Measures L1 scan performance against reference fixtures.
//! SLA target (SC-002): 100K LOC scanned in under 30 seconds.
//! 10.4: L1 vs L2 掃描效能比較，目標 < 50% overhead。
//!
//! Run with: `cargo bench`

use criterion::{Criterion, criterion_group, criterion_main};
use std::fs;
use std::path::Path;

use atlas_core::engine::{ScanEngine, ScanOptions};
use atlas_core::AnalysisLevel;

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

/// 在臨時目錄中產生 100 個 TypeScript 檔案，每個含有一個函數。
fn create_100_file_project() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    for i in 0..100 {
        let content = format!(
            r#"function handler{i}(req: any) {{
    const name = req.body.field{i};
    const derived = name;
    const result = derived + "suffix";
    console.log(result);
    db.query(result);
}}
"#
        );
        let file_path = tmp.path().join(format!("file{i}.ts"));
        fs::write(&file_path, content).expect("failed to write fixture file");
    }
    tmp
}

/// Benchmark: L1-only vs L2 scan on a 100-file project.
fn bench_l1_vs_l2_scan(c: &mut Criterion) {
    let engine = setup_engine();
    let tmp = create_100_file_project();
    let target = tmp.path();

    let l1_options = ScanOptions {
        analysis_level: AnalysisLevel::L1,
        ..Default::default()
    };

    let l2_options = ScanOptions {
        analysis_level: AnalysisLevel::L2,
        ..Default::default()
    };

    let mut group = c.benchmark_group("l1_vs_l2_100_files");

    group.bench_function("l1_only", |b| {
        b.iter(|| {
            let result = engine
                .scan_with_options(target, None, &l1_options)
                .expect("L1 scan failed");
            std::hint::black_box(&result);
        })
    });

    group.bench_function("l2_enabled", |b| {
        b.iter(|| {
            let result = engine
                .scan_with_options(target, None, &l2_options)
                .expect("L2 scan failed");
            std::hint::black_box(&result);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_scan_small,
    bench_scan_polyglot,
    bench_scan_secrets,
    bench_l1_vs_l2_scan
);
criterion_main!(benches);
