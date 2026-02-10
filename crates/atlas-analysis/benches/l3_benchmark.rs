//! Criterion benchmark for L3 inter-procedural taint analysis.
//!
//! 10.4: 測量 L3 分析 500 函數專案的效能，目標 max_depth=5 在 30 秒內完成。

use criterion::{Criterion, criterion_group, criterion_main};

use atlas_analysis::l2_taint_config::load_taint_config;
use atlas_analysis::l3_engine::{L3Engine, ParsedFile};
use atlas_lang::Language;

/// 產生一個 500 函數的 TypeScript 專案。
/// 結構：50 個 entry points，每個串聯 9 層呼叫，共 500 函數。
fn generate_500_function_project() -> String {
    let mut lines = Vec::with_capacity(3000);

    for chain in 0..50 {
        // entry point：從 req.body 取得 tainted 資料
        lines.push(format!(
            "function entry{chain}(req) {{\n    const data = req.body.field{chain};\n    func{chain}_1(data);\n}}"
        ));

        // 中間層函數：傳遞 tainted 參數
        for depth in 1..9 {
            lines.push(format!(
                "function func{chain}_{depth}(p) {{\n    func{chain}_{}(p);\n}}",
                depth + 1
            ));
        }

        // 最深層函數：包含 sink
        lines.push(format!(
            "function func{chain}_9(v) {{\n    db.query(v);\n}}"
        ));
    }

    lines.join("\n\n")
}

/// Benchmark: L3 分析 500 函數專案。
fn bench_l3_500_functions(c: &mut Criterion) {
    let source = generate_500_function_project();
    let source_bytes = source.as_bytes();

    // 預先解析 AST
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("failed to set TypeScript language");
    let tree = parser
        .parse(source_bytes, None)
        .expect("failed to parse TypeScript source");

    let taint_config = load_taint_config(Language::TypeScript)
        .expect("failed to load TypeScript taint config");
    let engine = L3Engine::new(Language::TypeScript, taint_config, 5);

    let mut group = c.benchmark_group("l3_interprocedural");
    group.sample_size(10); // 減少取樣數以加速 benchmark run
    group.measurement_time(std::time::Duration::from_secs(30));

    group.bench_function("l3_analyze_500_functions_depth5", |b| {
        b.iter(|| {
            let files = [ParsedFile {
                file_path: "project.ts",
                source: source_bytes,
                tree: &tree,
            }];
            let findings = engine.analyze_project(&files);
            std::hint::black_box(&findings);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_l3_500_functions);
criterion_main!(benches);
