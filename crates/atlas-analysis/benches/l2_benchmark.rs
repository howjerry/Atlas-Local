//! Criterion benchmark for L2 intra-procedural taint analysis.
//!
//! 10.3: 測量 L2 分析一個 ~100 行函數的效能，目標 < 10ms。

use criterion::{Criterion, criterion_group, criterion_main};

use atlas_analysis::l2_engine::L2Engine;
use atlas_lang::Language;

/// 產生一個 ~100 行 TypeScript 函數，含多個 tainted 來源與 sink。
fn generate_100_line_ts_function() -> String {
    let mut lines = Vec::with_capacity(110);
    lines.push("function handler(req, res) {".to_string());

    // 10 個 tainted 來源
    for i in 0..10 {
        lines.push(format!("    const input{i} = req.body.field{i};"));
    }

    // 40 行傳播/賦值
    for i in 0..10 {
        lines.push(format!("    const derived{i} = input{i};"));
        lines.push(format!("    const text{i} = \"prefix\" + derived{i};"));
        lines.push(format!("    const msg{i} = text{i} + \"suffix\";"));
        lines.push(format!("    const payload{i} = msg{i};"));
    }

    // 10 行淨化
    for i in 0..5 {
        lines.push(format!("    const safe{i} = parseInt(input{i});"));
    }
    for i in 5..10 {
        lines.push(format!(
            "    const safe{i} = encodeURIComponent(input{i});"
        ));
    }

    // 10 行 sink 呼叫（混合不同漏洞類型—用於 SAST 測試，非實際執行）
    lines.push("    db.query(payload0);".to_string());
    lines.push("    db.query(payload1);".to_string());
    lines.push("    res.send(payload4);".to_string());
    lines.push("    res.send(payload5);".to_string());
    lines.push("    fs.writeFile(payload6, payload2);".to_string());
    lines.push("    fetch(payload7);".to_string());
    lines.push("    fetch(payload3);".to_string());
    lines.push("    db.query(payload8);".to_string());
    lines.push("    db.query(safe0);".to_string()); // 淨化過，不應觸發
    lines.push("    res.send(safe5);".to_string()); // 淨化過，不應觸發

    // 20 行不相關的安全邏輯填充到 ~100 行
    for i in 0..20 {
        lines.push(format!("    const local{i} = {i} * 2 + 1;"));
    }

    lines.push("}".to_string());
    lines.join("\n")
}

/// Benchmark: L2 分析一個 ~100 行函數。
fn bench_l2_100_line_function(c: &mut Criterion) {
    let source = generate_100_line_ts_function();
    let source_bytes = source.as_bytes();

    // 預先解析 AST
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("failed to set TypeScript language");
    let tree = parser
        .parse(source_bytes, None)
        .expect("failed to parse TypeScript source");

    let engine = L2Engine::new(Language::TypeScript).expect("failed to create L2Engine");

    c.bench_function("l2_analyze_100_line_function", |b| {
        b.iter(|| {
            let findings = engine.analyze_file(&tree, source_bytes, "bench.ts");
            // 確保有產生 findings（防止被最佳化掉）
            std::hint::black_box(&findings);
        })
    });
}

criterion_group!(benches, bench_l2_100_line_function);
criterion_main!(benches);
