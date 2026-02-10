//! Criterion benchmark for metrics engine performance.
//!
//! 6.7: 驗證 100K 行專案的 metrics 計算 < 10 秒。
//! 使用生成的 TypeScript 檔案模擬大型專案。

use criterion::{Criterion, criterion_group, criterion_main};

use atlas_analysis::duplication::{DuplicationDetector, TokenizedFile};
use atlas_analysis::metrics::{MetricsConfig, MetricsEngine};
use atlas_lang::Language;

/// 產生一個含有多個函數的 TypeScript 檔案（~500 行）
///
/// 每個函數包含分支結構，模擬真實程式碼的複雜度
fn generate_ts_file(file_index: usize, functions_per_file: usize) -> String {
    let mut lines = Vec::with_capacity(600);

    for f in 0..functions_per_file {
        lines.push(format!(
            "function file{file_index}_func{f}(a: number, b: string, c: boolean) {{"
        ));
        // if/else 分支
        lines.push("    if (a > 0) {".to_string());
        lines.push("        const result = a * 2;".to_string());
        lines.push("        if (b.length > 5) {".to_string());
        lines.push("            console.log(result);".to_string());
        lines.push("            for (let i = 0; i < a; i++) {".to_string());
        lines.push("                const val = i + result;".to_string());
        lines.push("                if (val > 100) {".to_string());
        lines.push("                    break;".to_string());
        lines.push("                }".to_string());
        lines.push("            }".to_string());
        lines.push("        }".to_string());
        lines.push("    } else {".to_string());
        lines.push("        while (a < 0) {".to_string());
        lines.push("            a = a + 1;".to_string());
        lines.push("        }".to_string());
        lines.push("    }".to_string());

        // switch 分支
        lines.push("    switch (b) {".to_string());
        lines.push("        case \"alpha\":".to_string());
        lines.push("            return 1;".to_string());
        lines.push("        case \"beta\":".to_string());
        lines.push("            return 2;".to_string());
        lines.push("        case \"gamma\":".to_string());
        lines.push("            return 3;".to_string());
        lines.push("        default:".to_string());
        lines.push("            return 0;".to_string());
        lines.push("    }".to_string());
        lines.push("}".to_string());
        lines.push(String::new()); // 空行分隔
    }

    lines.join("\n")
}

/// Benchmark: 200 個檔案 × ~500 行 ≈ 100K 行的 metrics 計算
fn bench_metrics_100k_lines(c: &mut Criterion) {
    let files_count = 200;
    let functions_per_file = 18; // 每個函數 ~28 行，18 × 28 ≈ 504 行/檔

    // 預先產生所有檔案的原始碼
    let sources: Vec<String> = (0..files_count)
        .map(|i| generate_ts_file(i, functions_per_file))
        .collect();

    // 預先解析所有 AST
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("設定 TypeScript 語言失敗");

    let trees: Vec<tree_sitter::Tree> = sources
        .iter()
        .map(|src| parser.parse(src.as_bytes(), None).expect("解析失敗"))
        .collect();

    let total_lines: usize = sources.iter().map(|s| s.lines().count()).sum();
    println!(
        "Benchmark 配置: {files_count} 檔案, 每檔 {functions_per_file} 函數, 總計 {total_lines} 行"
    );

    let engine = MetricsEngine::new(MetricsConfig::default());

    // 僅量測 metrics 計算（不含解析和 duplication）
    let mut group = c.benchmark_group("metrics_engine");
    group.sample_size(10); // 大型 benchmark 降低迭代次數

    group.bench_function("compute_file_metrics_100k_lines", |b| {
        b.iter(|| {
            let mut all_metrics = Vec::with_capacity(files_count);
            for (i, (tree, src)) in trees.iter().zip(sources.iter()).enumerate() {
                let path = format!("file_{i}.ts");
                let file_metrics =
                    engine.compute_file_metrics(tree, src, Language::TypeScript, &path);
                if let Some(m) = file_metrics {
                    all_metrics.push(m);
                }
            }
            std::hint::black_box(&all_metrics);
        })
    });

    group.finish();
}

/// Benchmark: 重複偵測在 10K 行規模上的效能
///
/// 註：Rabin-Karp 跨檔案比對在 100K 行規模下耗時較長（~280s），
/// 此處使用 20 檔 × ~500 行 ≈ 10K 行進行基準量測。
fn bench_duplication_10k_lines(c: &mut Criterion) {
    let files_count = 20;
    let functions_per_file = 18;

    // 產生檔案（部分重複以測試偵測）
    let mut sources: Vec<String> = (0..files_count)
        .map(|i| generate_ts_file(i, functions_per_file))
        .collect();

    // 讓 2 個檔案與其他重複
    sources[18] = sources[0].clone();
    sources[19] = sources[1].clone();

    // 預先解析 AST 並 tokenize
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("設定 TypeScript 語言失敗");

    let tokenized_files: Vec<TokenizedFile> = sources
        .iter()
        .enumerate()
        .map(|(i, src)| {
            let tree = parser.parse(src.as_bytes(), None).expect("解析失敗");
            let path = format!("file_{i}.ts");
            DuplicationDetector::tokenize_file(&tree, src, &path)
        })
        .collect();

    let total_lines: usize = sources.iter().map(|s| s.lines().count()).sum();
    println!("Duplication benchmark 配置: {files_count} 檔案, 總計 {total_lines} 行");

    let detector = DuplicationDetector::new(100);

    let mut group = c.benchmark_group("duplication_detection");
    group.sample_size(10);

    group.bench_function("detect_duplicates_10k_lines", |b| {
        b.iter(|| {
            let result = detector.detect(&tokenized_files);
            std::hint::black_box(&result);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_metrics_100k_lines, bench_duplication_10k_lines);
criterion_main!(benches);
