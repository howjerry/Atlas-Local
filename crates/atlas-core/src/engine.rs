//! Scan pipeline orchestrator for Atlas Local SAST.
//!
//! The [`ScanEngine`] coordinates the full scan pipeline:
//!
//! 1. **Discover** source files in the target directory.
//! 2. **Parse** each file using the appropriate language adapter.
//! 3. **Analyse** each parsed file against matching L1 rules.
//! 4. **Collect** findings, sort deterministically, and return a [`ScanResult`].
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use atlas_core::engine::{ScanEngine, ScanOptions};
//!
//! let mut engine = ScanEngine::new();
//! engine.load_rules(Path::new("rules/")).unwrap();
//!
//! // Simple scan with defaults:
//! let result = engine.scan(Path::new("src/"), None).unwrap();
//!
//! // Scan with custom options (4 threads, 2 MiB max file size):
//! let options = ScanOptions { jobs: Some(4), max_file_size_kb: 2048, ..Default::default() };
//! let result = engine.scan_with_options(Path::new("src/"), None, &options).unwrap();
//! println!("Found {} findings in {} files", result.findings.len(), result.files_scanned);
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use atlas_analysis::{DiffStatus, Finding, FindingBuilder, L1PatternEngine, LineRange, RuleMatchMetadata};
use atlas_analysis::l2_engine::L2Engine;
use atlas_analysis::l2_taint_config::{load_custom_taint_config, load_taint_config, merge_taint_config};
use atlas_analysis::l3_engine::{L3Engine, ParsedFile};
use atlas_analysis::l3_lang_config::get_l3_config;
use atlas_analysis::metrics::{FileMetricsData, MetricsConfig, MetricsEngine};
use atlas_analysis::duplication::{DuplicationDetector, DuplicationResult, TokenizedFile};
use atlas_cache::cache::{CacheConfig, ResultCache};
use atlas_lang::{
    AdapterRegistry, register_csharp_adapter, register_go_adapter, register_java_adapter,
    register_js_ts_adapters, register_kotlin_adapter, register_php_adapter,
    register_python_adapter, register_ruby_adapter,
};
use atlas_rules::declarative::DeclarativeRuleLoader;
use atlas_rules::Rule;

/// 從重複偵測產生的最大 Finding 數量上限
const MAX_DUPLICATION_FINDINGS: usize = 50;

use crate::AnalysisLevel;
use crate::{Category, Confidence, Severity};

use crate::diff::DiffContext;
use crate::scanner::{discover_files_with_options};
use crate::{CoreError, Language};

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

/// The result of running a scan across a target directory.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// All findings, sorted deterministically by
    /// `(file_path, start_line, start_col, rule_id)`.
    pub findings: Vec<Finding>,
    /// Number of files that were successfully scanned.
    pub files_scanned: u32,
    /// Number of files that were skipped (read errors, parse failures, etc.).
    pub files_skipped: u32,
    /// Languages detected across all scanned files.
    pub languages_detected: Vec<Language>,
    /// Summary of findings by severity (T089).
    pub summary: FindingsSummary,
    /// Timing and performance statistics (T089).
    pub stats: ScanStats,
    /// 每個檔案的品質 metrics 資料（僅在 `--metrics` 啟用時填充）。
    pub file_metrics: Vec<FileMetricsData>,
    /// 程式碼重複檢測結果（僅在 `--metrics` 啟用時填充）。
    pub duplication: Option<DuplicationResult>,
}

// ---------------------------------------------------------------------------
// FindingsSummary  (T089)
// ---------------------------------------------------------------------------

/// Summary of findings grouped by severity.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FindingsSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub total: u32,
}

impl FindingsSummary {
    /// Computes a summary from a list of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for f in findings {
            match f.severity {
                crate::Severity::Critical => summary.critical += 1,
                crate::Severity::High => summary.high += 1,
                crate::Severity::Medium => summary.medium += 1,
                crate::Severity::Low => summary.low += 1,
                crate::Severity::Info => summary.info += 1,
            }
            summary.total += 1;
        }
        summary
    }
}

// ---------------------------------------------------------------------------
// ScanStats  (T089)
// ---------------------------------------------------------------------------

/// Timing and performance statistics for a scan.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ScanStats {
    /// Total scan duration in milliseconds.
    pub duration_ms: u64,
    /// Number of parse failures.
    pub parse_failures: u32,
    /// Cache hit rate (0.0 - 1.0), if caching is enabled.
    pub cache_hit_rate: Option<f64>,
}

// ---------------------------------------------------------------------------
// ScanOptions
// ---------------------------------------------------------------------------

/// Options controlling scan behaviour.
///
/// Pass this to [`ScanEngine::scan`] to configure parallelism and file-size
/// limits. Use [`Default::default()`] for sensible defaults.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum file size in KiB. Files larger than this are skipped.
    /// Defaults to `1024` (1 MiB).
    pub max_file_size_kb: u64,
    /// Number of parallel threads for file processing.
    /// `None` means use rayon's default (all available cores).
    pub jobs: Option<usize>,
    /// If `true`, skip the result cache entirely.
    pub no_cache: bool,
    /// Git diff context for diff-aware scanning.
    /// When set (and not fallback), only changed files are scanned.
    pub diff_context: Option<DiffContext>,
    /// 分析深度等級。預設 L1（僅 AST 模式比對），L2 啟用 intra-procedural 資料流分析。
    pub analysis_level: AnalysisLevel,
    /// Glob 排除模式。匹配的檔案在 discovery 階段被排除。
    pub exclude_patterns: Vec<String>,
    /// 是否追蹤符號連結。
    pub follow_symlinks: bool,
    /// 快取資料庫目錄路徑。
    pub cache_dir: Option<std::path::PathBuf>,
    /// 是否計算程式碼品質 metrics（cyclomatic/cognitive complexity、duplication、LOC）。
    /// 預設 false（opt-in via `--metrics`）。
    pub compute_metrics: bool,
    /// 從 policy YAML 讀取的 metrics 閾值配置。
    /// 設定時覆蓋 `MetricsConfig::default()` 的對應欄位。
    pub metrics_config: Option<MetricsConfig>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size_kb: 1024,
            jobs: None,
            no_cache: false,
            diff_context: None,
            analysis_level: AnalysisLevel::L1,
            exclude_patterns: Vec::new(),
            follow_symlinks: true,
            cache_dir: None,
            compute_metrics: false,
            metrics_config: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ScanEngine
// ---------------------------------------------------------------------------

/// The scan pipeline orchestrator.
///
/// Holds registered language adapters and loaded rules. Call [`scan`](Self::scan)
/// to run the full pipeline against a target directory.
pub struct ScanEngine {
    /// Registry of language adapters for parsing source files.
    adapter_registry: AdapterRegistry,
    /// Loaded SAST rules to evaluate against parsed files.
    rules: Vec<Rule>,
}

impl ScanEngine {
    /// Creates a new `ScanEngine` with TypeScript, JavaScript, Java,
    /// Python, C#, and Go adapters pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = AdapterRegistry::new();
        register_js_ts_adapters(&mut registry);
        register_java_adapter(&mut registry);
        register_python_adapter(&mut registry);
        register_csharp_adapter(&mut registry);
        register_go_adapter(&mut registry);
        register_ruby_adapter(&mut registry);
        register_php_adapter(&mut registry);
        register_kotlin_adapter(&mut registry);
        Self {
            adapter_registry: registry,
            rules: Vec::new(),
        }
    }

    /// Loads declarative rules from a directory of YAML files.
    ///
    /// This walks the directory recursively, loading all `.yaml` and `.yml`
    /// files as declarative (L1) rules. The rules are appended to any
    /// previously loaded rules.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RuleEvaluation`] if rule loading fails (I/O,
    /// YAML parsing, or validation errors).
    pub fn load_rules(&mut self, rules_dir: &Path) -> Result<(), CoreError> {
        let loader = DeclarativeRuleLoader;
        let loaded = loader
            .load_from_dir(rules_dir)
            .map_err(|e| CoreError::RuleEvaluation(e.to_string()))?;
        info!(count = loaded.len(), dir = %rules_dir.display(), "loaded declarative rules");
        self.rules.extend(loaded);
        Ok(())
    }

    /// Adds rules directly (useful for testing or programmatic rule creation).
    pub fn add_rules(&mut self, rules: Vec<Rule>) {
        self.rules.extend(rules);
    }

    /// Returns a reference to the loaded rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Runs the full scan pipeline against the given `target` directory.
    ///
    /// # Pipeline
    ///
    /// 1. Discover source files (respecting `.gitignore`, `.atlasignore`, etc.).
    /// 2. For each discovered file (processed **in parallel** via rayon):
    ///    a. Look up the language adapter from the registry.
    ///    b. Read the file content; skip files exceeding `max_file_size_kb`.
    ///    c. Validate UTF-8 encoding; skip non-UTF-8 files with a warning.
    ///    d. Parse with the adapter to get a tree-sitter `Tree`.
    ///    e. For each rule matching the file's language:
    ///       - Compile an `L1PatternEngine` with the rule's pattern.
    ///       - Evaluate the pattern against the tree.
    ///       - Collect any findings.
    /// 3. Sort all findings deterministically.
    /// 4. Return a [`ScanResult`].
    ///
    /// # Parallelism
    ///
    /// File processing uses rayon's parallel iterators. The number of threads
    /// is controlled by [`ScanOptions::jobs`]:
    /// - `None` — rayon default (all available cores).
    /// - `Some(n)` — use exactly `n` threads.
    ///
    /// # Error handling
    ///
    /// - Files that cannot be read are logged at WARN level and skipped.
    /// - Files larger than `max_file_size_kb` KiB are logged and skipped.
    /// - Non-UTF-8 files are logged at WARN level and skipped.
    /// - Files that fail to parse are logged at WARN level and skipped.
    /// - Rules whose patterns fail to compile are logged at WARN level and
    ///   skipped for that file.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if file discovery itself fails (e.g. the target
    /// directory does not exist).
    pub fn scan(
        &self,
        target: &Path,
        language_filter: Option<&[Language]>,
    ) -> Result<ScanResult, CoreError> {
        self.scan_with_options(target, language_filter, &ScanOptions::default())
    }

    /// Like [`scan`](Self::scan), but accepts [`ScanOptions`] for fine-grained
    /// control over parallelism and file-size limits.
    pub fn scan_with_options(
        &self,
        target: &Path,
        language_filter: Option<&[Language]>,
        options: &ScanOptions,
    ) -> Result<ScanResult, CoreError> {
        let scan_start = std::time::Instant::now();

        // Step 1: Discover files（套用 exclude_patterns 和 follow_symlinks 設定）。
        let mut discovery = discover_files_with_options(
            target,
            language_filter,
            &options.exclude_patterns,
            options.follow_symlinks,
        )?;
        info!(
            files = discovery.files.len(),
            languages = ?discovery.languages_detected,
            "file discovery complete"
        );

        // Step 1b: Filter to changed files if diff context is active.
        let diff_ctx = options.diff_context.as_ref();
        if let Some(dc) = diff_ctx {
            if !dc.is_fallback {
                let total_files = discovery.files.len();
                let changed_paths = dc.changed_paths();
                discovery
                    .files
                    .retain(|f| changed_paths.contains(f.relative_path.as_str()));

                let changed_count = discovery.files.len();
                info!(
                    changed = changed_count,
                    total = total_files,
                    "diff-aware file filtering applied"
                );

                if changed_count == 0 {
                    info!("No changed files to scan");
                    return Ok(ScanResult {
                        findings: Vec::new(),
                        files_scanned: 0,
                        files_skipped: 0,
                        languages_detected: Vec::new(),
                        summary: FindingsSummary::default(),
                        stats: ScanStats {
                            duration_ms: scan_start.elapsed().as_millis() as u64,
                            parse_failures: 0,
                            cache_hit_rate: None,
                        },
                        file_metrics: Vec::new(),
                        duplication: None,
                    });
                }

                // Log suggestion if diff covers >80% of files.
                if total_files > 0
                    && (changed_count as f64 / total_files as f64) > 0.8
                {
                    warn!("Consider running a full scan for comprehensive coverage");
                }
            }
        }

        let max_file_bytes = options.max_file_size_kb * 1024;

        // Pre-compile L1 queries once per rule (not per file).
        let query_cache = self.precompile_queries();
        info!(
            cached = query_cache.len(),
            total_rules = self.rules.len(),
            "L1 query pre-compilation complete"
        );

        // 計算 rules version hash（用於快取 key 和 invalidation）。
        let rules_hash = self.compute_rules_hash();

        // 開啟結果快取（SQLite Connection 非 Send，不能在 rayon 內使用）。
        let result_cache = if !options.no_cache {
            self.open_result_cache(options.cache_dir.as_deref(), &rules_hash)
        } else {
            None
        };

        // 快取 lookup：序列讀檔、算 key、查快取。
        // 命中的直接收集 findings，未命中的送入平行處理。
        let mut cached_findings: Vec<Finding> = Vec::new();
        let mut uncached_files: Vec<(usize, String)> = Vec::new(); // (index, cache_key)
        let mut cache_hits: u32 = 0;
        let mut cache_misses: u32 = 0;

        for (idx, discovered) in discovery.files.iter().enumerate() {
            if let Some(ref cache) = result_cache {
                // 讀檔計算 cache key。
                if let Ok(content) = std::fs::read(&discovered.path) {
                    let cache_key = ResultCache::compute_key(
                        &content,
                        &rules_hash,
                        &format!("{}", options.analysis_level.depth()),
                    );
                    match cache.get(&cache_key) {
                        Ok(Some(data)) => {
                            // 快取命中：反序列化 findings。
                            if let Ok(findings) = serde_json::from_slice::<Vec<Finding>>(&data) {
                                cache_hits += 1;
                                cached_findings.extend(findings);
                                continue;
                            }
                            // 反序列化失敗 → 當作 miss。
                        }
                        Ok(None) => {}
                        Err(e) => {
                            debug!(error = %e, "cache lookup error; treating as miss");
                        }
                    }
                    cache_misses += 1;
                    uncached_files.push((idx, cache_key));
                } else {
                    // 檔案讀取失敗，稍後 process_file 會處理。
                    uncached_files.push((idx, String::new()));
                }
            } else {
                uncached_files.push((idx, String::new()));
            }
        }

        if result_cache.is_some() {
            info!(
                cache_hits,
                cache_misses,
                "result cache lookup complete"
            );
        }

        // Shared counters for parallel processing.
        let files_scanned = AtomicU32::new(cache_hits);
        let files_skipped = AtomicU32::new(0);
        let parse_failures = AtomicU32::new(0);

        // Build a rayon thread pool with the requested number of threads.
        let pool = {
            let mut builder = rayon::ThreadPoolBuilder::new();
            if let Some(n) = options.jobs {
                builder = builder.num_threads(n);
            }
            builder
                .build()
                .map_err(|e| CoreError::Config(format!("failed to build thread pool: {e}")))?
        };

        let analysis_level = options.analysis_level;

        // 建立 Metrics Engine（僅在 --metrics 啟用時）
        // 若 policy 有提供 metrics_config，用它覆蓋預設值。
        let metrics_engine = if options.compute_metrics {
            let config = if let Some(ref override_cfg) = options.metrics_config {
                override_cfg.clone()
            } else {
                MetricsConfig::default()
            };
            Some(MetricsEngine::new(config))
        } else {
            None
        };

        // Step 2: Process uncached files in parallel.
        let processed_results: Vec<(usize, Vec<Finding>, Option<FileMetricsData>)> = pool.install(|| {
            uncached_files
                .par_iter()
                .map(|(idx, _cache_key)| {
                    let discovered = &discovery.files[*idx];
                    let (findings, file_metrics) = self.process_file(
                        discovered,
                        max_file_bytes,
                        &query_cache,
                        &files_scanned,
                        &files_skipped,
                        &parse_failures,
                        diff_ctx,
                        analysis_level,
                        metrics_engine.as_ref(),
                    );
                    (*idx, findings, file_metrics)
                })
                .collect()
        });

        // 寫入快取（序列操作）— 僅快取 findings，metrics 不快取。
        if let Some(ref cache) = result_cache {
            let uncached_map: HashMap<usize, &str> = uncached_files
                .iter()
                .map(|(idx, key)| (*idx, key.as_str()))
                .collect();
            for (idx, findings, _) in &processed_results {
                if let Some(cache_key) = uncached_map.get(idx) {
                    if !cache_key.is_empty() {
                        if let Ok(data) = serde_json::to_vec(findings) {
                            if let Err(e) = cache.put(cache_key, &data) {
                                debug!(error = %e, "failed to write cache entry");
                            }
                        }
                    }
                }
            }
        }

        // 合併 cached + processed findings 並收集 per-file metrics。
        let mut all_findings = cached_findings;
        let mut all_file_metrics: Vec<FileMetricsData> = Vec::new();
        for (_idx, findings, file_metrics) in processed_results {
            all_findings.extend(findings);
            if let Some(fm) = file_metrics {
                all_file_metrics.push(fm);
            }
        }

        // Step 2c: Duplication detection（跨檔案比對，需要在所有檔案處理完後執行）
        // 僅在 --metrics 啟用時執行。
        let duplication_result = if options.compute_metrics {
            let tokenized_files: Vec<TokenizedFile> = discovery
                .files
                .iter()
                .filter_map(|discovered| {
                    // 跳過自動產生的檔案以避免重複偵測爆炸
                    if is_autogenerated_for_duplication(&discovered.relative_path) {
                        return None;
                    }
                    let adapter = self.adapter_registry.get_by_language(discovered.language)?;
                    let source = std::fs::read(&discovered.path).ok()?;
                    let source_str = std::str::from_utf8(&source).ok()?;
                    let tree = adapter.parse(&source).ok()?;
                    Some(DuplicationDetector::tokenize_file(
                        &tree,
                        source_str,
                        &discovered.relative_path,
                    ))
                })
                .collect();

            if !tokenized_files.is_empty() {
                let detector = DuplicationDetector::new(
                    metrics_engine.as_ref().map_or(100, |e| e.config().min_tokens),
                );
                let dup_result = detector.detect(&tokenized_files);
                info!(
                    blocks = dup_result.blocks.len(),
                    percentage = format!("{:.1}%", dup_result.duplication_percentage),
                    "duplication detection complete"
                );
                Some(dup_result)
            } else {
                None
            }
        } else {
            None
        };

        // Step 2b: 將重複偵測結果轉換為 Finding，使其參與 gate 評估。
        if let Some(ref dup_result) = duplication_result {
            for block in dup_result.blocks.iter().take(MAX_DUPLICATION_FINDINGS) {
                if let Ok(line_range) = LineRange::new(
                    block.line_range_a.0 as u32,
                    0,
                    block.line_range_a.1 as u32,
                    0,
                ) {
                    let snippet = format!(
                        "重複區塊: {} 行, {} tokens (與 {} 第 {}-{} 行重複)",
                        block.line_count,
                        block.token_count,
                        block.file_b,
                        block.line_range_b.0,
                        block.line_range_b.1
                    );
                    if let Ok(finding) = FindingBuilder::new()
                        .rule_id("atlas/metrics/code-duplication")
                        .file_path(&block.file_a)
                        .severity(Severity::Low)
                        .category(Category::Metrics)
                        .confidence(Confidence::High)
                        .analysis_level(AnalysisLevel::L1)
                        .line_range(line_range)
                        .description(format!(
                            "發現重複程式碼區塊 ({} 行, {} tokens)，與 {} 的 {}-{} 行重複",
                            block.line_count,
                            block.token_count,
                            block.file_b,
                            block.line_range_b.0,
                            block.line_range_b.1
                        ))
                        .remediation("將重複的程式碼提取為獨立函數或模組以提高維護性")
                        .snippet(&snippet)
                        .meta("token_count", serde_json::json!(block.token_count))
                        .meta("line_count", serde_json::json!(block.line_count))
                        .meta("duplicate_file", serde_json::json!(block.file_b))
                        .meta(
                            "duplicate_line_range",
                            serde_json::json!({
                                "start": block.line_range_b.0,
                                "end": block.line_range_b.1
                            }),
                        )
                        .build()
                    {
                        all_findings.push(finding);
                    }
                }
            }
        }

        // Step 2d: L3 inter-procedural taint analysis（跨函數分析，需所有檔案處理完畢後執行）
        if analysis_level.depth() >= 3 {
            let l3_findings = self.run_l3_analysis(&discovery, target);
            if !l3_findings.is_empty() {
                info!(count = l3_findings.len(), "L3 inter-procedural findings");
            }
            all_findings.extend(l3_findings);
        }

        // Step 3: Sort findings deterministically.
        all_findings.sort();

        let scanned = files_scanned.load(Ordering::Relaxed);
        let skipped = files_skipped.load(Ordering::Relaxed);
        let parse_fail_count = parse_failures.load(Ordering::Relaxed);

        let languages_detected: Vec<Language> = discovery.languages_detected.into_iter().collect();

        let total_cacheable = cache_hits + cache_misses;
        let cache_hit_rate = if result_cache.is_some() && total_cacheable > 0 {
            Some(cache_hits as f64 / total_cacheable as f64)
        } else if result_cache.is_some() {
            Some(0.0)
        } else {
            None
        };

        info!(
            findings = all_findings.len(),
            files_scanned = scanned,
            files_skipped = skipped,
            parse_failures = parse_fail_count,
            ?cache_hit_rate,
            "scan complete"
        );

        // Step 6: Compute summary and stats.
        let summary = FindingsSummary::from_findings(&all_findings);
        let duration_ms = scan_start.elapsed().as_millis() as u64;
        let stats = ScanStats {
            duration_ms,
            parse_failures: parse_fail_count,
            cache_hit_rate,
        };

        // Step 7: Return result.
        Ok(ScanResult {
            findings: all_findings,
            files_scanned: scanned,
            files_skipped: skipped,
            languages_detected,
            summary,
            stats,
            file_metrics: all_file_metrics,
            duplication: duplication_result,
        })
    }

    /// L3 跨函數污染分析 — 按語言分組，重新解析檔案並執行 L3 引擎。
    fn run_l3_analysis(
        &self,
        discovery: &crate::scanner::DiscoveryResult,
        scan_dir: &Path,
    ) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        // 載入自訂 taint config（若存在）
        let custom_config = match load_custom_taint_config(scan_dir) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to load custom taint config");
                None
            }
        };

        // 按語言分組檔案
        let mut files_by_lang: HashMap<Language, Vec<&crate::scanner::DiscoveredFile>> =
            HashMap::new();
        for file in &discovery.files {
            // 只處理 L3 支援的語言
            if get_l3_config(file.language).is_some() {
                files_by_lang
                    .entry(file.language)
                    .or_default()
                    .push(file);
            }
        }

        for (language, lang_files) in &files_by_lang {
            // 載入 taint config
            let builtin_config = match load_taint_config(*language) {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "failed to load taint config for L3");
                    continue;
                }
            };

            // 合併自訂配置
            let (taint_config, custom_depth) = if let Some(ref custom) = custom_config {
                merge_taint_config(builtin_config, custom.clone())
            } else {
                (builtin_config, None)
            };
            let max_depth = custom_depth.unwrap_or(5);

            let engine = L3Engine::new(*language, taint_config, max_depth);

            // 讀取並解析所有檔案
            let adapter = match self.adapter_registry.get_by_language(*language) {
                Some(a) => a,
                None => continue,
            };

            let mut parsed: Vec<(String, Vec<u8>, tree_sitter::Tree)> = Vec::new();
            for file in lang_files {
                let source = match std::fs::read(&file.path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let tree = match adapter.parse(&source) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                parsed.push((file.relative_path.clone(), source, tree));
            }

            // 建構 ParsedFile 引用
            let parsed_files: Vec<ParsedFile<'_>> = parsed
                .iter()
                .map(|(path, source, tree)| ParsedFile {
                    file_path: path,
                    source,
                    tree,
                })
                .collect();

            let findings = engine.analyze_project(&parsed_files);
            debug!(
                language = %language,
                count = findings.len(),
                "L3 analysis complete"
            );
            all_findings.extend(findings);
        }

        all_findings
    }

    /// Pre-compiles tree-sitter queries for all L1 declarative rules.
    ///
    /// Returns a map from rule ID to compiled `L1PatternEngine`. Rules that
    /// fail to compile are logged at WARN level and excluded from the cache.
    fn precompile_queries(&self) -> HashMap<String, L1PatternEngine> {
        let mut cache = HashMap::new();
        for rule in &self.rules {
            if rule.analysis_level != AnalysisLevel::L1 {
                continue;
            }
            let pattern = match &rule.pattern {
                Some(p) => p,
                None => continue,
            };
            let adapter = match self.adapter_registry.get_by_language(rule.language) {
                Some(a) => a,
                None => continue,
            };
            let ts_lang = adapter.tree_sitter_language();
            match L1PatternEngine::new(&ts_lang, pattern) {
                Ok(engine) => {
                    cache.insert(rule.id.clone(), engine);
                }
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        error = %e,
                        "failed to pre-compile rule pattern; rule will be skipped during scan"
                    );
                }
            }
        }
        cache
    }

    /// 計算所有已載入規則的版本雜湊，用於快取 invalidation。
    fn compute_rules_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for rule in &self.rules {
            hasher.update(rule.id.as_bytes());
            hasher.update(rule.version.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// 嘗試開啟結果快取。僅在明確指定 `cache_dir` 時啟用。
    /// 失敗時回傳 None（降級為不使用快取）。
    fn open_result_cache(
        &self,
        cache_dir: Option<&Path>,
        rules_hash: &str,
    ) -> Option<ResultCache> {
        // 僅在明確指定快取目錄時啟用，CLI 層負責提供預設路徑。
        let cache_path = cache_dir
            .map(|d| d.join("atlas-cache.db"))?;

        // 確保目錄存在。
        if let Some(parent) = cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let config = CacheConfig {
            max_entries: 10_000,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            rules_version_hash: rules_hash.to_string(),
        };

        match ResultCache::open(&cache_path, config) {
            Ok(cache) => {
                info!(path = %cache_path.display(), "result cache opened");
                Some(cache)
            }
            Err(e) => {
                warn!(error = %e, "failed to open result cache; continuing without cache");
                None
            }
        }
    }

    /// Process a single discovered file: read, validate, parse, and evaluate
    /// rules. Returns the findings for this file (may be empty).
    #[allow(clippy::too_many_arguments)]
    fn process_file(
        &self,
        discovered: &crate::scanner::DiscoveredFile,
        max_file_bytes: u64,
        query_cache: &HashMap<String, L1PatternEngine>,
        files_scanned: &AtomicU32,
        files_skipped: &AtomicU32,
        parse_failures: &AtomicU32,
        diff_context: Option<&DiffContext>,
        analysis_level: AnalysisLevel,
        metrics_engine: Option<&MetricsEngine>,
    ) -> (Vec<Finding>, Option<FileMetricsData>) {
        // 2a. Look up adapter by language.
        let adapter = match self.adapter_registry.get_by_language(discovered.language) {
            Some(a) => a,
            None => {
                debug!(
                    language = %discovered.language,
                    path = %discovered.relative_path,
                    "no adapter registered for language; skipping"
                );
                files_skipped.fetch_add(1, Ordering::Relaxed);
                return (Vec::new(), None);
            }
        };

        // 2b. Read file content.
        let source = match std::fs::read(&discovered.path) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    path = %discovered.path.display(),
                    error = %e,
                    "failed to read file; skipping"
                );
                files_skipped.fetch_add(1, Ordering::Relaxed);
                return (Vec::new(), None);
            }
        };

        // Edge case: skip files exceeding the max file size.
        if max_file_bytes > 0 && source.len() as u64 > max_file_bytes {
            warn!(
                path = %discovered.relative_path,
                size_bytes = source.len(),
                max_bytes = max_file_bytes,
                "file exceeds max size; skipping"
            );
            files_skipped.fetch_add(1, Ordering::Relaxed);
            return (Vec::new(), None);
        }

        // T091: Warn for files exceeding 1 MiB that still pass the limit.
        const ONE_MIB: u64 = 1024 * 1024;
        if source.len() as u64 > ONE_MIB {
            warn!(
                path = %discovered.relative_path,
                size_bytes = source.len(),
                "large file (>1 MiB); analysis may be slower"
            );
        }

        // Edge case: validate UTF-8 encoding.
        if std::str::from_utf8(&source).is_err() {
            warn!(
                path = %discovered.relative_path,
                "file is not valid UTF-8; skipping"
            );
            files_skipped.fetch_add(1, Ordering::Relaxed);
            parse_failures.fetch_add(1, Ordering::Relaxed);
            return (Vec::new(), None);
        }

        // 2c. Parse with adapter.
        let tree = match adapter.parse(&source) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    path = %discovered.relative_path,
                    error = %e,
                    "failed to parse file; skipping"
                );
                files_skipped.fetch_add(1, Ordering::Relaxed);
                parse_failures.fetch_add(1, Ordering::Relaxed);
                return (Vec::new(), None);
            }
        };

        let mut findings = Vec::new();

        // 2d. Evaluate each matching rule using pre-compiled queries.
        for rule in &self.rules {
            // Only evaluate rules that match the file's language.
            if rule.language != discovered.language {
                continue;
            }

            // Skip secrets-category rules for files marked as secrets-excluded
            // (e.g. .env.example, .env.sample, .env.template).
            if rule.category == crate::Category::Secrets && discovered.secrets_excluded {
                debug!(
                    rule_id = %rule.id,
                    file = %discovered.relative_path,
                    "skipping secrets rule for excluded file"
                );
                continue;
            }

            // Look up the pre-compiled L1 engine from the cache.
            let l1_engine = match query_cache.get(&rule.id) {
                Some(e) => e,
                None => continue, // Not an L1 rule or failed to compile
            };

            // Build metadata from the rule.
            let metadata = RuleMatchMetadata {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                category: rule.category,
                cwe_id: rule.cwe_id.clone(),
                description: rule.description.clone(),
                remediation: rule.remediation.clone(),
                confidence: rule.confidence,
                metadata: rule.metadata.clone(),
            };

            // Evaluate and collect findings.
            let rule_findings =
                l1_engine.evaluate(&tree, &source, &discovered.relative_path, &metadata);

            if !rule_findings.is_empty() {
                debug!(
                    rule_id = %rule.id,
                    file = %discovered.relative_path,
                    count = rule_findings.len(),
                    "findings from rule"
                );
            }

            findings.extend(rule_findings);
        }

        // L2: intra-procedural data-flow analysis（若啟用）
        if analysis_level.depth() >= 2 {
            match L2Engine::new(discovered.language) {
                Ok(l2_engine) => {
                    let l2_findings =
                        l2_engine.analyze_file(&tree, &source, &discovered.relative_path);
                    if !l2_findings.is_empty() {
                        debug!(
                            file = %discovered.relative_path,
                            count = l2_findings.len(),
                            "L2 data-flow findings"
                        );
                    }
                    findings.extend(l2_findings);
                }
                Err(e) => {
                    warn!(
                        file = %discovered.relative_path,
                        error = %e,
                        "failed to initialize L2 engine; skipping L2 analysis"
                    );
                }
            }
        }

        // Metrics：計算 per-file 品質指標（複用已解析的 AST）
        let source_str = std::str::from_utf8(&source).unwrap_or("");
        let file_metrics = if let Some(me) = metrics_engine {
            let fm = me.compute_file_metrics(
                &tree,
                source_str,
                discovered.language,
                &discovered.relative_path,
            );
            // 閾值檢查：產生超過閾值的 findings
            if let Some(ref metrics_data) = fm {
                let threshold_findings = me.check_thresholds(
                    metrics_data,
                    &discovered.relative_path,
                    discovered.language,
                );
                findings.extend(threshold_findings);
            }
            fm
        } else {
            None
        };

        // Attribute diff status to each finding.
        if let Some(dc) = diff_context {
            if !dc.is_fallback {
                let changed_file = dc.get_file(&discovered.relative_path);
                for finding in &mut findings {
                    finding.diff_status = Some(
                        if changed_file
                            .is_some_and(|cf| {
                                cf.overlaps_any_hunk(
                                    finding.line_range.start_line,
                                    finding.line_range.end_line,
                                )
                            })
                        {
                            DiffStatus::New
                        } else {
                            DiffStatus::Context
                        },
                    );
                }
            }
        }

        files_scanned.fetch_add(1, Ordering::Relaxed);
        (findings, file_metrics)
    }
}

/// 判斷檔案是否為自動產生的程式碼（不計入重複偵測）
fn is_autogenerated_for_duplication(relative_path: &str) -> bool {
    let path_lower = relative_path.to_lowercase();
    // EF Core Migrations
    path_lower.ends_with(".designer.cs")
        || path_lower.ends_with("modelsnapshot.cs")
        // .NET Source Generators
        || path_lower.ends_with(".g.cs")
        || path_lower.ends_with(".generated.cs")
        || path_lower.ends_with(".g.i.cs")
        // Minified / Bundled 檔案
        || path_lower.ends_with(".min.js")
        || path_lower.ends_with(".min.css")
        || path_lower.ends_with(".bundle.js")
        || path_lower.ends_with(".chunk.js")
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ScanEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanEngine")
            .field("adapter_registry", &self.adapter_registry)
            .field("rules_count", &self.rules.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_new_has_adapters_registered() {
        let engine = ScanEngine::new();
        // TypeScript and JavaScript adapters should be registered.
        assert!(
            engine
                .adapter_registry
                .get_by_language(Language::TypeScript)
                .is_some()
        );
        assert!(
            engine
                .adapter_registry
                .get_by_language(Language::JavaScript)
                .is_some()
        );
    }

    #[test]
    fn engine_new_has_no_rules() {
        let engine = ScanEngine::new();
        assert!(engine.rules.is_empty());
    }

    #[test]
    fn engine_default_matches_new() {
        let engine = ScanEngine::default();
        assert!(
            engine
                .adapter_registry
                .get_by_language(Language::TypeScript)
                .is_some()
        );
        assert!(engine.rules.is_empty());
    }

    #[test]
    fn scan_empty_directory_returns_empty_result() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = ScanEngine::new();

        let result = engine.scan(tmp.path(), None).unwrap();

        assert!(result.findings.is_empty());
        assert_eq!(result.files_scanned, 0);
        assert_eq!(result.files_skipped, 0);
        assert!(result.languages_detected.is_empty());
    }

    #[test]
    fn scan_nonexistent_directory_returns_error() {
        let engine = ScanEngine::new();
        let result = engine.scan(Path::new("/nonexistent/unlikely/path"), None);
        assert!(result.is_err());
    }

    #[test]
    fn add_rules_increases_rule_count() {
        let mut engine = ScanEngine::new();
        assert_eq!(engine.rules.len(), 0);

        let rule = Rule {
            id: "test/rule".to_owned(),
            name: "Test Rule".to_owned(),
            description: "A test rule".to_owned(),
            severity: crate::Severity::Medium,
            category: crate::Category::Security,
            language: Language::TypeScript,
            analysis_level: AnalysisLevel::L1,
            rule_type: crate::RuleType::Declarative,
            confidence: crate::Confidence::Medium,
            pattern: Some("(identifier) @id".to_owned()),
            script: None,
            plugin: None,
            cwe_id: None,
            remediation: "Fix it.".to_owned(),
            references: vec![],
            tags: vec![],
            version: "1.0.0".to_owned(),
            metadata: std::collections::BTreeMap::new(),
        };

        engine.add_rules(vec![rule]);
        assert_eq!(engine.rules.len(), 1);
    }

    #[test]
    fn scan_with_no_rules_returns_no_findings() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.ts"), "const x: number = 42;").unwrap();

        let engine = ScanEngine::new();
        let result = engine.scan(tmp.path(), None).unwrap();

        assert!(result.findings.is_empty());
        assert_eq!(result.files_scanned, 1);
        assert!(result.languages_detected.contains(&Language::TypeScript));
    }

    #[test]
    fn load_rules_from_nonexistent_dir_returns_error() {
        let mut engine = ScanEngine::new();
        let result = engine.load_rules(Path::new("/nonexistent/rules/dir"));
        assert!(result.is_err());
    }

    #[test]
    fn load_rules_from_empty_dir_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let mut engine = ScanEngine::new();
        let result = engine.load_rules(tmp.path());
        assert!(result.is_ok());
        assert_eq!(engine.rules.len(), 0);
    }

    // -----------------------------------------------------------------------
    // T024: Parallel scan tests
    // -----------------------------------------------------------------------

    #[test]
    fn scan_with_options_parallel() {
        let tmp = tempfile::tempdir().unwrap();
        // Create several files to exercise parallel processing.
        for i in 0..10 {
            std::fs::write(
                tmp.path().join(format!("file_{i}.ts")),
                format!("const x{i}: number = {i};"),
            )
            .unwrap();
        }

        let engine = ScanEngine::new();
        let options = ScanOptions {
            jobs: Some(2),
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        assert_eq!(result.files_scanned, 10);
        assert_eq!(result.files_skipped, 0);
    }

    #[test]
    fn scan_with_options_single_thread() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.ts"), "const x: number = 1;").unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            jobs: Some(1),
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn scan_options_default() {
        let opts = ScanOptions::default();
        assert_eq!(opts.max_file_size_kb, 1024);
        assert!(opts.jobs.is_none());
    }

    // -----------------------------------------------------------------------
    // T028: Edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn scan_skips_files_exceeding_max_size() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a small file (should be scanned).
        std::fs::write(tmp.path().join("small.ts"), "const x = 1;").unwrap();

        // Create a large file exceeding our 1 KiB limit (should be skipped).
        let large_content = "a".repeat(2048);
        std::fs::write(
            tmp.path().join("large.ts"),
            format!("const y = \"{large_content}\";"),
        )
        .unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            max_file_size_kb: 1, // 1 KiB limit
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.files_skipped, 1);
    }

    #[test]
    fn scan_skips_non_utf8_files() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a valid UTF-8 file.
        std::fs::write(tmp.path().join("good.ts"), "const x = 1;").unwrap();

        // Create a non-UTF-8 file with a supported extension.
        // Use invalid UTF-8 bytes that are NOT NUL (to pass binary detection).
        let mut bad_bytes = b"const y = '".to_vec();
        bad_bytes.extend_from_slice(&[0xFF, 0xFE, 0x80, 0x81]);
        bad_bytes.extend_from_slice(b"';");
        std::fs::write(tmp.path().join("bad.ts"), &bad_bytes).unwrap();

        let engine = ScanEngine::new();
        let result = engine.scan(tmp.path(), None).unwrap();

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.files_skipped, 1);
        // 非 UTF-8 檔案應被計入 parse_failures。
        assert_eq!(result.stats.parse_failures, 1);
    }

    #[test]
    fn scan_with_zero_max_size_does_not_skip() {
        // max_file_size_kb = 0 means "no limit" (the check uses > 0 guard).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.ts"), "const x = 1;").unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            max_file_size_kb: 0,
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.files_skipped, 0);
    }

    // -----------------------------------------------------------------------
    // Cache 整合測試
    // -----------------------------------------------------------------------

    #[test]
    fn scan_with_cache_second_run_has_hits() {
        let src = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("app.ts"), "const x: number = 42;").unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            cache_dir: Some(cache_dir.path().to_path_buf()),
            ..Default::default()
        };

        // 第一次掃描：cache miss → hit rate = 0.0。
        let r1 = engine.scan_with_options(src.path(), None, &options).unwrap();
        assert_eq!(r1.files_scanned, 1);
        assert_eq!(r1.stats.cache_hit_rate, Some(0.0));

        // 第二次掃描：cache hit → hit rate > 0。
        let r2 = engine.scan_with_options(src.path(), None, &options).unwrap();
        assert_eq!(r2.files_scanned, 1);
        assert!(
            r2.stats.cache_hit_rate.unwrap() > 0.0,
            "expected cache_hit_rate > 0 on second scan, got {:?}",
            r2.stats.cache_hit_rate
        );
    }

    #[test]
    fn scan_with_no_cache_flag_skips_cache() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("app.ts"), "const x = 1;").unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            no_cache: true,
            ..Default::default()
        };

        let result = engine.scan_with_options(src.path(), None, &options).unwrap();
        assert!(result.stats.cache_hit_rate.is_none());
    }

    // -----------------------------------------------------------------------
    // Task 6.5: Metrics pipeline 整合測試
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_with_metrics_produces_file_metrics() {
        // 建立含有函數定義的 TypeScript 檔案，啟用 compute_metrics 後掃描，
        // 驗證 file_metrics 包含正確的函數級指標。
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("app.ts"),
            "function hello() { if (true) { return 1; } return 0; }",
        )
        .unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            compute_metrics: true,
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        // 應成功掃描 1 個檔案
        assert_eq!(result.files_scanned, 1);
        // 啟用 metrics 後，file_metrics 應包含 1 筆資料
        assert_eq!(result.file_metrics.len(), 1);

        let fm = &result.file_metrics[0];
        // 至少偵測到 1 個函數（hello）
        assert_eq!(fm.functions.len(), 1);
        // if 分支至少貢獻 cyclomatic complexity >= 2
        assert!(
            fm.functions[0].cyclomatic_complexity >= 2,
            "expected cyclomatic_complexity >= 2, got {}",
            fm.functions[0].cyclomatic_complexity,
        );
        // LOC 計數應大於 0
        assert!(fm.total_lines > 0);
    }

    #[test]
    fn test_scan_without_metrics_no_file_metrics() {
        // 建立相同的 TypeScript 檔案，但 compute_metrics = false（預設），
        // 驗證 file_metrics 為空且 duplication 為 None。
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("app.ts"),
            "function hello() { if (true) { return 1; } return 0; }",
        )
        .unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            compute_metrics: false,
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        // 檔案仍應被正常掃描
        assert_eq!(result.files_scanned, 1);
        // 未啟用 metrics 時，file_metrics 應為空
        assert!(
            result.file_metrics.is_empty(),
            "expected empty file_metrics when compute_metrics=false, got {} entries",
            result.file_metrics.len(),
        );
        // duplication 也應為 None
        assert!(
            result.duplication.is_none(),
            "expected duplication=None when compute_metrics=false",
        );
    }

    // -----------------------------------------------------------------------
    // Task 8.6 / 8.7: L3 pipeline 整合測試
    // -----------------------------------------------------------------------

    #[test]
    fn l2_mode_does_not_produce_l3_findings() {
        // 建立含有跨函數污染模式的 TypeScript 檔案，使用 L2 模式掃描。
        // L3 引擎不應被執行，因此不應有 l3- 開頭的 rule_id。
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("app.ts"),
            r#"
function handleRequest(req) {
    const input = req.body.name;
    runQuery(input);
}

function runQuery(sql) {
    db.query(sql);
}
"#,
        )
        .unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            analysis_level: AnalysisLevel::L2,
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        assert_eq!(result.files_scanned, 1);
        // L2 模式下不應產生 L3 findings
        let l3_count = result
            .findings
            .iter()
            .filter(|f| f.rule_id.contains("l3-"))
            .count();
        assert_eq!(
            l3_count, 0,
            "L2 模式不應產生 L3 findings，但找到 {l3_count} 個"
        );
    }

    #[test]
    fn l3_mode_produces_l2_and_l3_findings() {
        // 建立含有 (1) 直接 intraprocedural 和 (2) 跨函數 interprocedural
        // 污染流的 TypeScript 檔案，使用 L3 模式掃描。
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("app.ts"),
            r#"
function directFlow(req) {
    const data = req.body.name;
    db.query(data);
}

function indirectFlow(req) {
    const input = req.body.name;
    runQuery(input);
}

function runQuery(sql) {
    db.query(sql);
}
"#,
        )
        .unwrap();

        let engine = ScanEngine::new();
        let options = ScanOptions {
            analysis_level: AnalysisLevel::L3,
            ..Default::default()
        };
        let result = engine
            .scan_with_options(tmp.path(), None, &options)
            .unwrap();

        assert_eq!(result.files_scanned, 1);

        let l2_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id.contains("l2-"))
            .collect();
        let l3_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id.contains("l3-"))
            .collect();

        // L3 模式應同時產生 L2（intraprocedural）和 L3（interprocedural）findings
        assert!(
            !l2_findings.is_empty(),
            "L3 模式應包含 L2 findings（intraprocedural flow）"
        );
        assert!(
            !l3_findings.is_empty(),
            "L3 模式應包含 L3 findings（interprocedural flow）"
        );

        // L3 findings 的 analysis_level 應為 L3
        for f in &l3_findings {
            assert_eq!(
                f.analysis_level,
                AnalysisLevel::L3,
                "L3 finding 的 analysis_level 應為 L3"
            );
        }
    }
}
