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

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use rayon::prelude::*;
use tracing::{debug, info, warn};

use atlas_analysis::{Finding, L1PatternEngine, RuleMatchMetadata};
use atlas_lang::{
    AdapterRegistry, register_csharp_adapter, register_go_adapter, register_java_adapter,
    register_js_ts_adapters, register_python_adapter,
};
use atlas_rules::declarative::DeclarativeRuleLoader;
use atlas_rules::{AnalysisLevel, Confidence, Rule};

use crate::scanner::discover_files;
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
                atlas_rules::Severity::Critical => summary.critical += 1,
                atlas_rules::Severity::High => summary.high += 1,
                atlas_rules::Severity::Medium => summary.medium += 1,
                atlas_rules::Severity::Low => summary.low += 1,
                atlas_rules::Severity::Info => summary.info += 1,
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
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size_kb: 1024,
            jobs: None,
            no_cache: false,
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

        // Step 1: Discover files.
        let discovery = discover_files(target, language_filter)?;
        info!(
            files = discovery.files.len(),
            languages = ?discovery.languages_detected,
            "file discovery complete"
        );

        let max_file_bytes = options.max_file_size_kb * 1024;

        // Shared counters for parallel processing.
        let files_scanned = AtomicU32::new(0);
        let files_skipped = AtomicU32::new(0);

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

        // Step 2: Process each discovered file in parallel.
        let mut all_findings: Vec<Finding> = pool.install(|| {
            discovery
                .files
                .par_iter()
                .flat_map(|discovered| {
                    self.process_file(discovered, max_file_bytes, &files_scanned, &files_skipped)
                })
                .collect()
        });

        // Step 3: L2 intra-procedural analysis (framework — future expansion).
        // When L2 rules are loaded, build scope graphs per function and track
        // variable definitions/uses to identify data-flow paths within function
        // boundaries.  Currently a no-op; findings from L1 are passed through.
        debug!("L2 intra-procedural analysis phase: no L2 rules loaded — skipping");

        // Step 4: L3 inter-procedural taint analysis (framework — future expansion).
        // When L3 rules are loaded, build a cross-file call graph and track
        // taint sources/sinks across function boundaries.  Currently a no-op.
        debug!("L3 inter-procedural analysis phase: no L3 rules loaded — skipping");

        // Step 5: Sort findings deterministically.
        all_findings.sort();

        let scanned = files_scanned.load(Ordering::Relaxed);
        let skipped = files_skipped.load(Ordering::Relaxed);

        let languages_detected: Vec<Language> = discovery.languages_detected.into_iter().collect();

        info!(
            findings = all_findings.len(),
            files_scanned = scanned,
            files_skipped = skipped,
            "scan complete"
        );

        // Step 6: Compute summary and stats.
        let summary = FindingsSummary::from_findings(&all_findings);
        let duration_ms = scan_start.elapsed().as_millis() as u64;
        let stats = ScanStats {
            duration_ms,
            parse_failures: 0,
            cache_hit_rate: if options.no_cache { None } else { Some(0.0) },
        };

        // Step 7: Return result.
        Ok(ScanResult {
            findings: all_findings,
            files_scanned: scanned,
            files_skipped: skipped,
            languages_detected,
            summary,
            stats,
        })
    }

    /// Process a single discovered file: read, validate, parse, and evaluate
    /// rules. Returns the findings for this file (may be empty).
    fn process_file(
        &self,
        discovered: &crate::scanner::DiscoveredFile,
        max_file_bytes: u64,
        files_scanned: &AtomicU32,
        files_skipped: &AtomicU32,
    ) -> Vec<Finding> {
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
                return Vec::new();
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
                return Vec::new();
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
            return Vec::new();
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
            return Vec::new();
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
                return Vec::new();
            }
        };

        let ts_lang = adapter.tree_sitter_language();
        let mut findings = Vec::new();

        // 2d. Evaluate each matching rule.
        for rule in &self.rules {
            // Only evaluate rules that match the file's language.
            if rule.language != discovered.language {
                continue;
            }

            // Only L1 declarative rules are supported for now.
            if rule.analysis_level != AnalysisLevel::L1 {
                continue;
            }

            // Skip secrets-category rules for files marked as secrets-excluded
            // (e.g. .env.example, .env.sample, .env.template).
            if rule.category == atlas_rules::Category::Secrets && discovered.secrets_excluded {
                debug!(
                    rule_id = %rule.id,
                    file = %discovered.relative_path,
                    "skipping secrets rule for excluded file"
                );
                continue;
            }

            // Get the pattern string.
            let pattern = match &rule.pattern {
                Some(p) => p,
                None => {
                    warn!(
                        rule_id = %rule.id,
                        "declarative rule has no pattern; skipping"
                    );
                    continue;
                }
            };

            // Compile the L1 pattern engine.
            let l1_engine = match L1PatternEngine::new(&ts_lang, pattern) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        error = %e,
                        "failed to compile rule pattern; skipping"
                    );
                    continue;
                }
            };

            // Build metadata from the rule.
            let metadata = RuleMatchMetadata {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                category: rule.category,
                cwe_id: rule.cwe_id.clone(),
                description: rule.description.clone(),
                remediation: rule.remediation.clone(),
                confidence: Confidence::Medium,
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

        files_scanned.fetch_add(1, Ordering::Relaxed);
        findings
    }
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
            severity: atlas_rules::Severity::Medium,
            category: atlas_rules::Category::Security,
            language: Language::TypeScript,
            analysis_level: AnalysisLevel::L1,
            rule_type: atlas_rules::RuleType::Declarative,
            pattern: Some("(identifier) @id".to_owned()),
            script: None,
            plugin: None,
            cwe_id: None,
            remediation: "Fix it.".to_owned(),
            references: vec![],
            tags: vec![],
            version: "1.0.0".to_owned(),
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
}
