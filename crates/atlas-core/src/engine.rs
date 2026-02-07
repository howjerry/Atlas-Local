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
//! use atlas_core::engine::ScanEngine;
//!
//! let mut engine = ScanEngine::new();
//! engine.load_rules(Path::new("rules/")).unwrap();
//! let result = engine.scan(Path::new("src/"), None).unwrap();
//! println!("Found {} findings in {} files", result.findings.len(), result.files_scanned);
//! ```

use std::path::Path;

use tracing::{debug, info, warn};

use atlas_analysis::{Finding, L1PatternEngine, RuleMatchMetadata};
use atlas_lang::{AdapterRegistry, register_js_ts_adapters};
use atlas_rules::{AnalysisLevel, Confidence, Rule};
use atlas_rules::declarative::DeclarativeRuleLoader;

use crate::{CoreError, Language};
use crate::scanner::discover_files;

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
    /// Creates a new `ScanEngine` with TypeScript and JavaScript adapters
    /// pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = AdapterRegistry::new();
        register_js_ts_adapters(&mut registry);
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

    /// Runs the full scan pipeline against the given `target` directory.
    ///
    /// # Pipeline
    ///
    /// 1. Discover source files (respecting `.gitignore`, `.atlasignore`, etc.).
    /// 2. For each discovered file:
    ///    a. Look up the language adapter from the registry.
    ///    b. Read the file content.
    ///    c. Parse with the adapter to get a tree-sitter `Tree`.
    ///    d. For each rule matching the file's language:
    ///       - Compile an `L1PatternEngine` with the rule's pattern.
    ///       - Evaluate the pattern against the tree.
    ///       - Collect any findings.
    /// 3. Sort all findings deterministically.
    /// 4. Return a [`ScanResult`].
    ///
    /// # Error handling
    ///
    /// - Files that cannot be read are logged at WARN level and skipped.
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
        // Step 1: Discover files.
        let discovery = discover_files(target, language_filter)?;
        info!(
            files = discovery.files.len(),
            languages = ?discovery.languages_detected,
            "file discovery complete"
        );

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut files_scanned: u32 = 0;
        let mut files_skipped: u32 = 0;

        // Step 2: Process each discovered file.
        for discovered in &discovery.files {
            // 2a. Look up adapter by language.
            let adapter = match self.adapter_registry.get_by_language(discovered.language) {
                Some(a) => a,
                None => {
                    debug!(
                        language = %discovered.language,
                        path = %discovered.relative_path,
                        "no adapter registered for language; skipping"
                    );
                    files_skipped += 1;
                    continue;
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
                    files_skipped += 1;
                    continue;
                }
            };

            // 2c. Parse with adapter.
            let tree = match adapter.parse(&source) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        path = %discovered.relative_path,
                        error = %e,
                        "failed to parse file; skipping"
                    );
                    files_skipped += 1;
                    continue;
                }
            };

            let ts_lang = adapter.tree_sitter_language();

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
                let findings = l1_engine.evaluate(
                    &tree,
                    &source,
                    &discovered.relative_path,
                    &metadata,
                );

                if !findings.is_empty() {
                    debug!(
                        rule_id = %rule.id,
                        file = %discovered.relative_path,
                        count = findings.len(),
                        "findings from rule"
                    );
                }

                all_findings.extend(findings);
            }

            files_scanned += 1;
        }

        // Step 3: Sort findings deterministically.
        all_findings.sort();

        let languages_detected: Vec<Language> =
            discovery.languages_detected.into_iter().collect();

        info!(
            findings = all_findings.len(),
            files_scanned,
            files_skipped,
            "scan complete"
        );

        // Step 4: Return result.
        Ok(ScanResult {
            findings: all_findings,
            files_scanned,
            files_skipped,
            languages_detected,
        })
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
}
