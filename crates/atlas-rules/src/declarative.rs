//! Declarative YAML rule loader for Atlas Local SAST.
//!
//! This module provides [`DeclarativeRuleLoader`] which loads declarative rule
//! definitions from YAML files. Each YAML file describes one rule with a
//! tree-sitter S-expression pattern for AST-level (L1) pattern matching.
//!
//! # YAML Format
//!
//! ```yaml
//! id: atlas/security/typescript/sql-injection
//! name: SQL Injection Detection
//! description: Detects potential SQL injection via string concatenation
//! severity: high
//! category: security
//! language: TypeScript
//! cwe_id: CWE-89
//! pattern: |
//!   (binary_expression
//!     left: (identifier) @source
//!     right: (template_string) @sink)
//! remediation: Use parameterized queries instead of string concatenation.
//! references:
//!   - https://cwe.mitre.org/data/definitions/89.html
//! tags:
//!   - sql
//!   - injection
//! version: 1.0.0
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use walkdir::WalkDir;

use crate::{AnalysisLevel, Category, Language, Rule, RuleError, RuleType, Severity};

// ---------------------------------------------------------------------------
// DeclarativeError
// ---------------------------------------------------------------------------

/// Errors that can occur while loading declarative YAML rule files.
#[derive(Debug, thiserror::Error)]
pub enum DeclarativeError {
    /// An I/O error occurred while reading a rule file.
    #[error("I/O error reading rule file '{}': {source}", path.display())]
    IoError {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The YAML content could not be parsed.
    #[error("YAML parse error in '{}': {source}", path.display())]
    YamlParseError {
        /// The path that contained invalid YAML.
        path: PathBuf,
        /// The underlying YAML parsing error.
        source: serde_yml::Error,
    },

    /// A parsed rule failed structural validation.
    #[error("validation error for rule '{rule_id}': {source}")]
    ValidationError {
        /// The rule ID that failed validation.
        rule_id: String,
        /// The underlying validation error.
        source: RuleError,
    },
}

// ---------------------------------------------------------------------------
// DeclarativeRuleFile (intermediate deserialization struct)
// ---------------------------------------------------------------------------

/// Intermediate struct that maps the simplified YAML format for declarative rules.
///
/// This struct uses serde to deserialize the YAML directly, then converts into
/// the full [`Rule`] struct with `rule_type = Declarative` and
/// `analysis_level = L1`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclarativeRuleFile {
    /// Unique rule identifier (e.g. `atlas/security/typescript/sql-injection`).
    pub id: String,

    /// Human-readable rule name.
    pub name: String,

    /// What the rule detects.
    pub description: String,

    /// Finding severity (lowercase: critical, high, medium, low, info).
    pub severity: Severity,

    /// Rule category (lowercase: security, quality, secrets).
    pub category: Category,

    /// Target programming language (PascalCase: TypeScript, JavaScript, etc.).
    pub language: Language,

    /// Detection confidence level. Defaults to `Medium` if omitted.
    #[serde(default)]
    pub confidence: Option<crate::Confidence>,

    /// Tree-sitter S-expression pattern.
    pub pattern: String,

    /// Associated CWE identifier (e.g. `CWE-89`). Optional.
    #[serde(default)]
    pub cwe_id: Option<String>,

    /// Remediation guidance.
    pub remediation: String,

    /// External reference links.
    #[serde(default)]
    pub references: Vec<String>,

    /// Searchable tags.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Rule version in SemVer format (e.g. `1.0.0`).
    pub version: String,

    /// Arbitrary metadata carried through to findings (e.g. `quality_domain`).
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, serde_json::Value>>,
}

impl From<DeclarativeRuleFile> for Rule {
    fn from(file: DeclarativeRuleFile) -> Self {
        Rule {
            id: file.id,
            name: file.name,
            description: file.description,
            severity: file.severity,
            category: file.category,
            language: file.language,
            analysis_level: AnalysisLevel::L1,
            rule_type: RuleType::Declarative,
            confidence: file.confidence.unwrap_or(crate::Confidence::Medium),
            pattern: Some(file.pattern),
            script: None,
            plugin: None,
            cwe_id: file.cwe_id,
            remediation: file.remediation,
            references: file.references,
            tags: file.tags,
            version: file.version,
            metadata: file.metadata.unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// DeclarativeRuleLoader
// ---------------------------------------------------------------------------

/// Loads declarative SAST rules from YAML files.
///
/// Each YAML file defines a single rule with a tree-sitter S-expression pattern
/// for L1 (AST-level) analysis. The loader parses the YAML, converts it into a
/// [`Rule`], and validates the result.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use atlas_rules::declarative::DeclarativeRuleLoader;
///
/// let loader = DeclarativeRuleLoader;
/// let rules = loader.load_from_dir(Path::new("rules/")).unwrap();
/// for rule in &rules {
///     println!("{}", rule);
/// }
/// ```
pub struct DeclarativeRuleLoader;

impl DeclarativeRuleLoader {
    /// Loads a single declarative rule from a YAML file.
    ///
    /// The file is expected to contain exactly one rule definition in the
    /// declarative YAML format. The resulting [`Rule`] will have
    /// `rule_type = Declarative` and `analysis_level = L1`.
    ///
    /// # Errors
    ///
    /// - [`DeclarativeError::IoError`] if the file cannot be read.
    /// - [`DeclarativeError::YamlParseError`] if the YAML is malformed or
    ///   missing required fields.
    /// - [`DeclarativeError::ValidationError`] if the parsed rule fails
    ///   structural validation.
    pub fn load_from_file(&self, path: &Path) -> Result<Vec<Rule>, DeclarativeError> {
        let contents = std::fs::read_to_string(path).map_err(|e| DeclarativeError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;

        self.load_from_str(&contents, path)
    }

    /// Loads all declarative rules from `.yaml` and `.yml` files in a directory,
    /// recursively.
    ///
    /// Files that do not have a `.yaml` or `.yml` extension are silently skipped.
    /// The returned rules are sorted by ID for deterministic ordering.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Errors can be I/O errors, YAML
    /// parse errors, or validation errors.
    pub fn load_from_dir(&self, dir: &Path) -> Result<Vec<Rule>, DeclarativeError> {
        let mut rules = Vec::new();

        for entry in WalkDir::new(dir).follow_links(true) {
            let entry = entry.map_err(|e| {
                let path = e
                    .path()
                    .map_or_else(|| dir.to_path_buf(), Path::to_path_buf);
                DeclarativeError::IoError {
                    path,
                    source: std::io::Error::other(e),
                }
            })?;

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            match path.extension().and_then(|ext| ext.to_str()) {
                Some("yaml" | "yml") => {}
                _ => continue,
            }

            let loaded = self.load_from_file(path)?;
            rules.extend(loaded);
        }

        rules.sort();
        Ok(rules)
    }

    /// Parses a YAML string and returns validated rule(s).
    ///
    /// The `source_path` is used only for error messages.
    fn load_from_str(&self, yaml: &str, source_path: &Path) -> Result<Vec<Rule>, DeclarativeError> {
        let file: DeclarativeRuleFile =
            serde_yml::from_str(yaml).map_err(|e| DeclarativeError::YamlParseError {
                path: source_path.to_path_buf(),
                source: e,
            })?;

        let rule: Rule = file.into();

        rule.validate()
            .map_err(|e| DeclarativeError::ValidationError {
                rule_id: rule.id.clone(),
                source: e,
            })?;

        Ok(vec![rule])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Valid YAML for a declarative rule.
    const VALID_YAML: &str = r#"
id: atlas/security/typescript/sql-injection
name: SQL Injection Detection
description: Detects potential SQL injection via string concatenation
severity: high
category: security
language: TypeScript
cwe_id: CWE-89
pattern: |
  (binary_expression
    left: (identifier) @source
    right: (template_string) @sink)
remediation: Use parameterized queries instead of string concatenation.
references:
  - https://cwe.mitre.org/data/definitions/89.html
tags:
  - sql
  - injection
version: 1.0.0
"#;

    /// Another valid YAML rule for directory loading tests.
    const VALID_YAML_2: &str = r#"
id: atlas/security/python/hardcoded-password
name: Hardcoded Password Detection
description: Detects hardcoded passwords in source code
severity: medium
category: secrets
language: Python
pattern: |
  (assignment
    left: (identifier) @name
    right: (string) @value)
remediation: Use environment variables or a secrets manager.
tags:
  - secrets
  - password
version: 1.0.0
"#;

    // -------------------------------------------------------------------
    // load_from_str / single file loading
    // -------------------------------------------------------------------

    #[test]
    fn load_single_rule_from_yaml_string() {
        let loader = DeclarativeRuleLoader;
        let path = Path::new("test.yaml");
        let rules = loader.load_from_str(VALID_YAML, path).unwrap();

        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.id, "atlas/security/typescript/sql-injection");
        assert_eq!(rule.name, "SQL Injection Detection");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.category, Category::Security);
        assert_eq!(rule.language, Language::TypeScript);
        assert_eq!(rule.analysis_level, AnalysisLevel::L1);
        assert_eq!(rule.rule_type, RuleType::Declarative);
        assert!(rule.pattern.is_some());
        assert_eq!(rule.cwe_id.as_deref(), Some("CWE-89"));
        assert_eq!(rule.references.len(), 1);
        assert_eq!(rule.tags, vec!["sql", "injection"]);
        assert_eq!(rule.version, "1.0.0");
        // script and plugin should be None
        assert!(rule.script.is_none());
        assert!(rule.plugin.is_none());
    }

    #[test]
    fn load_rule_from_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("rule.yaml");
        fs::write(&file_path, VALID_YAML).unwrap();

        let loader = DeclarativeRuleLoader;
        let rules = loader.load_from_file(&file_path).unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "atlas/security/typescript/sql-injection");
    }

    // -------------------------------------------------------------------
    // load_from_dir
    // -------------------------------------------------------------------

    #[test]
    fn load_rules_from_directory() {
        let dir = TempDir::new().unwrap();

        // Create a top-level YAML file.
        fs::write(dir.path().join("sql-injection.yaml"), VALID_YAML).unwrap();

        // Create a subdirectory with another YAML file.
        let sub = dir.path().join("python");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("hardcoded-password.yml"), VALID_YAML_2).unwrap();

        // Create a non-YAML file that should be skipped.
        fs::write(dir.path().join("README.md"), "# ignore me").unwrap();

        let loader = DeclarativeRuleLoader;
        let rules = loader.load_from_dir(dir.path()).unwrap();

        assert_eq!(rules.len(), 2);
        // Rules should be sorted by ID.
        assert_eq!(rules[0].id, "atlas/security/python/hardcoded-password");
        assert_eq!(rules[1].id, "atlas/security/typescript/sql-injection");
    }

    #[test]
    fn load_from_empty_directory() {
        let dir = TempDir::new().unwrap();

        let loader = DeclarativeRuleLoader;
        let rules = loader.load_from_dir(dir.path()).unwrap();

        assert!(rules.is_empty());
    }

    // -------------------------------------------------------------------
    // Error cases
    // -------------------------------------------------------------------

    #[test]
    fn error_on_invalid_yaml() {
        let loader = DeclarativeRuleLoader;
        let path = Path::new("bad.yaml");
        let result = loader.load_from_str("not: [valid: yaml: for: rules", path);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DeclarativeError::YamlParseError { .. }),
            "expected YamlParseError, got: {err}"
        );
        assert!(err.to_string().contains("bad.yaml"));
    }

    #[test]
    fn error_on_missing_required_field() {
        // YAML missing the 'pattern' field which is required by DeclarativeRuleFile.
        let yaml = r#"
id: atlas/security/typescript/no-pattern
name: Missing Pattern
description: This rule has no pattern
severity: high
category: security
language: TypeScript
remediation: Fix it.
version: 1.0.0
"#;

        let loader = DeclarativeRuleLoader;
        let result = loader.load_from_str(yaml, Path::new("no-pattern.yaml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DeclarativeError::YamlParseError { .. }),
            "expected YamlParseError, got: {err}"
        );
    }

    #[test]
    fn error_on_validation_failure() {
        // Rule with invalid version that will fail Rule::validate().
        let yaml = r#"
id: atlas/security/typescript/bad-version
name: Bad Version Rule
description: This rule has an invalid version
severity: high
category: security
language: TypeScript
pattern: "(identifier)"
remediation: Fix it.
version: not-semver
"#;

        let loader = DeclarativeRuleLoader;
        let result = loader.load_from_str(yaml, Path::new("bad-version.yaml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DeclarativeError::ValidationError { .. }),
            "expected ValidationError, got: {err}"
        );
        assert!(err.to_string().contains("bad-version"));
    }

    #[test]
    fn error_on_nonexistent_file() {
        let loader = DeclarativeRuleLoader;
        let result = loader.load_from_file(Path::new("/nonexistent/rule.yaml"));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DeclarativeError::IoError { .. }),
            "expected IoError, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // DeclarativeRuleFile -> Rule conversion
    // -------------------------------------------------------------------

    #[test]
    fn conversion_sets_declarative_fields() {
        let file = DeclarativeRuleFile {
            id: "test/rule".to_owned(),
            name: "Test".to_owned(),
            description: "A test rule".to_owned(),
            severity: Severity::Low,
            category: Category::Quality,
            language: Language::Go,
            pattern: "(identifier)".to_owned(),
            cwe_id: None,
            remediation: "Fix it.".to_owned(),
            references: vec![],
            tags: vec![],
            version: "1.0.0".to_owned(),
            confidence: None,
            metadata: None,
        };

        let rule: Rule = file.into();
        assert_eq!(rule.rule_type, RuleType::Declarative);
        assert_eq!(rule.analysis_level, AnalysisLevel::L1);
        assert!(rule.pattern.is_some());
        assert!(rule.script.is_none());
        assert!(rule.plugin.is_none());
    }

    // -------------------------------------------------------------------
    // Optional fields
    // -------------------------------------------------------------------

    #[test]
    fn load_rule_without_optional_fields() {
        let yaml = r#"
id: atlas/quality/go/unused-var
name: Unused Variable
description: Detects unused variables
severity: info
category: quality
language: Go
pattern: "(identifier) @unused"
remediation: Remove the unused variable.
version: 0.1.0
"#;

        let loader = DeclarativeRuleLoader;
        let rules = loader.load_from_str(yaml, Path::new("test.yaml")).unwrap();

        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert!(rule.cwe_id.is_none());
        assert!(rule.references.is_empty());
        assert!(rule.tags.is_empty());
    }

    // -------------------------------------------------------------------
    // Load built-in Python rules from disk
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_python_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/python");

        if !rules_dir.exists() {
            panic!("Python rules directory not found: {}", rules_dir.display());
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all Python rules should load successfully");

        assert_eq!(rules.len(), 11, "expected exactly 11 Python rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/python/bare-except",
                "atlas/quality/python/empty-function-body",
                "atlas/quality/python/magic-number",
                "atlas/quality/python/mutable-default-arg",
                "atlas/quality/python/pass-in-except",
                "atlas/quality/python/print-statement",
                "atlas/quality/python/todo-comment",
                "atlas/security/python/command-injection",
                "atlas/security/python/eval-usage",
                "atlas/security/python/sql-injection",
                "atlas/security/python/unsafe-deserialization",
            ]
        );

        // Verify common properties across all rules.
        for rule in &rules {
            assert_eq!(rule.language, Language::Python);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // Verify security rules.
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 4, "expected 4 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        let sql = rules
            .iter()
            .find(|r| r.id.contains("sql-injection"))
            .unwrap();
        assert_eq!(sql.severity, Severity::Critical);
        assert_eq!(sql.cwe_id.as_deref(), Some("CWE-89"));

        let cmd = rules
            .iter()
            .find(|r| r.id.contains("command-injection"))
            .unwrap();
        assert_eq!(cmd.severity, Severity::Critical);
        assert_eq!(cmd.cwe_id.as_deref(), Some("CWE-78"));

        let eval = rules.iter().find(|r| r.id.contains("eval-usage")).unwrap();
        assert_eq!(eval.severity, Severity::Critical);

        let deser = rules
            .iter()
            .find(|r| r.id.contains("unsafe-deserialization"))
            .unwrap();
        assert_eq!(deser.severity, Severity::High);

        // Verify quality rules.
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 7, "expected 7 quality rules");
        for rule in &quality_rules {
            assert!(rule.cwe_id.is_none());
        }

        let bare_except = rules
            .iter()
            .find(|r| r.id.contains("bare-except"))
            .unwrap();
        assert_eq!(bare_except.severity, Severity::Medium);
        assert_eq!(bare_except.category, Category::Quality);

        let print_stmt = rules
            .iter()
            .find(|r| r.id.contains("print-statement"))
            .unwrap();
        assert_eq!(print_stmt.severity, Severity::Low);
        assert_eq!(print_stmt.category, Category::Quality);

        let pass_except = rules
            .iter()
            .find(|r| r.id.contains("pass-in-except"))
            .unwrap();
        assert_eq!(pass_except.severity, Severity::Medium);
        assert_eq!(pass_except.category, Category::Quality);

        let mutable_default = rules
            .iter()
            .find(|r| r.id.contains("mutable-default-arg"))
            .unwrap();
        assert_eq!(mutable_default.severity, Severity::Medium);
        assert_eq!(mutable_default.category, Category::Quality);

        let empty_fn = rules
            .iter()
            .find(|r| r.id.contains("empty-function-body"))
            .unwrap();
        assert_eq!(empty_fn.severity, Severity::Low);
        assert_eq!(empty_fn.category, Category::Quality);

        let todo_comment = rules
            .iter()
            .find(|r| r.id.contains("todo-comment"))
            .unwrap();
        assert_eq!(todo_comment.severity, Severity::Info);
        assert_eq!(todo_comment.category, Category::Quality);

        let magic_num = rules
            .iter()
            .find(|r| r.id.contains("magic-number"))
            .unwrap();
        assert_eq!(magic_num.severity, Severity::Low);
        assert_eq!(magic_num.category, Category::Quality);
    }

    // -------------------------------------------------------------------
    // Load built-in Java rules from disk
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_java_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/java");

        if !rules_dir.exists() {
            panic!("Java rules directory not found: {}", rules_dir.display());
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all Java rules should load successfully");

        assert_eq!(rules.len(), 11, "expected exactly 11 Java rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/java/empty-catch-block",
                "atlas/quality/java/empty-method-body",
                "atlas/quality/java/raw-type-usage",
                "atlas/quality/java/redundant-boolean",
                "atlas/quality/java/string-concat-in-loop",
                "atlas/quality/java/system-out-println",
                "atlas/quality/java/todo-comment",
                "atlas/security/java/insecure-deserialization",
                "atlas/security/java/path-traversal",
                "atlas/security/java/sql-injection",
                "atlas/security/java/xss-servlet",
            ]
        );

        // Verify common properties across all rules.
        for rule in &rules {
            assert_eq!(rule.language, Language::Java);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // Verify security rules.
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 4, "expected 4 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        let sql = rules
            .iter()
            .find(|r| r.id.contains("sql-injection"))
            .unwrap();
        assert_eq!(sql.severity, Severity::Critical);
        assert_eq!(sql.cwe_id.as_deref(), Some("CWE-89"));

        let xss = rules.iter().find(|r| r.id.contains("xss-servlet")).unwrap();
        assert_eq!(xss.severity, Severity::High);
        assert_eq!(xss.cwe_id.as_deref(), Some("CWE-79"));

        let deser = rules
            .iter()
            .find(|r| r.id.contains("insecure-deserialization"))
            .unwrap();
        assert_eq!(deser.severity, Severity::Critical);
        assert_eq!(deser.cwe_id.as_deref(), Some("CWE-502"));

        let path = rules
            .iter()
            .find(|r| r.id.contains("path-traversal"))
            .unwrap();
        assert_eq!(path.severity, Severity::High);
        assert_eq!(path.cwe_id.as_deref(), Some("CWE-22"));

        // Verify quality rules.
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 7, "expected 7 quality rules");

        let empty_catch = rules
            .iter()
            .find(|r| r.id.contains("empty-catch-block"))
            .unwrap();
        assert_eq!(empty_catch.severity, Severity::Medium);
        assert_eq!(empty_catch.category, Category::Quality);
        assert!(empty_catch.cwe_id.is_none());
        assert_eq!(empty_catch.confidence, crate::Confidence::High);

        let sysout = rules
            .iter()
            .find(|r| r.id.contains("system-out-println"))
            .unwrap();
        assert_eq!(sysout.severity, Severity::Low);
        assert_eq!(sysout.category, Category::Quality);
        assert!(sysout.cwe_id.is_none());
        assert_eq!(sysout.confidence, crate::Confidence::High);

        // Verify new quality rules.
        let todo = rules
            .iter()
            .find(|r| r.id.contains("todo-comment"))
            .unwrap();
        assert_eq!(todo.severity, Severity::Info);
        assert_eq!(todo.category, Category::Quality);
        assert!(todo.cwe_id.is_none());
        assert_eq!(todo.confidence, crate::Confidence::High);
        assert!(todo.tags.contains(&"maintainability".to_owned()));

        let empty_method = rules
            .iter()
            .find(|r| r.id.contains("empty-method-body"))
            .unwrap();
        assert_eq!(empty_method.severity, Severity::Low);
        assert_eq!(empty_method.category, Category::Quality);
        assert!(empty_method.cwe_id.is_none());
        assert_eq!(empty_method.confidence, crate::Confidence::Medium);
        assert!(empty_method.tags.contains(&"maintainability".to_owned()));

        let redundant_bool = rules
            .iter()
            .find(|r| r.id.contains("redundant-boolean"))
            .unwrap();
        assert_eq!(redundant_bool.severity, Severity::Low);
        assert_eq!(redundant_bool.category, Category::Quality);
        assert!(redundant_bool.cwe_id.is_none());
        assert_eq!(redundant_bool.confidence, crate::Confidence::High);
        assert!(redundant_bool.tags.contains(&"best-practices".to_owned()));

        let str_concat = rules
            .iter()
            .find(|r| r.id.contains("string-concat-in-loop"))
            .unwrap();
        assert_eq!(str_concat.severity, Severity::Medium);
        assert_eq!(str_concat.category, Category::Quality);
        assert!(str_concat.cwe_id.is_none());
        assert_eq!(str_concat.confidence, crate::Confidence::High);
        assert!(str_concat.tags.contains(&"performance".to_owned()));

        let raw_type = rules
            .iter()
            .find(|r| r.id.contains("raw-type-usage"))
            .unwrap();
        assert_eq!(raw_type.severity, Severity::Low);
        assert_eq!(raw_type.category, Category::Quality);
        assert!(raw_type.cwe_id.is_none());
        assert_eq!(raw_type.confidence, crate::Confidence::Medium);
        assert!(raw_type.tags.contains(&"type-safety".to_owned()));
    }

    // -------------------------------------------------------------------
    // C# builtin rules
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_csharp_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/csharp");

        if !rules_dir.exists() {
            panic!("C# rules directory not found: {}", rules_dir.display());
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all C# rules should load successfully");

        assert_eq!(rules.len(), 11, "expected exactly 11 C# rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/csharp/console-writeline",
                "atlas/quality/csharp/empty-catch-block",
                "atlas/quality/csharp/empty-method-body",
                "atlas/quality/csharp/object-type-usage",
                "atlas/quality/csharp/redundant-boolean",
                "atlas/quality/csharp/todo-comment",
                "atlas/security/csharp/command-injection",
                "atlas/security/csharp/insecure-deserialization",
                "atlas/security/csharp/path-traversal",
                "atlas/security/csharp/sql-injection-concatenation",
                "atlas/security/csharp/sql-injection-interpolation",
            ]
        );

        // Verify common properties across all rules.
        for rule in &rules {
            assert_eq!(rule.language, Language::CSharp);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // Verify security rules have CWE and security category.
        let security_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 5);
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        // Verify quality rules.
        let quality_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 6);
        for rule in &quality_rules {
            assert!(rule.cwe_id.is_none());
        }

        let empty_catch = rules
            .iter()
            .find(|r| r.id.contains("empty-catch-block"))
            .unwrap();
        assert_eq!(empty_catch.severity, Severity::Medium);
        assert_eq!(empty_catch.category, Category::Quality);

        let console_wl = rules
            .iter()
            .find(|r| r.id.contains("console-writeline"))
            .unwrap();
        assert_eq!(console_wl.severity, Severity::Low);
        assert_eq!(console_wl.category, Category::Quality);

        let empty_method = rules
            .iter()
            .find(|r| r.id.contains("empty-method-body"))
            .unwrap();
        assert_eq!(empty_method.severity, Severity::Low);
        assert_eq!(empty_method.category, Category::Quality);

        let object_type = rules
            .iter()
            .find(|r| r.id.contains("object-type-usage"))
            .unwrap();
        assert_eq!(object_type.severity, Severity::Low);
        assert_eq!(object_type.category, Category::Quality);

        let redundant_bool = rules
            .iter()
            .find(|r| r.id.contains("redundant-boolean"))
            .unwrap();
        assert_eq!(redundant_bool.severity, Severity::Low);
        assert_eq!(redundant_bool.category, Category::Quality);

        let todo_comment = rules
            .iter()
            .find(|r| r.id.contains("todo-comment"))
            .unwrap();
        assert_eq!(todo_comment.severity, Severity::Info);
        assert_eq!(todo_comment.category, Category::Quality);

        // Verify specific severities.
        let sql_concat = rules
            .iter()
            .find(|r| r.id.contains("sql-injection-concatenation"))
            .unwrap();
        assert_eq!(sql_concat.severity, Severity::Critical);
        assert_eq!(sql_concat.cwe_id.as_deref(), Some("CWE-89"));

        let sql_interp = rules
            .iter()
            .find(|r| r.id.contains("sql-injection-interpolation"))
            .unwrap();
        assert_eq!(sql_interp.severity, Severity::Critical);
        assert_eq!(sql_interp.cwe_id.as_deref(), Some("CWE-89"));

        let deser = rules
            .iter()
            .find(|r| r.id.contains("insecure-deserialization"))
            .unwrap();
        assert_eq!(deser.severity, Severity::Critical);
        assert_eq!(deser.cwe_id.as_deref(), Some("CWE-502"));

        let path = rules
            .iter()
            .find(|r| r.id.contains("path-traversal"))
            .unwrap();
        assert_eq!(path.severity, Severity::High);
        assert_eq!(path.cwe_id.as_deref(), Some("CWE-22"));

        let cmd = rules
            .iter()
            .find(|r| r.id.contains("command-injection"))
            .unwrap();
        assert_eq!(cmd.severity, Severity::Critical);
        assert_eq!(cmd.cwe_id.as_deref(), Some("CWE-78"));
    }

    // -------------------------------------------------------------------
    // Load built-in Go rules from disk
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_go_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/go");

        if !rules_dir.exists() {
            panic!("Go rules directory not found: {}", rules_dir.display());
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all Go rules should load successfully");

        assert_eq!(rules.len(), 9, "expected exactly 9 Go rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/go/defer-in-loop",
                "atlas/quality/go/empty-error-check",
                "atlas/quality/go/empty-function-body",
                "atlas/quality/go/fmt-println",
                "atlas/quality/go/todo-comment",
                "atlas/quality/go/unchecked-error",
                "atlas/security/go/command-injection",
                "atlas/security/go/path-traversal",
                "atlas/security/go/sql-injection",
            ]
        );

        // Verify common properties across all rules.
        for rule in &rules {
            assert_eq!(rule.language, Language::Go);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // Verify security rules.
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 3, "expected 3 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        let sql = rules
            .iter()
            .find(|r| r.id.contains("sql-injection"))
            .unwrap();
        assert_eq!(sql.severity, Severity::Critical);
        assert_eq!(sql.cwe_id.as_deref(), Some("CWE-89"));

        let cmd = rules
            .iter()
            .find(|r| r.id.contains("command-injection"))
            .unwrap();
        assert_eq!(cmd.severity, Severity::Critical);
        assert_eq!(cmd.cwe_id.as_deref(), Some("CWE-78"));

        let path = rules
            .iter()
            .find(|r| r.id.contains("path-traversal"))
            .unwrap();
        assert_eq!(path.severity, Severity::High);
        assert_eq!(path.cwe_id.as_deref(), Some("CWE-22"));

        // Verify quality rules.
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 6, "expected 6 quality rules");
        for rule in &quality_rules {
            assert!(rule.cwe_id.is_none());
        }

        let defer_loop = rules
            .iter()
            .find(|r| r.id.contains("defer-in-loop"))
            .unwrap();
        assert_eq!(defer_loop.severity, Severity::Medium);
        assert_eq!(defer_loop.category, Category::Quality);

        let empty_err = rules
            .iter()
            .find(|r| r.id.contains("empty-error-check"))
            .unwrap();
        assert_eq!(empty_err.severity, Severity::Medium);
        assert_eq!(empty_err.category, Category::Quality);

        let fmt_println = rules
            .iter()
            .find(|r| r.id.contains("fmt-println"))
            .unwrap();
        assert_eq!(fmt_println.severity, Severity::Low);
        assert_eq!(fmt_println.category, Category::Quality);

        let empty_fn = rules
            .iter()
            .find(|r| r.id.contains("empty-function-body"))
            .unwrap();
        assert_eq!(empty_fn.severity, Severity::Low);
        assert_eq!(empty_fn.category, Category::Quality);

        let todo = rules
            .iter()
            .find(|r| r.id.contains("todo-comment"))
            .unwrap();
        assert_eq!(todo.severity, Severity::Info);
        assert_eq!(todo.category, Category::Quality);

        let unchecked = rules
            .iter()
            .find(|r| r.id.contains("unchecked-error"))
            .unwrap();
        assert_eq!(unchecked.severity, Severity::High);
        assert_eq!(unchecked.category, Category::Quality);
    }
}
