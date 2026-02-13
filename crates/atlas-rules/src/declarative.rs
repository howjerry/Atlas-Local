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

    /// Detection confidence level. Defaults to `High` if omitted.
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

    /// 是否跳過測試檔案。
    #[serde(default)]
    pub skip_test_files: bool,
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
            confidence: file.confidence.unwrap_or(crate::Confidence::High),
            pattern: Some(file.pattern),
            script: None,
            plugin: None,
            cwe_id: file.cwe_id,
            remediation: file.remediation,
            references: file.references,
            tags: file.tags,
            version: file.version,
            metadata: file.metadata.unwrap_or_default(),
            skip_test_files: file.skip_test_files,
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
            skip_test_files: false,
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
    // Load built-in TypeScript rules from disk
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_typescript_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/typescript");

        if !rules_dir.exists() {
            panic!("TypeScript rules directory not found: {}", rules_dir.display());
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all TypeScript rules should load successfully");

        assert_eq!(rules.len(), 39, "expected exactly 39 TypeScript rules");

        // 驗證所有規則按 ID 排序
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/typescript/alert-usage",
                "atlas/quality/typescript/any-type-usage",
                "atlas/quality/typescript/console-log",
                "atlas/quality/typescript/debugger-statement",
                "atlas/quality/typescript/empty-catch-block",
                "atlas/quality/typescript/empty-conditional",
                "atlas/quality/typescript/empty-function-body",
                "atlas/quality/typescript/empty-interface",
                "atlas/quality/typescript/excessive-parameters",
                "atlas/quality/typescript/loose-equality",
                "atlas/quality/typescript/magic-number",
                "atlas/quality/typescript/nested-ternary",
                "atlas/quality/typescript/no-return-await",
                "atlas/quality/typescript/non-null-assertion",
                "atlas/quality/typescript/redundant-boolean",
                "atlas/quality/typescript/string-concat-in-loop",
                "atlas/quality/typescript/todo-comment",
                "atlas/quality/typescript/var-declaration",
                "atlas/security/typescript/code-injection-eval",
                "atlas/security/typescript/code-injection-function-constructor",
                "atlas/security/typescript/cors-wildcard",
                "atlas/security/typescript/dangerouslysetinnerhtml",
                "atlas/security/typescript/hardcoded-secret",
                "atlas/security/typescript/header-injection",
                "atlas/security/typescript/insecure-cookie",
                "atlas/security/typescript/insecure-random",
                "atlas/security/typescript/jwt-no-verify",
                "atlas/security/typescript/log-injection",
                "atlas/security/typescript/nosql-injection",
                "atlas/security/typescript/open-redirect",
                "atlas/security/typescript/path-traversal",
                "atlas/security/typescript/prototype-pollution",
                "atlas/security/typescript/regex-dos",
                "atlas/security/typescript/sql-injection",
                "atlas/security/typescript/ssrf",
                "atlas/security/typescript/template-injection",
                "atlas/security/typescript/unsafe-redirect",
                "atlas/security/typescript/weak-crypto",
                "atlas/security/typescript/xss-innerhtml",
            ]
        );

        // 驗證共同屬性
        for rule in &rules {
            assert_eq!(rule.language, Language::TypeScript);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // 驗證安全規則
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 21, "expected 21 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some(), "security rule {} should have CWE ID", rule.id);
        }

        // 驗證品質規則
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 18, "expected 18 quality rules");
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

        assert_eq!(rules.len(), 34, "expected exactly 34 Python rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/python/assert-usage",
                "atlas/quality/python/bare-except",
                "atlas/quality/python/broad-exception",
                "atlas/quality/python/empty-conditional",
                "atlas/quality/python/empty-function-body",
                "atlas/quality/python/excessive-parameters",
                "atlas/quality/python/global-variable",
                "atlas/quality/python/magic-number",
                "atlas/quality/python/mutable-default-arg",
                "atlas/quality/python/nested-ternary",
                "atlas/quality/python/pass-in-except",
                "atlas/quality/python/print-statement",
                "atlas/quality/python/redundant-boolean",
                "atlas/quality/python/string-concat-in-loop",
                "atlas/quality/python/todo-comment",
                "atlas/security/python/command-injection",
                "atlas/security/python/django-raw-sql",
                "atlas/security/python/eval-usage",
                "atlas/security/python/flask-debug-mode",
                "atlas/security/python/hardcoded-secret",
                "atlas/security/python/insecure-random",
                "atlas/security/python/insecure-tls",
                "atlas/security/python/jwt-no-verify",
                "atlas/security/python/ldap-injection",
                "atlas/security/python/log-injection",
                "atlas/security/python/open-redirect",
                "atlas/security/python/sql-injection",
                "atlas/security/python/ssrf",
                "atlas/security/python/template-injection",
                "atlas/security/python/unrestricted-file-upload",
                "atlas/security/python/unsafe-deserialization",
                "atlas/security/python/unsafe-yaml-load",
                "atlas/security/python/weak-crypto",
                "atlas/security/python/xml-bomb",
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

        // 驗證安全規則
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 19, "expected 19 security rules");
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

        // 驗證品質規則（原 7 + 新增 8 = 15）
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 15, "expected 15 quality rules");
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

        assert_eq!(rules.len(), 34, "expected exactly 34 Java rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/java/boolean-method-naming",
                "atlas/quality/java/empty-catch-block",
                "atlas/quality/java/empty-conditional",
                "atlas/quality/java/empty-method-body",
                "atlas/quality/java/excessive-parameters",
                "atlas/quality/java/magic-number",
                "atlas/quality/java/nested-ternary",
                "atlas/quality/java/raw-type-usage",
                "atlas/quality/java/redundant-boolean",
                "atlas/quality/java/string-concat-in-loop",
                "atlas/quality/java/system-exit",
                "atlas/quality/java/system-out-println",
                "atlas/quality/java/thread-sleep-in-loop",
                "atlas/quality/java/todo-comment",
                "atlas/security/java/expression-language-injection",
                "atlas/security/java/hardcoded-secret",
                "atlas/security/java/insecure-deserialization",
                "atlas/security/java/insecure-object-reference",
                "atlas/security/java/insecure-random",
                "atlas/security/java/insecure-tls",
                "atlas/security/java/jndi-injection",
                "atlas/security/java/jwt-no-verify",
                "atlas/security/java/ldap-injection",
                "atlas/security/java/log-injection",
                "atlas/security/java/open-redirect",
                "atlas/security/java/path-traversal",
                "atlas/security/java/spring-csrf-disabled",
                "atlas/security/java/sql-injection",
                "atlas/security/java/ssrf",
                "atlas/security/java/unrestricted-file-upload",
                "atlas/security/java/weak-crypto",
                "atlas/security/java/xpath-injection",
                "atlas/security/java/xss-servlet",
                "atlas/security/java/xxe",
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
        assert_eq!(security_rules.len(), 20, "expected 20 security rules");
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

        // 驗證新增的安全規則
        let insecure_random = rules
            .iter()
            .find(|r| r.id.contains("insecure-random"))
            .unwrap();
        assert_eq!(insecure_random.severity, Severity::Medium);
        assert_eq!(insecure_random.cwe_id.as_deref(), Some("CWE-330"));

        let weak_crypto = rules
            .iter()
            .find(|r| r.id.contains("weak-crypto"))
            .unwrap();
        assert_eq!(weak_crypto.severity, Severity::Medium);
        assert_eq!(weak_crypto.cwe_id.as_deref(), Some("CWE-327"));

        let open_redirect = rules
            .iter()
            .find(|r| r.id.contains("open-redirect"))
            .unwrap();
        assert_eq!(open_redirect.severity, Severity::Medium);
        assert_eq!(open_redirect.cwe_id.as_deref(), Some("CWE-601"));

        let ssrf = rules.iter().find(|r| r.id.contains("ssrf")).unwrap();
        assert_eq!(ssrf.severity, Severity::High);
        assert_eq!(ssrf.cwe_id.as_deref(), Some("CWE-918"));

        let xxe = rules.iter().find(|r| r.id.contains("xxe")).unwrap();
        assert_eq!(xxe.severity, Severity::High);
        assert_eq!(xxe.cwe_id.as_deref(), Some("CWE-611"));

        let hardcoded_secret = rules
            .iter()
            .find(|r| r.id.contains("hardcoded-secret"))
            .unwrap();
        assert_eq!(hardcoded_secret.severity, Severity::High);
        assert_eq!(hardcoded_secret.cwe_id.as_deref(), Some("CWE-798"));

        // Verify quality rules.
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 14, "expected 14 quality rules");

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

        // 驗證新增的品質規則
        let empty_cond = rules
            .iter()
            .find(|r| r.id.contains("empty-conditional"))
            .unwrap();
        assert_eq!(empty_cond.severity, Severity::Low);
        assert_eq!(empty_cond.category, Category::Quality);
        assert!(empty_cond.cwe_id.is_none());
        assert_eq!(empty_cond.confidence, crate::Confidence::High);

        let magic_num = rules
            .iter()
            .find(|r| r.id.contains("magic-number"))
            .unwrap();
        assert_eq!(magic_num.severity, Severity::Low);
        assert_eq!(magic_num.category, Category::Quality);
        assert!(magic_num.cwe_id.is_none());
        assert_eq!(magic_num.confidence, crate::Confidence::Medium);

        let nested_ternary = rules
            .iter()
            .find(|r| r.id.contains("nested-ternary"))
            .unwrap();
        assert_eq!(nested_ternary.severity, Severity::Low);
        assert_eq!(nested_ternary.category, Category::Quality);

        let excessive_params = rules
            .iter()
            .find(|r| r.id.contains("excessive-parameters"))
            .unwrap();
        assert_eq!(excessive_params.severity, Severity::Low);
        assert_eq!(excessive_params.category, Category::Quality);
        assert_eq!(excessive_params.confidence, crate::Confidence::High);

        let sys_exit = rules
            .iter()
            .find(|r| r.id.contains("system-exit"))
            .unwrap();
        assert_eq!(sys_exit.severity, Severity::Medium);
        assert_eq!(sys_exit.category, Category::Quality);
        assert_eq!(sys_exit.confidence, crate::Confidence::High);

        let thread_sleep = rules
            .iter()
            .find(|r| r.id.contains("thread-sleep-in-loop"))
            .unwrap();
        assert_eq!(thread_sleep.severity, Severity::Medium);
        assert_eq!(thread_sleep.category, Category::Quality);
        assert_eq!(thread_sleep.confidence, crate::Confidence::High);

        let bool_naming = rules
            .iter()
            .find(|r| r.id.contains("boolean-method-naming"))
            .unwrap();
        assert_eq!(bool_naming.severity, Severity::Low);
        assert_eq!(bool_naming.category, Category::Quality);
        assert_eq!(bool_naming.confidence, crate::Confidence::Medium);
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

        assert_eq!(rules.len(), 29, "expected exactly 29 C# rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/csharp/console-writeline",
                "atlas/quality/csharp/empty-catch-block",
                "atlas/quality/csharp/empty-conditional",
                "atlas/quality/csharp/empty-finally-block",
                "atlas/quality/csharp/empty-method-body",
                "atlas/quality/csharp/excessive-parameters",
                "atlas/quality/csharp/goto-usage",
                "atlas/quality/csharp/nested-ternary",
                "atlas/quality/csharp/object-type-usage",
                "atlas/quality/csharp/redundant-boolean",
                "atlas/quality/csharp/string-concat-in-loop",
                "atlas/quality/csharp/todo-comment",
                "atlas/security/csharp/command-injection",
                "atlas/security/csharp/csrf-disabled",
                "atlas/security/csharp/insecure-deserialization",
                "atlas/security/csharp/insecure-random",
                "atlas/security/csharp/insecure-tls",
                "atlas/security/csharp/jwt-no-verify",
                "atlas/security/csharp/ldap-injection",
                "atlas/security/csharp/log-injection",
                "atlas/security/csharp/open-redirect",
                "atlas/security/csharp/path-traversal",
                "atlas/security/csharp/regex-dos",
                "atlas/security/csharp/sql-injection-concatenation",
                "atlas/security/csharp/sql-injection-interpolation",
                "atlas/security/csharp/unrestricted-file-upload",
                "atlas/security/csharp/viewstate-insecure",
                "atlas/security/csharp/weak-crypto",
                "atlas/security/csharp/xxe",
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
        assert_eq!(security_rules.len(), 17);
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        // Verify quality rules.
        let quality_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 12);
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

        // 新安全規則驗證
        let insecure_random = rules
            .iter()
            .find(|r| r.id.contains("insecure-random"))
            .unwrap();
        assert_eq!(insecure_random.severity, Severity::Medium);
        assert_eq!(insecure_random.cwe_id.as_deref(), Some("CWE-330"));

        let weak_crypto = rules
            .iter()
            .find(|r| r.id.contains("weak-crypto"))
            .unwrap();
        assert_eq!(weak_crypto.severity, Severity::Medium);
        assert_eq!(weak_crypto.cwe_id.as_deref(), Some("CWE-327"));

        let open_redirect = rules
            .iter()
            .find(|r| r.id.contains("open-redirect"))
            .unwrap();
        assert_eq!(open_redirect.severity, Severity::Medium);
        assert_eq!(open_redirect.cwe_id.as_deref(), Some("CWE-601"));

        // 新品質規則驗證
        let empty_cond = rules
            .iter()
            .find(|r| r.id.contains("empty-conditional"))
            .unwrap();
        assert_eq!(empty_cond.severity, Severity::Low);
        assert_eq!(empty_cond.category, Category::Quality);

        let nested_ternary = rules
            .iter()
            .find(|r| r.id.contains("nested-ternary"))
            .unwrap();
        assert_eq!(nested_ternary.severity, Severity::Low);
        assert_eq!(nested_ternary.category, Category::Quality);

        let excessive_params = rules
            .iter()
            .find(|r| r.id.contains("excessive-parameters"))
            .unwrap();
        assert_eq!(excessive_params.severity, Severity::Low);
        assert_eq!(excessive_params.category, Category::Quality);

        let string_concat = rules
            .iter()
            .find(|r| r.id.contains("string-concat-in-loop"))
            .unwrap();
        assert_eq!(string_concat.severity, Severity::Low);
        assert_eq!(string_concat.category, Category::Quality);

        let empty_finally = rules
            .iter()
            .find(|r| r.id.contains("empty-finally-block"))
            .unwrap();
        assert_eq!(empty_finally.severity, Severity::Low);
        assert_eq!(empty_finally.category, Category::Quality);

        let goto = rules
            .iter()
            .find(|r| r.id.contains("goto-usage"))
            .unwrap();
        assert_eq!(goto.severity, Severity::Low);
        assert_eq!(goto.category, Category::Quality);
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

        assert_eq!(rules.len(), 29, "expected exactly 29 Go rules");

        // Verify all rules are sorted by ID.
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/go/defer-in-loop",
                "atlas/quality/go/empty-conditional",
                "atlas/quality/go/empty-error-check",
                "atlas/quality/go/empty-function-body",
                "atlas/quality/go/excessive-parameters",
                "atlas/quality/go/fmt-println",
                "atlas/quality/go/panic-usage",
                "atlas/quality/go/redundant-boolean",
                "atlas/quality/go/string-concat-in-loop",
                "atlas/quality/go/todo-comment",
                "atlas/quality/go/type-assertion-without-check",
                "atlas/quality/go/unchecked-error",
                "atlas/security/go/command-injection",
                "atlas/security/go/file-permission-too-broad",
                "atlas/security/go/hardcoded-secret",
                "atlas/security/go/hardcoded-tls-key",
                "atlas/security/go/insecure-cookie",
                "atlas/security/go/insecure-random",
                "atlas/security/go/jwt-no-verify",
                "atlas/security/go/log-injection",
                "atlas/security/go/open-redirect",
                "atlas/security/go/path-traversal",
                "atlas/security/go/race-condition-map",
                "atlas/security/go/sql-injection",
                "atlas/security/go/ssrf",
                "atlas/security/go/template-injection",
                "atlas/security/go/tls-insecure-skip-verify",
                "atlas/security/go/unsafe-reflect",
                "atlas/security/go/weak-crypto",
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
        assert_eq!(security_rules.len(), 17, "expected 17 security rules");
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
        assert_eq!(quality_rules.len(), 12, "expected 12 quality rules");
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

    // -------------------------------------------------------------------
    // Load built-in secrets rules from disk
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_secrets_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/secrets");

        if !rules_dir.exists() {
            panic!(
                "Secrets rules directory not found: {}",
                rules_dir.display()
            );
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all secrets rules should load successfully");

        assert_eq!(rules.len(), 15, "expected exactly 15 secrets rules");

        // 驗證所有規則共通屬性
        for rule in &rules {
            assert_eq!(rule.category, Category::Secrets);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(rule.cwe_id.is_some(), "secrets rule {} should have CWE", rule.id);
            assert_eq!(rule.version, "1.0.0");
        }

        // 驗證排序後的規則 ID 清單
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/secrets/generic/aws-access-key",
                "atlas/secrets/generic/azure-storage-key",
                "atlas/secrets/generic/connection-string-password",
                "atlas/secrets/generic/generic-api-key",
                "atlas/secrets/generic/github-token",
                "atlas/secrets/generic/gitlab-pat",
                "atlas/secrets/generic/google-api-key",
                "atlas/secrets/generic/jwt-secret",
                "atlas/secrets/generic/jwt-token",
                "atlas/secrets/generic/npm-token",
                "atlas/secrets/generic/private-key-header",
                "atlas/secrets/generic/sendgrid-api-key",
                "atlas/secrets/generic/slack-webhook",
                "atlas/secrets/generic/stripe-secret-key",
                "atlas/secrets/generic/twilio-api-key",
            ]
        );
    }

    // -------------------------------------------------------------------
    // Load built-in Kotlin rules from disk
    // -------------------------------------------------------------------

    #[test]
    fn load_builtin_kotlin_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/kotlin");

        if !rules_dir.exists() {
            panic!(
                "Kotlin rules directory not found: {}",
                rules_dir.display()
            );
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all Kotlin rules should load successfully");

        assert_eq!(rules.len(), 30, "expected exactly 30 Kotlin rules");

        // 驗證排序後的規則 ID 清單
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/kotlin/empty-catch-block",
                "atlas/quality/kotlin/empty-function-body",
                "atlas/quality/kotlin/empty-when-branch",
                "atlas/quality/kotlin/excessive-parameters",
                "atlas/quality/kotlin/force-unwrap",
                "atlas/quality/kotlin/magic-number",
                "atlas/quality/kotlin/println-residual",
                "atlas/quality/kotlin/redundant-boolean",
                "atlas/quality/kotlin/string-concat-in-loop",
                "atlas/quality/kotlin/todo-comment",
                "atlas/quality/kotlin/unsafe-cast",
                "atlas/quality/kotlin/var-could-be-val",
                "atlas/security/kotlin/command-injection",
                "atlas/security/kotlin/coroutine-unsafe-context",
                "atlas/security/kotlin/expression-language-injection",
                "atlas/security/kotlin/hardcoded-secret",
                "atlas/security/kotlin/insecure-deserialization",
                "atlas/security/kotlin/insecure-random",
                "atlas/security/kotlin/insecure-tls",
                "atlas/security/kotlin/jndi-injection",
                "atlas/security/kotlin/jwt-no-verify",
                "atlas/security/kotlin/ldap-injection",
                "atlas/security/kotlin/log-injection",
                "atlas/security/kotlin/path-traversal",
                "atlas/security/kotlin/spring-csrf-disabled",
                "atlas/security/kotlin/sql-injection",
                "atlas/security/kotlin/unrestricted-file-upload",
                "atlas/security/kotlin/weak-crypto",
                "atlas/security/kotlin/xss",
                "atlas/security/kotlin/xxe",
            ]
        );

        // 驗證所有規則共通屬性
        for rule in &rules {
            assert_eq!(rule.language, Language::Kotlin);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // 驗證安全規則
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 18, "expected 18 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        // 驗證品質規則
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 12, "expected 12 quality rules");

        // 驗證個別安全規則
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

        let xss = rules.iter().find(|r| r.id.contains("/xss")).unwrap();
        assert_eq!(xss.severity, Severity::High);
        assert_eq!(xss.cwe_id.as_deref(), Some("CWE-79"));

        let path = rules
            .iter()
            .find(|r| r.id.contains("path-traversal"))
            .unwrap();
        assert_eq!(path.severity, Severity::High);
        assert_eq!(path.cwe_id.as_deref(), Some("CWE-22"));

        let insecure_random = rules
            .iter()
            .find(|r| r.id.contains("insecure-random"))
            .unwrap();
        assert_eq!(insecure_random.severity, Severity::Medium);
        assert_eq!(insecure_random.cwe_id.as_deref(), Some("CWE-330"));

        let weak_crypto = rules
            .iter()
            .find(|r| r.id.contains("weak-crypto"))
            .unwrap();
        assert_eq!(weak_crypto.severity, Severity::Medium);
        assert_eq!(weak_crypto.cwe_id.as_deref(), Some("CWE-327"));

        let hardcoded = rules
            .iter()
            .find(|r| r.id.contains("hardcoded-secret"))
            .unwrap();
        assert_eq!(hardcoded.severity, Severity::High);
        assert_eq!(hardcoded.cwe_id.as_deref(), Some("CWE-798"));

        let deser = rules
            .iter()
            .find(|r| r.id.contains("insecure-deserialization"))
            .unwrap();
        assert_eq!(deser.severity, Severity::High);
        assert_eq!(deser.cwe_id.as_deref(), Some("CWE-502"));
    }

    #[test]
    fn load_builtin_ruby_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/ruby");

        if !rules_dir.exists() {
            panic!(
                "Ruby rules directory not found: {}",
                rules_dir.display()
            );
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all Ruby rules should load successfully");

        assert_eq!(rules.len(), 34, "expected exactly 34 Ruby rules");

        // 驗證排序後的規則 ID 清單
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/ruby/bare-rescue",
                "atlas/quality/ruby/class-variable",
                "atlas/quality/ruby/empty-conditional",
                "atlas/quality/ruby/empty-method-body",
                "atlas/quality/ruby/empty-rescue-block",
                "atlas/quality/ruby/excessive-parameters",
                "atlas/quality/ruby/global-variable",
                "atlas/quality/ruby/magic-number",
                "atlas/quality/ruby/nested-ternary",
                "atlas/quality/ruby/pp-debug",
                "atlas/quality/ruby/puts-residual",
                "atlas/quality/ruby/redundant-boolean",
                "atlas/quality/ruby/sleep-usage",
                "atlas/quality/ruby/string-concat-in-loop",
                "atlas/quality/ruby/todo-comment",
                "atlas/security/ruby/command-injection",
                "atlas/security/ruby/csrf-disabled",
                "atlas/security/ruby/dynamic-code-execution",
                "atlas/security/ruby/hardcoded-secret",
                "atlas/security/ruby/header-injection",
                "atlas/security/ruby/insecure-tls",
                "atlas/security/ruby/jwt-no-verify",
                "atlas/security/ruby/ldap-injection",
                "atlas/security/ruby/log-injection",
                "atlas/security/ruby/mass-assignment",
                "atlas/security/ruby/open-redirect",
                "atlas/security/ruby/path-traversal",
                "atlas/security/ruby/sql-injection",
                "atlas/security/ruby/unrestricted-file-upload",
                "atlas/security/ruby/unsafe-reflection",
                "atlas/security/ruby/weak-crypto",
                "atlas/security/ruby/xss",
                "atlas/security/ruby/xxe",
                "atlas/security/ruby/yaml-load",
            ]
        );

        // 驗證所有規則共通屬性
        for rule in &rules {
            assert_eq!(rule.language, Language::Ruby);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // 驗證安全規則
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 19, "expected 19 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        // 驗證品質規則
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 15, "expected 15 quality rules");

        // 驗證個別安全規則
        let sql = rules
            .iter()
            .find(|r| r.id.contains("sql-injection"))
            .unwrap();
        assert_eq!(sql.severity, Severity::High);
        assert_eq!(sql.cwe_id.as_deref(), Some("CWE-89"));

        let cmd = rules
            .iter()
            .find(|r| r.id.contains("command-injection"))
            .unwrap();
        assert_eq!(cmd.severity, Severity::Critical);
        assert_eq!(cmd.cwe_id.as_deref(), Some("CWE-78"));

        let xss = rules.iter().find(|r| r.id.contains("/xss")).unwrap();
        assert_eq!(xss.severity, Severity::High);
        assert_eq!(xss.cwe_id.as_deref(), Some("CWE-79"));

        let path = rules
            .iter()
            .find(|r| r.id.contains("path-traversal"))
            .unwrap();
        assert_eq!(path.severity, Severity::High);
        assert_eq!(path.cwe_id.as_deref(), Some("CWE-22"));

        let yaml = rules
            .iter()
            .find(|r| r.id.contains("yaml-load"))
            .unwrap();
        assert_eq!(yaml.severity, Severity::High);
        assert_eq!(yaml.cwe_id.as_deref(), Some("CWE-502"));

        let weak_crypto = rules
            .iter()
            .find(|r| r.id.contains("weak-crypto"))
            .unwrap();
        assert_eq!(weak_crypto.severity, Severity::Medium);
        assert_eq!(weak_crypto.cwe_id.as_deref(), Some("CWE-327"));

        let hardcoded = rules
            .iter()
            .find(|r| r.id.contains("hardcoded-secret"))
            .unwrap();
        assert_eq!(hardcoded.severity, Severity::High);
        assert_eq!(hardcoded.cwe_id.as_deref(), Some("CWE-798"));
    }

    #[test]
    fn load_builtin_php_rules_from_disk() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("rules/builtin/php");

        if !rules_dir.exists() {
            panic!(
                "PHP rules directory not found: {}",
                rules_dir.display()
            );
        }

        let loader = DeclarativeRuleLoader;
        let rules = loader
            .load_from_dir(&rules_dir)
            .expect("all PHP rules should load successfully");

        assert_eq!(rules.len(), 34, "expected exactly 34 PHP rules");

        // 驗證排序後的規則 ID 清單
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "atlas/quality/php/bare-exception",
                "atlas/quality/php/empty-catch-block",
                "atlas/quality/php/empty-conditional",
                "atlas/quality/php/empty-function-body",
                "atlas/quality/php/error-suppression",
                "atlas/quality/php/excessive-parameters",
                "atlas/quality/php/exit-usage",
                "atlas/quality/php/global-statement",
                "atlas/quality/php/loose-comparison",
                "atlas/quality/php/magic-number",
                "atlas/quality/php/nested-ternary",
                "atlas/quality/php/print-r-residual",
                "atlas/quality/php/redundant-boolean",
                "atlas/quality/php/todo-comment",
                "atlas/quality/php/var-dump-residual",
                "atlas/security/php/code-injection",
                "atlas/security/php/command-injection",
                "atlas/security/php/file-inclusion",
                "atlas/security/php/header-injection",
                "atlas/security/php/insecure-tls",
                "atlas/security/php/jwt-no-verify",
                "atlas/security/php/laravel-mass-assignment",
                "atlas/security/php/ldap-injection",
                "atlas/security/php/log-injection",
                "atlas/security/php/open-redirect",
                "atlas/security/php/path-traversal",
                "atlas/security/php/preg-eval",
                "atlas/security/php/sql-injection",
                "atlas/security/php/ssrf",
                "atlas/security/php/unrestricted-file-upload",
                "atlas/security/php/unserialize",
                "atlas/security/php/weak-crypto",
                "atlas/security/php/xss",
                "atlas/security/php/xxe",
            ]
        );

        // 驗證所有規則共通屬性
        for rule in &rules {
            assert_eq!(rule.language, Language::Php);
            assert_eq!(rule.analysis_level, AnalysisLevel::L1);
            assert_eq!(rule.rule_type, RuleType::Declarative);
            assert!(rule.pattern.is_some());
            assert!(!rule.tags.is_empty());
            assert_eq!(rule.version, "1.0.0");
        }

        // 驗證安全規則
        let security_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Security)
            .collect();
        assert_eq!(security_rules.len(), 19, "expected 19 security rules");
        for rule in &security_rules {
            assert!(rule.cwe_id.is_some());
        }

        // 驗證品質規則
        let quality_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.category == Category::Quality)
            .collect();
        assert_eq!(quality_rules.len(), 15, "expected 15 quality rules");

        // 驗證個別安全規則
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

        let xss = rules.iter().find(|r| r.id.contains("/xss")).unwrap();
        assert_eq!(xss.severity, Severity::High);
        assert_eq!(xss.cwe_id.as_deref(), Some("CWE-79"));

        let path = rules
            .iter()
            .find(|r| r.id.contains("path-traversal"))
            .unwrap();
        assert_eq!(path.severity, Severity::High);
        assert_eq!(path.cwe_id.as_deref(), Some("CWE-22"));

        let code_inj = rules
            .iter()
            .find(|r| r.id.contains("code-injection"))
            .unwrap();
        assert_eq!(code_inj.severity, Severity::Critical);
        assert_eq!(code_inj.cwe_id.as_deref(), Some("CWE-94"));

        let file_inc = rules
            .iter()
            .find(|r| r.id.contains("file-inclusion"))
            .unwrap();
        assert_eq!(file_inc.severity, Severity::Critical);
        assert_eq!(file_inc.cwe_id.as_deref(), Some("CWE-98"));

        let unserialize = rules
            .iter()
            .find(|r| r.id.contains("unserialize"))
            .unwrap();
        assert_eq!(unserialize.severity, Severity::High);
        assert_eq!(unserialize.cwe_id.as_deref(), Some("CWE-502"));

        let weak_crypto = rules
            .iter()
            .find(|r| r.id.contains("weak-crypto"))
            .unwrap();
        assert_eq!(weak_crypto.severity, Severity::Medium);
        assert_eq!(weak_crypto.cwe_id.as_deref(), Some("CWE-327"));
    }
}
