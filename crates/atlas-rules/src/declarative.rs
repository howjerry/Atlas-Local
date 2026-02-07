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

use std::path::{Path, PathBuf};

use serde::Deserialize;
use walkdir::WalkDir;

use crate::{
    AnalysisLevel, Category, Language, Rule, RuleError, RuleType, Severity,
};

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
            pattern: Some(file.pattern),
            script: None,
            plugin: None,
            cwe_id: file.cwe_id,
            remediation: file.remediation,
            references: file.references,
            tags: file.tags,
            version: file.version,
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
                let path = e.path().map_or_else(|| dir.to_path_buf(), Path::to_path_buf);
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
    fn load_from_str(
        &self,
        yaml: &str,
        source_path: &Path,
    ) -> Result<Vec<Rule>, DeclarativeError> {
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
}
