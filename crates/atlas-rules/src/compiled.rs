//! Compiled rule (cdylib) plugin loading for Atlas Local SAST.
//!
//! This module defines the stable C ABI contract for compiled rule plugins
//! and provides [`CompiledRuleLoader`] for loading shared library plugins
//! (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows).
//!
//! # ABI Contract
//!
//! A compiled rule plugin is a shared library that exports three C functions:
//!
//! ```c
//! // Returns the rule metadata as a JSON string.
//! // Caller must free the returned string with `rule_free_string`.
//! const char* rule_metadata();
//!
//! // Evaluates the rule against the given node data (JSON string).
//! // Returns findings as a JSON array string.
//! // Caller must free the returned string with `rule_free_string`.
//! const char* rule_evaluate(const char* node_json);
//!
//! // Frees a string previously returned by rule_metadata or rule_evaluate.
//! void rule_free_string(const char* s);
//! ```
//!
//! # JSON Interchange Types
//!
//! The host (Atlas) and plugin communicate via JSON strings using these
//! structures:
//!
//! - [`PluginMetadata`]: returned by `rule_metadata()`.
//! - [`NodeData`]: passed to `rule_evaluate()` as the `node_json` argument.
//! - [`PluginFinding`]: returned by `rule_evaluate()` as a JSON array.
//!
//! # Current Status
//!
//! Plugin loading requires the `libloading` crate which is not yet a
//! workspace dependency. The [`CompiledRuleLoader`] currently returns
//! [`CompiledRuleError::Unsupported`] when attempting to load a plugin.
//! The types and ABI contract are fully defined so that compiled plugins
//! can be authored against this specification today.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CompiledRuleError
// ---------------------------------------------------------------------------

/// Errors that can occur while loading or evaluating compiled rule plugins.
#[derive(Debug, thiserror::Error)]
pub enum CompiledRuleError {
    /// Compiled rule loading is not yet supported in this build.
    #[error("compiled rule loading not supported: {0}")]
    Unsupported(String),

    /// The shared library could not be loaded.
    #[error("failed to load plugin '{}': {reason}", path.display())]
    LoadError {
        /// The path to the shared library that failed to load.
        path: PathBuf,
        /// A human-readable description of the failure.
        reason: String,
    },

    /// A required symbol was not found in the shared library.
    #[error(
        "plugin ABI error in '{}': missing symbol '{symbol}'",
        path.display()
    )]
    AbiError {
        /// The path to the shared library.
        path: PathBuf,
        /// The name of the missing symbol.
        symbol: String,
    },

    /// The plugin returned data that could not be parsed as valid JSON.
    #[error("plugin returned invalid data: {reason}")]
    InvalidData {
        /// A description of what was wrong with the returned data.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// PluginMetadata
// ---------------------------------------------------------------------------

/// Metadata returned by a compiled rule plugin's `rule_metadata()` function.
///
/// This struct is serialized/deserialized as JSON for interchange across the
/// C ABI boundary.
///
/// # Example JSON
///
/// ```json
/// {
///   "id": "atlas/security/java/sql-injection-native",
///   "name": "SQL Injection (native)",
///   "severity": "high",
///   "category": "security",
///   "language": "Java",
///   "description": "Detects SQL injection via native taint analysis.",
///   "cwe_id": "CWE-89"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique rule identifier (e.g. `atlas/security/java/sql-injection-native`).
    pub id: String,

    /// Human-readable rule name.
    pub name: String,

    /// Finding severity (lowercase: `critical`, `high`, `medium`, `low`, `info`).
    pub severity: String,

    /// Rule category (lowercase: `security`, `quality`, `secrets`).
    pub category: String,

    /// Target programming language (e.g. `Java`, `Python`, `TypeScript`).
    pub language: String,

    /// What the rule detects.
    pub description: String,

    /// Associated CWE identifier (e.g. `CWE-89`). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
}

// ---------------------------------------------------------------------------
// NodeData
// ---------------------------------------------------------------------------

/// AST node data passed to a compiled rule plugin's `rule_evaluate()` function.
///
/// This struct is serialized to JSON by the host and passed as the
/// `node_json` C string argument.
///
/// # Example JSON
///
/// ```json
/// {
///   "node_type": "call_expression",
///   "node_text": "db.query(userInput)",
///   "start_line": 42,
///   "end_line": 42,
///   "start_col": 4,
///   "end_col": 27,
///   "file_path": "src/main/java/App.java"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeData {
    /// The tree-sitter node type (e.g. `call_expression`, `identifier`).
    pub node_type: String,

    /// The source text covered by this node.
    pub node_text: String,

    /// Starting line number (1-based).
    pub start_line: u32,

    /// Ending line number (1-based).
    pub end_line: u32,

    /// Starting column number (0-based byte offset).
    pub start_col: u32,

    /// Ending column number (0-based byte offset).
    pub end_col: u32,

    /// Path to the source file being analyzed.
    pub file_path: String,
}

// ---------------------------------------------------------------------------
// PluginFinding
// ---------------------------------------------------------------------------

/// A single finding produced by a compiled rule plugin's `rule_evaluate()`.
///
/// The plugin returns a JSON array of these structs from `rule_evaluate()`.
///
/// # Example JSON
///
/// ```json
/// {
///   "message": "Potential SQL injection: user input flows to db.query()",
///   "line": 42,
///   "column": 4
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFinding {
    /// Human-readable description of the finding.
    pub message: String,

    /// Line number where the finding was detected (1-based).
    pub line: u32,

    /// Column number where the finding was detected (0-based byte offset).
    pub column: u32,
}

// ---------------------------------------------------------------------------
// CompiledRule
// ---------------------------------------------------------------------------

/// A loaded and callable compiled rule.
///
/// Holds the plugin metadata and, once loading is implemented, the internal
/// function pointers obtained from the shared library.
#[derive(Debug)]
pub struct CompiledRule {
    /// Metadata returned by the plugin's `rule_metadata()` function.
    pub metadata: PluginMetadata,
}

impl CompiledRule {
    /// Evaluates this compiled rule against the given AST node.
    ///
    /// When fully implemented, this will serialize `node` to JSON, call the
    /// plugin's `rule_evaluate()` FFI function, and deserialize the returned
    /// findings.
    ///
    /// # Errors
    ///
    /// - [`CompiledRuleError::InvalidData`] if the plugin returns unparseable
    ///   JSON.
    /// - [`CompiledRuleError::Unsupported`] if loading is not yet available.
    pub fn evaluate(&self, _node: &NodeData) -> Result<Vec<PluginFinding>, CompiledRuleError> {
        Err(CompiledRuleError::Unsupported(
            "compiled rule evaluation is not yet implemented; \
             the libloading dependency is required"
                .into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Expected C ABI function signatures (documentation only)
// ---------------------------------------------------------------------------

/// Type alias for the `rule_metadata` C ABI function.
///
/// ```c
/// const char* rule_metadata();
/// ```
///
/// Returns a JSON string representing [`PluginMetadata`]. The caller must
/// free the returned pointer with [`RuleFreeStringFn`].
pub type RuleMetadataFn = unsafe extern "C" fn() -> *mut std::ffi::c_char;

/// Type alias for the `rule_evaluate` C ABI function.
///
/// ```c
/// const char* rule_evaluate(const char* node_json);
/// ```
///
/// Accepts a JSON string representing [`NodeData`] and returns a JSON array
/// of [`PluginFinding`]. The caller must free the returned pointer with
/// [`RuleFreeStringFn`].
pub type RuleEvaluateFn = unsafe extern "C" fn(*const std::ffi::c_char) -> *mut std::ffi::c_char;

/// Type alias for the `rule_free_string` C ABI function.
///
/// ```c
/// void rule_free_string(const char* s);
/// ```
///
/// Frees a string previously returned by [`RuleMetadataFn`] or
/// [`RuleEvaluateFn`]. Must be called exactly once per returned pointer.
pub type RuleFreeStringFn = unsafe extern "C" fn(*mut std::ffi::c_char);

/// The symbol name exported by plugins for `rule_metadata`.
pub const SYMBOL_METADATA: &str = "rule_metadata";

/// The symbol name exported by plugins for `rule_evaluate`.
pub const SYMBOL_EVALUATE: &str = "rule_evaluate";

/// The symbol name exported by plugins for `rule_free_string`.
pub const SYMBOL_FREE_STRING: &str = "rule_free_string";

// ---------------------------------------------------------------------------
// CompiledRuleLoader
// ---------------------------------------------------------------------------

/// Loads compiled SAST rule plugins from shared libraries.
///
/// Each shared library must export the three C ABI functions defined in the
/// module-level documentation: `rule_metadata`, `rule_evaluate`, and
/// `rule_free_string`.
///
/// # Current Status
///
/// Loading is not yet implemented because the `libloading` crate is not a
/// workspace dependency. Calling [`CompiledRuleLoader::load`] will return
/// [`CompiledRuleError::Unsupported`]. The ABI contract and interchange
/// types are fully defined and stable.
///
/// # Future Usage
///
/// ```no_run
/// use std::path::Path;
/// use atlas_rules::compiled::CompiledRuleLoader;
///
/// let loader = CompiledRuleLoader::new();
/// let rule = loader.load(Path::new("plugins/my_rule.so")).unwrap();
/// println!("Loaded rule: {}", rule.metadata.id);
/// ```
pub struct CompiledRuleLoader;

impl CompiledRuleLoader {
    /// Creates a new compiled rule loader.
    pub fn new() -> Self {
        Self
    }

    /// Loads a compiled rule plugin from the given shared library path.
    ///
    /// The path should point to a valid shared library for the current
    /// platform (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows).
    ///
    /// # Errors
    ///
    /// - [`CompiledRuleError::Unsupported`] -- always returned in the
    ///   current build because `libloading` is not yet available.
    /// - [`CompiledRuleError::LoadError`] -- the shared library could not
    ///   be loaded (future).
    /// - [`CompiledRuleError::AbiError`] -- a required symbol is missing
    ///   (future).
    /// - [`CompiledRuleError::InvalidData`] -- `rule_metadata()` returned
    ///   unparseable JSON (future).
    pub fn load(&self, path: &Path) -> Result<CompiledRule, CompiledRuleError> {
        // Validate that the path at least looks like a shared library.
        validate_plugin_extension(path)?;

        Err(CompiledRuleError::Unsupported(
            "compiled rule plugin loading requires the `libloading` \
             crate which is not yet a workspace dependency"
                .into(),
        ))
    }

    /// Returns the platform-specific shared library extension.
    ///
    /// - Linux: `.so`
    /// - macOS: `.dylib`
    /// - Windows: `.dll`
    pub fn platform_extension() -> &'static str {
        if cfg!(target_os = "linux") {
            "so"
        } else if cfg!(target_os = "macos") {
            "dylib"
        } else if cfg!(target_os = "windows") {
            "dll"
        } else {
            "so"
        }
    }
}

impl Default for CompiledRuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates that the file path has a recognized shared library extension.
///
/// Returns `Ok(())` if the extension is `.so`, `.dylib`, or `.dll`.
///
/// # Errors
///
/// Returns [`CompiledRuleError::LoadError`] if the extension is missing
/// or unrecognized.
fn validate_plugin_extension(path: &Path) -> Result<(), CompiledRuleError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("so" | "dylib" | "dll") => Ok(()),
        Some(ext) => Err(CompiledRuleError::LoadError {
            path: path.to_path_buf(),
            reason: format!(
                "unrecognized shared library extension '.{ext}'; \
                 expected .so, .dylib, or .dll"
            ),
        }),
        None => Err(CompiledRuleError::LoadError {
            path: path.to_path_buf(),
            reason: "file has no extension; expected .so, .dylib, or .dll".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // PluginMetadata serialization
    // -------------------------------------------------------------------

    #[test]
    fn plugin_metadata_serialization_roundtrip() {
        let metadata = PluginMetadata {
            id: "atlas/security/java/sql-injection-native".into(),
            name: "SQL Injection (native)".into(),
            severity: "high".into(),
            category: "security".into(),
            language: "Java".into(),
            description: "Detects SQL injection via native analysis.".into(),
            cwe_id: Some("CWE-89".into()),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: PluginMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn plugin_metadata_with_all_fields() {
        let json = r#"{
            "id": "atlas/security/python/cmd-injection",
            "name": "Command Injection",
            "severity": "critical",
            "category": "security",
            "language": "Python",
            "description": "Detects OS command injection.",
            "cwe_id": "CWE-78"
        }"#;

        let metadata: PluginMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.id, "atlas/security/python/cmd-injection");
        assert_eq!(metadata.severity, "critical");
        assert_eq!(metadata.cwe_id, Some("CWE-78".into()));
    }

    #[test]
    fn plugin_metadata_without_optional_cwe_id() {
        let json = r#"{
            "id": "atlas/quality/go/unused-export",
            "name": "Unused Export",
            "severity": "info",
            "category": "quality",
            "language": "Go",
            "description": "Detects unused exported identifiers."
        }"#;

        let metadata: PluginMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.id, "atlas/quality/go/unused-export");
        assert!(metadata.cwe_id.is_none());
    }

    #[test]
    fn plugin_metadata_skips_none_cwe_id_in_json() {
        let metadata = PluginMetadata {
            id: "test/rule".into(),
            name: "Test".into(),
            severity: "low".into(),
            category: "quality".into(),
            language: "Rust".into(),
            description: "A test rule.".into(),
            cwe_id: None,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(
            !json.contains("cwe_id"),
            "cwe_id should be skipped when None"
        );
    }

    // -------------------------------------------------------------------
    // PluginFinding serialization
    // -------------------------------------------------------------------

    #[test]
    fn plugin_finding_serialization_roundtrip() {
        let finding = PluginFinding {
            message: "Potential SQL injection at db.query()".into(),
            line: 42,
            column: 8,
        };

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: PluginFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, deserialized);
    }

    #[test]
    fn plugin_finding_array_roundtrip() {
        let findings = vec![
            PluginFinding {
                message: "First finding".into(),
                line: 10,
                column: 0,
            },
            PluginFinding {
                message: "Second finding".into(),
                line: 25,
                column: 12,
            },
        ];

        let json = serde_json::to_string(&findings).unwrap();
        let deserialized: Vec<PluginFinding> = serde_json::from_str(&json).unwrap();
        assert_eq!(findings, deserialized);
    }

    // -------------------------------------------------------------------
    // NodeData serialization
    // -------------------------------------------------------------------

    #[test]
    fn node_data_serialization_roundtrip() {
        let node = NodeData {
            node_type: "call_expression".into(),
            node_text: "db.query(userInput)".into(),
            start_line: 42,
            end_line: 42,
            start_col: 4,
            end_col: 27,
            file_path: "src/main/java/App.java".into(),
        };

        let json = serde_json::to_string(&node).unwrap();
        let deserialized: NodeData = serde_json::from_str(&json).unwrap();
        assert_eq!(node, deserialized);
    }

    #[test]
    fn node_data_json_structure_matches_abi_contract() {
        let node = NodeData {
            node_type: "identifier".into(),
            node_text: "password".into(),
            start_line: 1,
            end_line: 1,
            start_col: 0,
            end_col: 8,
            file_path: "test.py".into(),
        };

        let json = serde_json::to_string(&node).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify every expected field is present with the correct type.
        assert_eq!(value["node_type"], "identifier");
        assert_eq!(value["node_text"], "password");
        assert_eq!(value["start_line"], 1);
        assert_eq!(value["end_line"], 1);
        assert_eq!(value["start_col"], 0);
        assert_eq!(value["end_col"], 8);
        assert_eq!(value["file_path"], "test.py");

        // Verify there are no unexpected fields.
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 7, "NodeData should have exactly 7 fields");
    }

    // -------------------------------------------------------------------
    // CompiledRuleLoader
    // -------------------------------------------------------------------

    #[test]
    fn compiled_rule_loader_new_creates_instance() {
        let _loader = CompiledRuleLoader::new();
        // Verify it can also be created via Default (unit struct).
        let _loader2 = CompiledRuleLoader;
    }

    #[test]
    fn load_returns_unsupported_error() {
        let loader = CompiledRuleLoader::new();
        let result = loader.load(Path::new("plugin.so"));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::Unsupported(_)),
            "expected Unsupported error, got: {err}"
        );
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn load_rejects_invalid_extension() {
        let loader = CompiledRuleLoader::new();
        let result = loader.load(Path::new("plugin.txt"));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::LoadError { .. }),
            "expected LoadError for invalid extension, got: {err}"
        );
        assert!(err.to_string().contains("unrecognized"));
    }

    #[test]
    fn load_rejects_path_without_extension() {
        let loader = CompiledRuleLoader::new();
        let result = loader.load(Path::new("plugin"));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::LoadError { .. }),
            "expected LoadError for missing extension, got: {err}"
        );
        assert!(err.to_string().contains("no extension"));
    }

    #[test]
    fn load_accepts_so_extension_before_unsupported() {
        let loader = CompiledRuleLoader::new();
        let result = loader.load(Path::new("rules/my_rule.so"));

        // Should pass extension validation and fail at Unsupported.
        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::Unsupported(_)),
            "expected Unsupported for .so, got: {err}"
        );
    }

    #[test]
    fn load_accepts_dylib_extension_before_unsupported() {
        let loader = CompiledRuleLoader::new();
        let result = loader.load(Path::new("rules/my_rule.dylib"));

        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::Unsupported(_)),
            "expected Unsupported for .dylib, got: {err}"
        );
    }

    #[test]
    fn load_accepts_dll_extension_before_unsupported() {
        let loader = CompiledRuleLoader::new();
        let result = loader.load(Path::new("rules/my_rule.dll"));

        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::Unsupported(_)),
            "expected Unsupported for .dll, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // CompiledRule
    // -------------------------------------------------------------------

    #[test]
    fn compiled_rule_evaluate_returns_unsupported() {
        let rule = CompiledRule {
            metadata: PluginMetadata {
                id: "test/rule".into(),
                name: "Test Rule".into(),
                severity: "low".into(),
                category: "quality".into(),
                language: "Rust".into(),
                description: "A test rule.".into(),
                cwe_id: None,
            },
        };

        let node = NodeData {
            node_type: "identifier".into(),
            node_text: "x".into(),
            start_line: 1,
            end_line: 1,
            start_col: 0,
            end_col: 1,
            file_path: "test.rs".into(),
        };

        let result = rule.evaluate(&node);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CompiledRuleError::Unsupported(_)),
            "expected Unsupported error, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // Platform extension
    // -------------------------------------------------------------------

    #[test]
    fn platform_extension_returns_valid_value() {
        let ext = CompiledRuleLoader::platform_extension();
        assert!(
            ["so", "dylib", "dll"].contains(&ext),
            "unexpected platform extension: {ext}"
        );
    }

    // -------------------------------------------------------------------
    // Error display messages
    // -------------------------------------------------------------------

    #[test]
    fn error_display_unsupported() {
        let err = CompiledRuleError::Unsupported("test reason".into());
        assert!(err.to_string().contains("not supported"));
        assert!(err.to_string().contains("test reason"));
    }

    #[test]
    fn error_display_load_error() {
        let err = CompiledRuleError::LoadError {
            path: PathBuf::from("bad/plugin.so"),
            reason: "file not found".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad/plugin.so"));
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn error_display_abi_error() {
        let err = CompiledRuleError::AbiError {
            path: PathBuf::from("plugin.so"),
            symbol: "rule_metadata".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("plugin.so"));
        assert!(msg.contains("rule_metadata"));
    }

    #[test]
    fn error_display_invalid_data() {
        let err = CompiledRuleError::InvalidData {
            reason: "bad json".into(),
        };
        assert!(err.to_string().contains("bad json"));
    }

    // -------------------------------------------------------------------
    // ABI symbol constants
    // -------------------------------------------------------------------

    #[test]
    fn abi_symbol_names_are_correct() {
        assert_eq!(SYMBOL_METADATA, "rule_metadata");
        assert_eq!(SYMBOL_EVALUATE, "rule_evaluate");
        assert_eq!(SYMBOL_FREE_STRING, "rule_free_string");
    }

    // -------------------------------------------------------------------
    // validate_plugin_extension helper
    // -------------------------------------------------------------------

    #[test]
    fn validate_extension_accepts_all_valid_extensions() {
        assert!(validate_plugin_extension(Path::new("a.so")).is_ok());
        assert!(validate_plugin_extension(Path::new("a.dylib")).is_ok());
        assert!(validate_plugin_extension(Path::new("a.dll")).is_ok());
    }

    #[test]
    fn validate_extension_rejects_invalid_extensions() {
        assert!(validate_plugin_extension(Path::new("a.txt")).is_err());
        assert!(validate_plugin_extension(Path::new("a.rs")).is_err());
        assert!(validate_plugin_extension(Path::new("a.py")).is_err());
    }

    #[test]
    fn validate_extension_rejects_no_extension() {
        assert!(validate_plugin_extension(Path::new("plugin")).is_err());
        assert!(validate_plugin_extension(Path::new("path/to/plugin")).is_err());
    }
}
