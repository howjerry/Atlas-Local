//! Python language adapter.
//!
//! This module provides [`PythonAdapter`], which implements [`LanguageAdapter`]
//! for Python (`.py`) and Python stub (`.pyi`) files. It uses the
//! `tree-sitter-python` grammar crate for parsing.
//!
//! # Thread Safety
//!
//! Same as other adapters -- each parse call creates a fresh parser,
//! so the adapter itself is `Send + Sync`.

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// PythonAdapter
// ---------------------------------------------------------------------------

/// Language adapter for Python and Python stub files.
///
/// Uses the `tree-sitter-python` grammar crate. Both `.py` (source) and
/// `.pyi` (type stub) files use the same grammar.
///
/// # Thread Safety
///
/// Each call to [`parse`](Self::parse) creates a new [`tree_sitter::Parser`]
/// internally, because `Parser` is `!Send`. This means the adapter itself is
/// `Send + Sync` and can be shared across threads safely.
#[derive(Debug, Clone, Copy)]
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn extensions(&self) -> &[&str] {
        &["py", "pyi"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(
            language = "Python",
            source_len = source.len(),
            "parsing source"
        );

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Registers the [`PythonAdapter`] into an existing
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry).
pub fn register_python_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(PythonAdapter));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::AdapterRegistry;

    #[test]
    fn adapter_metadata() {
        let adapter = PythonAdapter;
        assert_eq!(adapter.language(), Language::Python);
        assert_eq!(adapter.extensions(), &["py", "pyi"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = PythonAdapter;
        let source = b"def hello():\n    return \"world\"";
        let tree = adapter.parse(source).expect("should parse valid Python");
        let root = tree.root_node();
        assert_eq!(root.kind(), "module");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_class() {
        let adapter = PythonAdapter;
        let source = br#"
class Greeter:
    def __init__(self, name: str):
        self.name = name

    def greet(self) -> str:
        return f"Hello, {self.name}!"
"#;
        let tree = adapter.parse(source).expect("should parse Python class");
        let root = tree.root_node();
        assert_eq!(root.kind(), "module");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_with_type_hints() {
        let adapter = PythonAdapter;
        let source = b"def add(a: int, b: int) -> int:\n    return a + b";
        let tree = adapter
            .parse(source)
            .expect("should parse Python with type hints");
        let root = tree.root_node();
        assert_eq!(root.kind(), "module");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = PythonAdapter;
        let tree = adapter.parse(b"").expect("empty Python source should parse");
        assert_eq!(tree.root_node().kind(), "module");
    }

    #[test]
    fn register_python_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_python_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("py").is_some());
        assert!(registry.get_by_extension("pyi").is_some());
        assert!(registry.get_by_language(Language::Python).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let lang = PythonAdapter.tree_sitter_language();
        // Should have a non-zero node kind count (basic sanity check).
        assert!(lang.node_kind_count() > 0);
    }
}
