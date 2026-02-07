//! Java language adapter.
//!
//! This module provides [`JavaAdapter`], which implements [`LanguageAdapter`]
//! for Java source files (`.java`). It uses the `tree-sitter-java` grammar
//! crate for parsing.
//!
//! # Thread Safety
//!
//! Same as [`TypeScriptAdapter`](crate::typescript::TypeScriptAdapter) -- each
//! parse call creates a fresh parser, so the adapter itself is `Send + Sync`.

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// JavaAdapter
// ---------------------------------------------------------------------------

/// Language adapter for Java source files.
///
/// Uses the `tree-sitter-java` grammar crate. Handles `.java` files.
///
/// # Thread Safety
///
/// Each call to [`parse`](Self::parse) creates a new [`tree_sitter::Parser`]
/// internally, because `Parser` is `!Send`. This means the adapter itself is
/// `Send + Sync` and can be shared across threads safely.
#[derive(Debug, Clone, Copy)]
pub struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn language(&self) -> Language {
        Language::Java
    }

    fn extensions(&self) -> &[&str] {
        &["java"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(
            language = "Java",
            source_len = source.len(),
            "parsing source"
        );

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_java::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Registers the [`JavaAdapter`] into an existing
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry).
///
/// This is a convenience function for callers that want to add Java support
/// to a registry that may already contain other language adapters.
pub fn register_java_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(JavaAdapter));
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
        let adapter = JavaAdapter;
        assert_eq!(adapter.language(), Language::Java);
        assert_eq!(adapter.extensions(), &["java"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = JavaAdapter;
        let source = b"public class Hello { public static void main(String[] args) {} }";
        let tree = adapter.parse(source).expect("should parse valid Java");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_with_generics() {
        let adapter = JavaAdapter;
        let source = br#"
            import java.util.List;
            import java.util.ArrayList;

            public class GenericExample {
                public <T extends Comparable<T>> List<T> sort(List<T> items) {
                    List<T> result = new ArrayList<>(items);
                    result.sort(null);
                    return result;
                }
            }
        "#;
        let tree = adapter
            .parse(source)
            .expect("should parse Java with generics");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = JavaAdapter;
        let tree = adapter.parse(b"").expect("empty Java source should parse");
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn register_java_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_java_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("java").is_some());
        assert!(registry.get_by_language(Language::Java).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let lang = JavaAdapter.tree_sitter_language();
        // Should have a non-zero node kind count (basic sanity check).
        assert!(lang.node_kind_count() > 0);
    }
}
