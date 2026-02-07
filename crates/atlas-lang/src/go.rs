//! Go language adapter.
//!
//! This module provides [`GoAdapter`], which implements [`LanguageAdapter`]
//! for Go (`.go`) files. It uses the `tree-sitter-go` grammar crate.

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// GoAdapter
// ---------------------------------------------------------------------------

/// Language adapter for Go source files.
///
/// Uses the `tree-sitter-go` grammar crate for parsing.
///
/// # Thread Safety
///
/// Each call to [`parse`](Self::parse) creates a new [`tree_sitter::Parser`]
/// internally, because `Parser` is `!Send`. This means the adapter itself is
/// `Send + Sync` and can be shared across threads safely.
#[derive(Debug, Clone, Copy)]
pub struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn language(&self) -> Language {
        Language::Go
    }

    fn extensions(&self) -> &[&str] {
        &["go"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(language = "Go", source_len = source.len(), "parsing source");

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_go::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Registers the [`GoAdapter`] into an existing
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry).
///
/// This is a convenience function for callers that want to add Go support
/// without manually constructing and registering the adapter.
pub fn register_go_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(GoAdapter));
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
        let adapter = GoAdapter;
        assert_eq!(adapter.language(), Language::Go);
        assert_eq!(adapter.extensions(), &["go"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = GoAdapter;
        let source = b"package main\nfunc main() {}";
        let tree = adapter.parse(source).expect("should parse valid Go");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_with_struct() {
        let adapter = GoAdapter;
        let source = br#"
package main

type User struct {
    Name string
    Age  int
}
"#;
        let tree = adapter.parse(source).expect("should parse Go struct");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_with_interface() {
        let adapter = GoAdapter;
        let source = br#"
package main

type Reader interface {
    Read(p []byte) (n int, err error)
}
"#;
        let tree = adapter.parse(source).expect("should parse Go interface");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = GoAdapter;
        // An empty Go source file is syntactically incomplete (no `package` clause),
        // so tree-sitter may produce a tree with error nodes. We verify that
        // parsing itself does not fail (returns a tree), but the tree will
        // contain errors because a valid Go file requires `package <name>`.
        let tree = adapter
            .parse(b"")
            .expect("empty source should still produce a tree");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        // Empty source may or may not have errors depending on the grammar;
        // we simply verify parsing succeeds.
    }

    #[test]
    fn register_go_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_go_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("go").is_some());
        assert!(registry.get_by_language(Language::Go).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let go_lang = GoAdapter.tree_sitter_language();
        // Should have a non-zero node kind count (basic sanity check).
        assert!(go_lang.node_kind_count() > 0);
    }
}
