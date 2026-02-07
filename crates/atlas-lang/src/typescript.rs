//! TypeScript and JavaScript language adapters.
//!
//! This module provides [`TypeScriptAdapter`] and [`JavaScriptAdapter`],
//! which implement [`LanguageAdapter`] for TypeScript/TSX and
//! JavaScript/JSX respectively. They live in the same file because they
//! share a nearly identical implementation pattern and both originate from
//! the tree-sitter-typescript / tree-sitter-javascript grammar crates.

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// TypeScriptAdapter
// ---------------------------------------------------------------------------

/// Language adapter for TypeScript and TSX files.
///
/// Uses the `tree-sitter-typescript` grammar crate. TSX is handled via the
/// dedicated TSX grammar (`LANGUAGE_TSX`) so that JSX syntax in `.tsx` files
/// parses correctly.
///
/// # Thread Safety
///
/// Each call to [`parse`](Self::parse) creates a new [`tree_sitter::Parser`]
/// internally, because `Parser` is `!Send`. This means the adapter itself is
/// `Send + Sync` and can be shared across threads safely.
#[derive(Debug, Clone, Copy)]
pub struct TypeScriptAdapter;

impl LanguageAdapter for TypeScriptAdapter {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn extensions(&self) -> &[&str] {
        &["ts", "tsx"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        // Use the TSX grammar so that both .ts and .tsx files parse correctly.
        // The TSX grammar is a strict superset of the TypeScript grammar.
        let lang: tree_sitter::Language = tree_sitter_typescript::LANGUAGE_TSX.into();
        parser.set_language(&lang)?;

        debug!(
            language = "TypeScript",
            source_len = source.len(),
            "parsing source"
        );

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    }
}

// ---------------------------------------------------------------------------
// JavaScriptAdapter
// ---------------------------------------------------------------------------

/// Language adapter for JavaScript and JSX files.
///
/// Uses the `tree-sitter-javascript` grammar crate. The JavaScript grammar
/// handles JSX syntax natively, so `.jsx` files parse correctly without a
/// separate grammar.
///
/// # Thread Safety
///
/// Same as [`TypeScriptAdapter`] -- each parse call creates a fresh parser.
#[derive(Debug, Clone, Copy)]
pub struct JavaScriptAdapter;

impl LanguageAdapter for JavaScriptAdapter {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn extensions(&self) -> &[&str] {
        &["js", "jsx", "mjs", "cjs"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(
            language = "JavaScript",
            source_len = source.len(),
            "parsing source"
        );

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_javascript::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Creates an [`AdapterRegistry`](crate::adapter::AdapterRegistry) pre-loaded
/// with all TypeScript and JavaScript adapters.
///
/// This is a convenience function for callers that want the default set of
/// JS/TS adapters without manually registering each one.
pub fn register_js_ts_adapters(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(TypeScriptAdapter));
    registry.register(Box::new(JavaScriptAdapter));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::AdapterRegistry;

    #[test]
    fn typescript_adapter_metadata() {
        let adapter = TypeScriptAdapter;
        assert_eq!(adapter.language(), Language::TypeScript);
        assert_eq!(adapter.extensions(), &["ts", "tsx"]);
    }

    #[test]
    fn javascript_adapter_metadata() {
        let adapter = JavaScriptAdapter;
        assert_eq!(adapter.language(), Language::JavaScript);
        assert_eq!(adapter.extensions(), &["js", "jsx", "mjs", "cjs"]);
    }

    #[test]
    fn typescript_parse_simple() {
        let adapter = TypeScriptAdapter;
        let source = b"const x: number = 42;";
        let tree = adapter.parse(source).expect("should parse valid TypeScript");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn typescript_parse_tsx() {
        let adapter = TypeScriptAdapter;
        let source = b"const App = () => <div>Hello</div>;";
        let tree = adapter.parse(source).expect("should parse valid TSX");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn javascript_parse_simple() {
        let adapter = JavaScriptAdapter;
        let source = b"const x = 42;";
        let tree = adapter.parse(source).expect("should parse valid JavaScript");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn javascript_parse_jsx() {
        let adapter = JavaScriptAdapter;
        let source = b"const App = () => <div>Hello</div>;";
        let tree = adapter.parse(source).expect("should parse valid JSX");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn javascript_parse_esm() {
        let adapter = JavaScriptAdapter;
        let source = b"import { foo } from 'bar';\nexport default foo;";
        let tree = adapter.parse(source).expect("should parse ESM syntax");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn javascript_parse_cjs() {
        let adapter = JavaScriptAdapter;
        let source = b"const foo = require('bar');\nmodule.exports = foo;";
        let tree = adapter.parse(source).expect("should parse CJS syntax");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn register_js_ts_adapters_works() {
        let mut registry = AdapterRegistry::new();
        register_js_ts_adapters(&mut registry);

        assert_eq!(registry.len(), 2);
        assert!(registry.get_by_extension("ts").is_some());
        assert!(registry.get_by_extension("tsx").is_some());
        assert!(registry.get_by_extension("js").is_some());
        assert!(registry.get_by_extension("jsx").is_some());
        assert!(registry.get_by_extension("mjs").is_some());
        assert!(registry.get_by_extension("cjs").is_some());

        assert!(registry.get_by_language(Language::TypeScript).is_some());
        assert!(registry.get_by_language(Language::JavaScript).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        // Verify that the tree-sitter Language objects can be obtained
        // without panicking.
        let ts_lang = TypeScriptAdapter.tree_sitter_language();
        let js_lang = JavaScriptAdapter.tree_sitter_language();

        // Both should have a non-zero node kind count (basic sanity check).
        assert!(ts_lang.node_kind_count() > 0);
        assert!(js_lang.node_kind_count() > 0);
    }

    #[test]
    fn parse_empty_source() {
        // An empty file should still parse successfully (produces an empty program node).
        let ts_tree = TypeScriptAdapter.parse(b"").expect("empty TS source should parse");
        assert_eq!(ts_tree.root_node().kind(), "program");

        let js_tree = JavaScriptAdapter.parse(b"").expect("empty JS source should parse");
        assert_eq!(js_tree.root_node().kind(), "program");
    }
}
