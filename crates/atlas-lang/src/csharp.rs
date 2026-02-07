//! C# language adapter.
//!
//! This module provides [`CSharpAdapter`], which implements
//! [`LanguageAdapter`] for C# (`.cs`) files using the
//! `tree-sitter-c-sharp` grammar crate.
//!
//! # Thread Safety
//!
//! Each call to [`parse`](CSharpAdapter::parse) creates a new
//! [`tree_sitter::Parser`] internally, because `Parser` is `!Send`.
//! This means the adapter itself is `Send + Sync` and can be shared
//! across threads safely.

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// CSharpAdapter
// ---------------------------------------------------------------------------

/// Language adapter for C# files.
///
/// Uses the `tree-sitter-c-sharp` grammar crate to parse `.cs` files.
#[derive(Debug, Clone, Copy)]
pub struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn extensions(&self) -> &[&str] {
        &["cs"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(
            language = "CSharp",
            source_len = source.len(),
            "parsing source"
        );

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_c_sharp::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// Registers a [`CSharpAdapter`] into the given
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry).
pub fn register_csharp_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(CSharpAdapter));
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
        let adapter = CSharpAdapter;
        assert_eq!(adapter.language(), Language::CSharp);
        assert_eq!(adapter.extensions(), &["cs"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = CSharpAdapter;
        let source = b"class Hello { static void Main() {} }";
        let tree = adapter.parse(source).expect("should parse valid C#");
        let root = tree.root_node();
        assert_eq!(root.kind(), "compilation_unit");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_with_namespace() {
        let adapter = CSharpAdapter;
        let source = br#"
namespace MyApp
{
    using System;

    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
        }
    }
}
"#;
        let tree = adapter
            .parse(source)
            .expect("should parse C# with namespace");
        let root = tree.root_node();
        assert_eq!(root.kind(), "compilation_unit");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_with_generics() {
        let adapter = CSharpAdapter;
        let source = br#"
public class Container<T> where T : class
{
    private T _value;

    public T GetValue() { return _value; }

    public void SetValue(T value) { _value = value; }
}
"#;
        let tree = adapter.parse(source).expect("should parse C# generics");
        let root = tree.root_node();
        assert_eq!(root.kind(), "compilation_unit");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = CSharpAdapter;
        let tree = adapter.parse(b"").expect("empty C# source should parse");
        assert_eq!(tree.root_node().kind(), "compilation_unit");
    }

    #[test]
    fn register_csharp_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_csharp_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("cs").is_some());
        assert!(registry.get_by_language(Language::CSharp).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let lang = CSharpAdapter.tree_sitter_language();
        // Should have a non-zero node kind count (basic sanity check).
        assert!(lang.node_kind_count() > 0);
    }
}
