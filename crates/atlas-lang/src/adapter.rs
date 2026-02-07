//! Language adapter trait and adapter registry.
//!
//! The [`LanguageAdapter`] trait defines the interface that every language
//! backend must implement. Each adapter knows how to create a tree-sitter
//! parser for its language, parse source code, and report which file
//! extensions it handles.
//!
//! The [`AdapterRegistry`] collects adapters and provides lookup by file
//! extension or [`Language`] variant.

use std::collections::HashMap;

#[cfg(test)]
use crate::error::LangError;
use crate::error::LangResult;
use crate::language::Language;

// ---------------------------------------------------------------------------
// LanguageAdapter trait
// ---------------------------------------------------------------------------

/// A language backend that can parse source code via tree-sitter.
///
/// Implementations must be `Send + Sync` so that adapters can be shared
/// across threads during parallel scanning. Each call to [`parse`](Self::parse)
/// creates a fresh `Parser` internally, avoiding the `!Send` constraint of
/// `tree_sitter::Parser`.
pub trait LanguageAdapter: Send + Sync {
    /// Returns the [`Language`] variant this adapter handles.
    fn language(&self) -> Language;

    /// Returns the file extensions this adapter handles **without** the leading dot.
    ///
    /// For example, a TypeScript adapter returns `&["ts", "tsx"]`.
    fn extensions(&self) -> &[&str];

    /// Parse `source` into a tree-sitter [`Tree`](tree_sitter::Tree).
    ///
    /// Returns [`LangError::ParseFailed`] if the parser returns `None`.
    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree>;

    /// Returns the tree-sitter [`Language`](tree_sitter::Language) for this adapter.
    ///
    /// This is used to create queries and other tree-sitter objects that
    /// require a language reference.
    fn tree_sitter_language(&self) -> tree_sitter::Language;
}

// ---------------------------------------------------------------------------
// AdapterRegistry
// ---------------------------------------------------------------------------

/// A collection of registered [`LanguageAdapter`]s with lookup by extension
/// or [`Language`].
///
/// # Examples
///
/// ```ignore
/// let mut registry = AdapterRegistry::new();
/// registry.register(Box::new(TypeScriptAdapter));
/// registry.register(Box::new(JavaScriptAdapter));
///
/// let adapter = registry.get_by_extension("ts").unwrap();
/// let tree = adapter.parse(b"const x: number = 42;").unwrap();
/// ```
pub struct AdapterRegistry {
    /// Adapters indexed by their [`Language`] variant.
    adapters: HashMap<Language, Box<dyn LanguageAdapter>>,
    /// Maps bare file extensions (e.g. `"ts"`) to the [`Language`] they belong to.
    extension_map: HashMap<String, Language>,
}

impl AdapterRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
            extension_map: HashMap::new(),
        }
    }

    /// Registers a language adapter.
    ///
    /// If an adapter for the same [`Language`] was previously registered it is
    /// replaced. Extension mappings are updated to point to the new adapter.
    pub fn register(&mut self, adapter: Box<dyn LanguageAdapter>) {
        let lang = adapter.language();
        for ext in adapter.extensions() {
            self.extension_map.insert((*ext).to_owned(), lang);
        }
        self.adapters.insert(lang, adapter);
    }

    /// Looks up an adapter by bare file extension (without the leading dot).
    ///
    /// Returns `None` if no adapter handles the given extension.
    #[must_use]
    pub fn get_by_extension(&self, ext: &str) -> Option<&dyn LanguageAdapter> {
        let lang = self.extension_map.get(ext)?;
        self.adapters.get(lang).map(AsRef::as_ref)
    }

    /// Looks up an adapter by [`Language`].
    ///
    /// Returns `None` if no adapter is registered for the given language.
    #[must_use]
    pub fn get_by_language(&self, lang: Language) -> Option<&dyn LanguageAdapter> {
        self.adapters.get(&lang).map(AsRef::as_ref)
    }

    /// Returns the number of registered adapters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Returns `true` if no adapters are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// Returns an iterator over all registered languages.
    pub fn languages(&self) -> impl Iterator<Item = Language> + '_ {
        self.adapters.keys().copied()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("languages", &self.adapters.keys().collect::<Vec<_>>())
            .field("extensions", &self.extension_map.keys().collect::<Vec<_>>())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal stub adapter for testing the registry without requiring
    /// actual tree-sitter grammars.
    struct StubAdapter {
        lang: Language,
        exts: &'static [&'static str],
    }

    impl LanguageAdapter for StubAdapter {
        fn language(&self) -> Language {
            self.lang
        }

        fn extensions(&self) -> &[&str] {
            self.exts
        }

        fn parse(&self, _source: &[u8]) -> LangResult<tree_sitter::Tree> {
            Err(LangError::ParseFailed)
        }

        fn tree_sitter_language(&self) -> tree_sitter::Language {
            // Stub: return a dummy language. This will not be used in tests
            // that only exercise registry logic.
            unreachable!("stub adapter does not provide a real tree-sitter language")
        }
    }

    #[test]
    fn registry_register_and_lookup_by_extension() {
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(StubAdapter {
            lang: Language::TypeScript,
            exts: &["ts", "tsx"],
        }));

        assert!(registry.get_by_extension("ts").is_some());
        assert!(registry.get_by_extension("tsx").is_some());
        assert!(registry.get_by_extension("js").is_none());
    }

    #[test]
    fn registry_lookup_by_language() {
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(StubAdapter {
            lang: Language::JavaScript,
            exts: &["js", "jsx", "mjs", "cjs"],
        }));

        assert!(registry.get_by_language(Language::JavaScript).is_some());
        assert!(registry.get_by_language(Language::TypeScript).is_none());
    }

    #[test]
    fn registry_len_and_is_empty() {
        let mut registry = AdapterRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(Box::new(StubAdapter {
            lang: Language::TypeScript,
            exts: &["ts", "tsx"],
        }));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_replace_adapter() {
        let mut registry = AdapterRegistry::new();

        // Register first adapter for TypeScript with "ts" only.
        registry.register(Box::new(StubAdapter {
            lang: Language::TypeScript,
            exts: &["ts"],
        }));
        assert!(registry.get_by_extension("ts").is_some());
        assert!(registry.get_by_extension("tsx").is_none());

        // Replace with adapter that also handles "tsx".
        registry.register(Box::new(StubAdapter {
            lang: Language::TypeScript,
            exts: &["ts", "tsx"],
        }));
        assert!(registry.get_by_extension("ts").is_some());
        assert!(registry.get_by_extension("tsx").is_some());
        // Still only one adapter registered.
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_default() {
        let registry = AdapterRegistry::default();
        assert!(registry.is_empty());
    }
}
