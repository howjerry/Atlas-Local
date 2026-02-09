//! PHP 語言適配器。
//!
//! 提供 [`PhpAdapter`]，實作 [`LanguageAdapter`] 以支援 PHP（`.php`）檔案。
//! 使用 `tree-sitter-php` grammar crate 的 `LANGUAGE_PHP` grammar 進行解析，
//! 可正確處理混合 HTML + PHP 的檔案。

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// PhpAdapter
// ---------------------------------------------------------------------------

/// PHP 語言適配器。
///
/// 使用 `tree-sitter-php` grammar crate 的 `LANGUAGE_PHP` 進行解析，
/// 支援含 `<?php` 標籤的標準 PHP 檔案（含混合 HTML）。
///
/// # 執行緒安全
///
/// 每次呼叫 [`parse`](Self::parse) 都建立新的 [`tree_sitter::Parser`]，
/// 因此本適配器為 `Send + Sync`，可安全跨執行緒共用。
#[derive(Debug, Clone, Copy)]
pub struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language(&self) -> Language {
        Language::Php
    }

    fn extensions(&self) -> &[&str] {
        &["php"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang)?;

        debug!(language = "PHP", source_len = source.len(), "parsing source");

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// 將 [`PhpAdapter`] 註冊至既有的
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry)。
pub fn register_php_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(PhpAdapter));
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
        let adapter = PhpAdapter;
        assert_eq!(adapter.language(), Language::Php);
        assert_eq!(adapter.extensions(), &["php"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = PhpAdapter;
        let source = b"<?php\necho 'Hello, World!';\n?>";
        let tree = adapter.parse(source).expect("should parse valid PHP");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_class() {
        let adapter = PhpAdapter;
        let source = br#"<?php
class Greeter {
    private string $name;

    public function __construct(string $name) {
        $this->name = $name;
    }

    public function greet(): string {
        return "Hello, {$this->name}!";
    }
}
"#;
        let tree = adapter.parse(source).expect("should parse PHP class");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = PhpAdapter;
        let tree = adapter
            .parse(b"")
            .expect("empty PHP source should parse");
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn register_php_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_php_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("php").is_some());
        assert!(registry.get_by_language(Language::Php).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let lang = PhpAdapter.tree_sitter_language();
        assert!(lang.node_kind_count() > 0);
    }
}
