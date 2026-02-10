//! Ruby 語言適配器。
//!
//! 提供 [`RubyAdapter`]，實作 [`LanguageAdapter`] 以支援 Ruby（`.rb`）檔案。
//! 使用 `tree-sitter-ruby` grammar crate 進行解析。

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// RubyAdapter
// ---------------------------------------------------------------------------

/// Ruby 語言適配器。
///
/// 使用 `tree-sitter-ruby` grammar crate 進行解析。
///
/// # 執行緒安全
///
/// 每次呼叫 [`parse`](Self::parse) 都建立新的 [`tree_sitter::Parser`]，
/// 因此本適配器為 `Send + Sync`，可安全跨執行緒共用。
#[derive(Debug, Clone, Copy)]
pub struct RubyAdapter;

impl LanguageAdapter for RubyAdapter {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn extensions(&self) -> &[&str] {
        &["rb"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = tree_sitter_ruby::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(language = "Ruby", source_len = source.len(), "parsing source");

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_ruby::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// 將 [`RubyAdapter`] 註冊至既有的
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry)。
pub fn register_ruby_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(RubyAdapter));
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
        let adapter = RubyAdapter;
        assert_eq!(adapter.language(), Language::Ruby);
        assert_eq!(adapter.extensions(), &["rb"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = RubyAdapter;
        let source = b"def hello\n  puts 'world'\nend";
        let tree = adapter.parse(source).expect("should parse valid Ruby");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_class() {
        let adapter = RubyAdapter;
        let source = br#"
class Greeter
  def initialize(name)
    @name = name
  end

  def greet
    "Hello, #{@name}!"
  end
end
"#;
        let tree = adapter.parse(source).expect("should parse Ruby class");
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = RubyAdapter;
        let tree = adapter
            .parse(b"")
            .expect("empty Ruby source should parse");
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn register_ruby_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_ruby_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("rb").is_some());
        assert!(registry.get_by_language(Language::Ruby).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let lang = RubyAdapter.tree_sitter_language();
        assert!(lang.node_kind_count() > 0);
    }

}
