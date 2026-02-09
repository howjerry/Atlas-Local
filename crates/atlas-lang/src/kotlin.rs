//! Kotlin 語言適配器。
//!
//! 提供 [`KotlinAdapter`]，實作 [`LanguageAdapter`] 以支援 Kotlin（`.kt`、`.kts`）檔案。
//! 使用 `tree-sitter-kotlin` grammar crate 進行解析。

use tracing::debug;

use crate::adapter::LanguageAdapter;
use crate::error::{LangError, LangResult};
use crate::language::Language;

// ---------------------------------------------------------------------------
// KotlinAdapter
// ---------------------------------------------------------------------------

/// Kotlin 語言適配器。
///
/// 使用 `tree-sitter-kotlin` grammar crate 進行解析。
/// 同時處理 `.kt`（原始碼）與 `.kts`（腳本）檔案。
///
/// # 執行緒安全
///
/// 每次呼叫 [`parse`](Self::parse) 都建立新的 [`tree_sitter::Parser`]，
/// 因此本適配器為 `Send + Sync`，可安全跨執行緒共用。
#[derive(Debug, Clone, Copy)]
pub struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn extensions(&self) -> &[&str] {
        &["kt", "kts"]
    }

    fn parse(&self, source: &[u8]) -> LangResult<tree_sitter::Tree> {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter_kotlin_ng::LANGUAGE.into();
        parser.set_language(&lang)?;

        debug!(
            language = "Kotlin",
            source_len = source.len(),
            "parsing source"
        );

        parser.parse(source, None).ok_or(LangError::ParseFailed)
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        tree_sitter_kotlin_ng::LANGUAGE.into()
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor
// ---------------------------------------------------------------------------

/// 將 [`KotlinAdapter`] 註冊至既有的
/// [`AdapterRegistry`](crate::adapter::AdapterRegistry)。
pub fn register_kotlin_adapter(registry: &mut crate::adapter::AdapterRegistry) {
    registry.register(Box::new(KotlinAdapter));
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
        let adapter = KotlinAdapter;
        assert_eq!(adapter.language(), Language::Kotlin);
        assert_eq!(adapter.extensions(), &["kt", "kts"]);
    }

    #[test]
    fn parse_simple() {
        let adapter = KotlinAdapter;
        let source = b"fun main() {\n    println(\"Hello, World!\")\n}";
        let tree = adapter.parse(source).expect("should parse valid Kotlin");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_class() {
        let adapter = KotlinAdapter;
        let source = br#"
class Greeter(private val name: String) {
    fun greet(): String {
        return "Hello, $name!"
    }
}
"#;
        let tree = adapter.parse(source).expect("should parse Kotlin class");
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
        assert!(!root.has_error(), "AST should have no errors");
    }

    #[test]
    fn parse_empty_source() {
        let adapter = KotlinAdapter;
        let tree = adapter
            .parse(b"")
            .expect("empty Kotlin source should parse");
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn register_kotlin_adapter_works() {
        let mut registry = AdapterRegistry::new();
        register_kotlin_adapter(&mut registry);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_by_extension("kt").is_some());
        assert!(registry.get_by_extension("kts").is_some());
        assert!(registry.get_by_language(Language::Kotlin).is_some());
    }

    #[test]
    fn tree_sitter_language_is_valid() {
        let lang = KotlinAdapter.tree_sitter_language();
        assert!(lang.node_kind_count() > 0);
    }
}
