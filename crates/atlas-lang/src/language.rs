//! Supported programming languages for the Atlas scanner.
//!
//! This module defines the [`Language`] enum which enumerates all programming
//! languages supported by Atlas Local SAST. It is defined in `atlas-lang` so
//! that language adapters can reference it without circular dependencies, and
//! is re-exported from `atlas-core` for use by the wider crate graph.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// Programming languages supported by the Atlas scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Language {
    /// TypeScript (`.ts`, `.tsx`).
    TypeScript,
    /// JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`).
    JavaScript,
    /// Java (`.java`).
    Java,
    /// Python (`.py`, `.pyi`).
    Python,
    /// Go (`.go`).
    Go,
    /// C# (`.cs`).
    CSharp,
    /// Ruby (`.rb`).
    Ruby,
    /// PHP (`.php`).
    Php,
    /// Kotlin (`.kt`, `.kts`).
    Kotlin,
}

impl Language {
    /// Returns the file extensions associated with this language.
    ///
    /// Extensions include the leading dot (e.g. `".ts"`).
    #[must_use]
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::TypeScript => &[".ts", ".tsx"],
            Self::JavaScript => &[".js", ".jsx", ".mjs", ".cjs"],
            Self::Java => &[".java"],
            Self::Python => &[".py", ".pyi"],
            Self::Go => &[".go"],
            Self::CSharp => &[".cs"],
            Self::Ruby => &[".rb"],
            Self::Php => &[".php"],
            Self::Kotlin => &[".kt", ".kts"],
        }
    }

    /// Returns all supported language variants.
    #[must_use]
    pub const fn all() -> &'static [Language] {
        &[
            Self::TypeScript,
            Self::JavaScript,
            Self::Java,
            Self::Python,
            Self::Go,
            Self::CSharp,
            Self::Ruby,
            Self::Php,
            Self::Kotlin,
        ]
    }

    /// Attempts to determine the language from a file extension (including the dot).
    ///
    /// Returns `None` if the extension is not recognized.
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            ".ts" | ".tsx" => Some(Self::TypeScript),
            ".js" | ".jsx" | ".mjs" | ".cjs" => Some(Self::JavaScript),
            ".java" => Some(Self::Java),
            ".py" | ".pyi" => Some(Self::Python),
            ".go" => Some(Self::Go),
            ".cs" => Some(Self::CSharp),
            ".rb" => Some(Self::Ruby),
            ".php" => Some(Self::Php),
            ".kt" | ".kts" => Some(Self::Kotlin),
            _ => None,
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::TypeScript => "TypeScript",
            Self::JavaScript => "JavaScript",
            Self::Java => "Java",
            Self::Python => "Python",
            Self::Go => "Go",
            Self::CSharp => "CSharp",
            Self::Ruby => "Ruby",
            Self::Php => "Php",
            Self::Kotlin => "Kotlin",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_extensions() {
        assert_eq!(Language::TypeScript.extensions(), &[".ts", ".tsx"]);
        assert_eq!(
            Language::JavaScript.extensions(),
            &[".js", ".jsx", ".mjs", ".cjs"]
        );
        assert_eq!(Language::Java.extensions(), &[".java"]);
        assert_eq!(Language::Python.extensions(), &[".py", ".pyi"]);
        assert_eq!(Language::Go.extensions(), &[".go"]);
        assert_eq!(Language::CSharp.extensions(), &[".cs"]);
        assert_eq!(Language::Ruby.extensions(), &[".rb"]);
        assert_eq!(Language::Php.extensions(), &[".php"]);
        assert_eq!(Language::Kotlin.extensions(), &[".kt", ".kts"]);
    }

    #[test]
    fn language_from_extension() {
        assert_eq!(Language::from_extension(".ts"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension(".tsx"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension(".js"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".jsx"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".mjs"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".cjs"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".java"), Some(Language::Java));
        assert_eq!(Language::from_extension(".py"), Some(Language::Python));
        assert_eq!(Language::from_extension(".pyi"), Some(Language::Python));
        assert_eq!(Language::from_extension(".go"), Some(Language::Go));
        assert_eq!(Language::from_extension(".cs"), Some(Language::CSharp));
        assert_eq!(Language::from_extension(".rb"), Some(Language::Ruby));
        assert_eq!(Language::from_extension(".php"), Some(Language::Php));
        assert_eq!(Language::from_extension(".kt"), Some(Language::Kotlin));
        assert_eq!(Language::from_extension(".kts"), Some(Language::Kotlin));
        assert_eq!(Language::from_extension(".rs"), None);
    }

    #[test]
    fn language_serde_roundtrip() {
        let json = serde_json::to_string(&Language::CSharp).unwrap();
        assert_eq!(json, "\"CSharp\"");
        let back: Language = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Language::CSharp);
    }

    #[test]
    fn language_display() {
        assert_eq!(Language::TypeScript.to_string(), "TypeScript");
        assert_eq!(Language::JavaScript.to_string(), "JavaScript");
        assert_eq!(Language::Java.to_string(), "Java");
        assert_eq!(Language::Python.to_string(), "Python");
        assert_eq!(Language::Go.to_string(), "Go");
        assert_eq!(Language::CSharp.to_string(), "CSharp");
        assert_eq!(Language::Ruby.to_string(), "Ruby");
        assert_eq!(Language::Php.to_string(), "Php");
        assert_eq!(Language::Kotlin.to_string(), "Kotlin");
    }

    #[test]
    fn all_languages_covered() {
        let all = Language::all();
        assert_eq!(all.len(), 9);
        // Every language should resolve from at least one of its own extensions.
        for lang in all {
            let ext = lang.extensions()[0];
            assert_eq!(Language::from_extension(ext), Some(*lang));
        }
    }
}
