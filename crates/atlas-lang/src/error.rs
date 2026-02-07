//! Error types for the atlas-lang crate.

/// Errors that can occur during language adapter operations.
#[derive(Debug, thiserror::Error)]
pub enum LangError {
    /// The tree-sitter parser failed to parse the given source code.
    #[error("parse failed: parser returned None (source may be too large or language not set)")]
    ParseFailed,

    /// Failed to set the tree-sitter language on a parser.
    #[error("failed to set tree-sitter language: {0}")]
    LanguageError(#[from] tree_sitter::LanguageError),

    /// No adapter is registered for the requested file extension.
    #[error("no adapter registered for extension: {extension}")]
    UnsupportedExtension {
        /// The file extension that was not recognized.
        extension: String,
    },

    /// No adapter is registered for the requested language.
    #[error("no adapter registered for language: {language}")]
    UnsupportedLanguage {
        /// The language that was not recognized.
        language: String,
    },
}

/// Convenience alias for `Result<T, LangError>`.
pub type LangResult<T> = Result<T, LangError>;
