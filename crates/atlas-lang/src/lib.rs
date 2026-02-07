//! Atlas Lang -- language adapters and tree-sitter integration.
//!
//! This crate provides:
//!
//! - [`Language`] -- the canonical enum of programming languages supported by Atlas.
//! - [`LanguageAdapter`] -- a trait for tree-sitter language backends.
//! - [`AdapterRegistry`] -- a collection of adapters with lookup by extension or language.
//! - Concrete adapters for TypeScript/TSX and JavaScript/JSX.
//!
//! # Architecture
//!
//! The [`Language`] enum lives here (rather than in `atlas-core`) so that
//! adapter code can reference it without creating a circular dependency.
//! `atlas-core` re-exports [`Language`] for the rest of the crate graph.

pub mod adapter;
pub mod error;
pub mod language;
pub mod typescript;

// Future language adapters -- uncomment as they are implemented.
// pub mod java;
// pub mod python;
// pub mod go;
// pub mod csharp;

// Re-exports for convenience.
pub use adapter::{AdapterRegistry, LanguageAdapter};
pub use error::{LangError, LangResult};
pub use language::Language;
pub use typescript::{JavaScriptAdapter, TypeScriptAdapter, register_js_ts_adapters};
