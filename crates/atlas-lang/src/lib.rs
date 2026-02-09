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

pub mod java;

pub mod python;

pub mod csharp;

pub mod go;

pub mod ruby;

pub mod php;

pub mod kotlin;

// Re-exports for convenience.
pub use adapter::{AdapterRegistry, LanguageAdapter};
pub use csharp::{CSharpAdapter, register_csharp_adapter};
pub use error::{LangError, LangResult};
pub use go::{GoAdapter, register_go_adapter};
pub use java::{JavaAdapter, register_java_adapter};
pub use kotlin::{KotlinAdapter, register_kotlin_adapter};
pub use language::Language;
pub use php::{PhpAdapter, register_php_adapter};
pub use python::{PythonAdapter, register_python_adapter};
pub use ruby::{RubyAdapter, register_ruby_adapter};
pub use typescript::{JavaScriptAdapter, TypeScriptAdapter, register_js_ts_adapters};
