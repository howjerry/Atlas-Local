//! Atlas Analysis — analysis levels, finding model, and AST utilities.

pub mod finding;
pub mod l1_pattern;
pub mod l2_builder;
pub mod l2_engine;
pub mod l2_intraprocedural;
pub mod l2_taint_config;
pub mod l3_interprocedural;
pub mod secrets;

pub use finding::{AnalysisError, DiffStatus, Finding, FindingBuilder, LineRange};
pub use l1_pattern::{L1Error, L1PatternEngine, RuleMatchMetadata};
