//! Atlas Analysis — analysis levels, finding model, and AST utilities.

pub mod finding;
pub mod l1_pattern;
pub mod secrets;

pub use finding::{AnalysisError, Finding, FindingBuilder, LineRange};
pub use l1_pattern::{L1Error, L1PatternEngine, RuleMatchMetadata};
