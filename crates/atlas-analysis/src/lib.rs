//! Atlas Analysis — analysis levels, finding model, and AST utilities.

pub mod finding;
pub mod l1_pattern;
pub mod l2_builder;
pub mod l2_engine;
pub mod l2_intraprocedural;
pub mod l2_taint_config;
pub mod call_graph_builder;
pub mod import_resolver;
pub mod l3_engine;
pub mod l3_interprocedural;
pub mod l3_lang_config;
pub mod secrets;
pub mod duplication;
pub mod metrics;

pub use finding::{AnalysisError, DiffStatus, Finding, FindingBuilder, LineRange};
pub use l1_pattern::{L1Error, L1PatternEngine, RuleMatchMetadata};
pub use metrics::{FileMetricsData, FunctionMetricsData, MetricsConfig, MetricsEngine};
pub use duplication::{
    DuplicateBlockData, DuplicationDetector, DuplicationResult, NormalizedToken, TokenizedFile,
};
