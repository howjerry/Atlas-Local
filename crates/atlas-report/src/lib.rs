//! Atlas Report — output formatters and report generation.
//!
//! This crate provides report formatters for Atlas Local SAST scan results.
//! The primary format is the Atlas Findings JSON v1.0.0 schema, which produces
//! deterministic, machine-readable output suitable for CI/CD pipelines.

pub mod json;

// Re-export key types for convenience.
pub use json::{
    AtlasReport, BaselineDiff, FindingsSummary, GateBreachedThreshold, GateDetails,
    GateResultReport, ReportOptions, ScanMetadata, ScanStats,
};
pub use json::{
    compute_config_hash, compute_findings_summary, compute_rules_version, compute_scan_id,
    format_report, format_report_with_options,
};
pub use json::{ENGINE_VERSION, SCHEMA_VERSION};
