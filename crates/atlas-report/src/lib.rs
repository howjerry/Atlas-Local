//! Atlas Report — output formatters and report generation.
//!
//! This crate provides report formatters for Atlas Local SAST scan results.
//! The primary format is the Atlas Findings JSON v1.0.0 schema, which produces
//! deterministic, machine-readable output suitable for CI/CD pipelines.

pub mod json;
pub mod jsonl;
pub mod masking;
pub mod sarif;

// Re-export key types for convenience.
pub use json::{
    AtlasReport, BaselineDiff, FindingsSummary, GateBreachedThreshold, GateDetails,
    GateResultReport, ReportOptions, ScanMetadata, ScanStats,
};
pub use json::{ENGINE_VERSION, SCHEMA_VERSION};
pub use json::{
    compute_config_hash, compute_findings_summary, compute_rules_version, compute_scan_id,
    format_report, format_report_with_options,
};

// ---------------------------------------------------------------------------
// Report output format
// ---------------------------------------------------------------------------

/// Supported output formats for scan reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Atlas Findings JSON v1.0.0.
    Json,
    /// SARIF v2.1.0.
    Sarif,
    /// Atlas Events JSONL v1.0.0.
    Jsonl,
}

impl OutputFormat {
    /// Default file extension for this format.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Jsonl => "jsonl",
        }
    }

    /// Default file name when writing to an output directory.
    #[must_use]
    pub fn default_filename(self) -> &'static str {
        match self {
            Self::Json => "atlas-report.json",
            Self::Sarif => "atlas-report.sarif",
            Self::Jsonl => "atlas-report.jsonl",
        }
    }
}

/// Parses a comma-separated format string into a list of output formats.
///
/// Unknown format names are returned as errors in the result vector.
///
/// # Examples
///
/// ```
/// use atlas_report::{OutputFormat, parse_formats};
///
/// let formats = parse_formats("json,sarif").unwrap();
/// assert_eq!(formats, vec![OutputFormat::Json, OutputFormat::Sarif]);
/// ```
pub fn parse_formats(format_str: &str) -> Result<Vec<OutputFormat>, String> {
    let mut formats = Vec::new();
    for s in format_str.split(',') {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "json" => formats.push(OutputFormat::Json),
            "sarif" => formats.push(OutputFormat::Sarif),
            "jsonl" => formats.push(OutputFormat::Jsonl),
            other => return Err(format!("unknown output format: '{other}'")),
        }
    }
    if formats.is_empty() {
        return Err("no output formats specified".to_string());
    }
    Ok(formats)
}

/// Detects the output format from a file extension.
#[must_use]
pub fn format_from_extension(ext: &str) -> Option<OutputFormat> {
    match ext.to_lowercase().as_str() {
        "json" => Some(OutputFormat::Json),
        "sarif" => Some(OutputFormat::Sarif),
        "jsonl" => Some(OutputFormat::Jsonl),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Report dispatcher
// ---------------------------------------------------------------------------

use atlas_core::config::AtlasConfig;
use atlas_core::engine::ScanResult;
use atlas_rules::Rule;

/// A generated report for a specific format.
pub struct FormattedReport {
    /// The output format.
    pub format: OutputFormat,
    /// The formatted report content.
    pub content: String,
}

/// Generates reports for the requested output formats.
///
/// Returns one [`FormattedReport`] per requested format.
pub fn generate_reports(
    formats: &[OutputFormat],
    scan_result: &ScanResult,
    target_path: &str,
    rules: &[Rule],
    config: &AtlasConfig,
    options: &ReportOptions<'_>,
) -> Vec<FormattedReport> {
    formats
        .iter()
        .map(|&fmt| {
            let content = match fmt {
                OutputFormat::Json => {
                    format_report_with_options(scan_result, target_path, rules, config, options)
                }
                OutputFormat::Sarif => sarif::format_sarif(scan_result, rules),
                OutputFormat::Jsonl => jsonl::format_jsonl(
                    scan_result,
                    target_path,
                    ENGINE_VERSION,
                    options.gate_status,
                    !options.include_timestamp,
                ),
            };
            FormattedReport {
                format: fmt,
                content,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_formats_single() {
        let fmts = parse_formats("json").unwrap();
        assert_eq!(fmts, vec![OutputFormat::Json]);
    }

    #[test]
    fn parse_formats_multiple() {
        let fmts = parse_formats("json,sarif,jsonl").unwrap();
        assert_eq!(
            fmts,
            vec![OutputFormat::Json, OutputFormat::Sarif, OutputFormat::Jsonl]
        );
    }

    #[test]
    fn parse_formats_with_spaces() {
        let fmts = parse_formats(" json , sarif ").unwrap();
        assert_eq!(fmts, vec![OutputFormat::Json, OutputFormat::Sarif]);
    }

    #[test]
    fn parse_formats_unknown() {
        let err = parse_formats("json,xml").unwrap_err();
        assert!(err.contains("xml"));
    }

    #[test]
    fn parse_formats_empty() {
        let err = parse_formats("").unwrap_err();
        assert!(err.contains("unknown") || err.contains("no output"));
    }

    #[test]
    fn format_from_extension_known() {
        assert_eq!(format_from_extension("json"), Some(OutputFormat::Json));
        assert_eq!(format_from_extension("sarif"), Some(OutputFormat::Sarif));
        assert_eq!(format_from_extension("jsonl"), Some(OutputFormat::Jsonl));
    }

    #[test]
    fn format_from_extension_unknown() {
        assert_eq!(format_from_extension("xml"), None);
        assert_eq!(format_from_extension("csv"), None);
    }

    #[test]
    fn format_from_extension_case_insensitive() {
        assert_eq!(format_from_extension("JSON"), Some(OutputFormat::Json));
        assert_eq!(format_from_extension("SARIF"), Some(OutputFormat::Sarif));
    }

    #[test]
    fn output_format_extensions() {
        assert_eq!(OutputFormat::Json.extension(), "json");
        assert_eq!(OutputFormat::Sarif.extension(), "sarif");
        assert_eq!(OutputFormat::Jsonl.extension(), "jsonl");
    }

    #[test]
    fn output_format_default_filenames() {
        assert_eq!(OutputFormat::Json.default_filename(), "atlas-report.json");
        assert_eq!(OutputFormat::Sarif.default_filename(), "atlas-report.sarif");
        assert_eq!(OutputFormat::Jsonl.default_filename(), "atlas-report.jsonl");
    }
}
