//! The `scan` CLI subcommand -- scans a project for security vulnerabilities.

use std::path::PathBuf;

use anyhow::Context;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

use atlas_core::engine::{ScanEngine, ScanOptions};
use atlas_core::Language;
use atlas_report::format_report;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// ScanArgs
// ---------------------------------------------------------------------------

/// Scan a project for security vulnerabilities.
#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Target directory to scan.
    pub target: PathBuf,

    /// Output format(s): json, sarif, jsonl (comma-separated).
    #[arg(long, default_value = "json")]
    pub format: String,

    /// Output directory or file path.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Policy file for gate evaluation.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Baseline file for incremental adoption.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Languages to scan (comma-separated, e.g. "typescript,python").
    #[arg(long)]
    pub lang: Option<String>,

    /// Number of parallel jobs.
    #[arg(long, short)]
    pub jobs: Option<usize>,

    /// Disable result caching.
    #[arg(long)]
    pub no_cache: bool,

    /// Enable verbose output.
    #[arg(long, short)]
    pub verbose: bool,

    /// Suppress all non-essential output.
    #[arg(long, short)]
    pub quiet: bool,

    /// Include timestamps in output.
    #[arg(long)]
    pub timestamp: bool,
}

// ---------------------------------------------------------------------------
// Language parsing helper
// ---------------------------------------------------------------------------

/// Maps a human-readable language name to [`Language`].
///
/// Accepts both the display name (e.g. "TypeScript") and lowercase variants
/// (e.g. "typescript", "ts").
fn parse_language(name: &str) -> Option<Language> {
    match name.trim().to_lowercase().as_str() {
        "typescript" | "ts" => Some(Language::TypeScript),
        "javascript" | "js" => Some(Language::JavaScript),
        "java" => Some(Language::Java),
        "python" | "py" => Some(Language::Python),
        "go" | "golang" => Some(Language::Go),
        "csharp" | "c#" | "cs" => Some(Language::CSharp),
        _ => None,
    }
}

/// Parses a comma-separated language list into a `Vec<Language>`.
///
/// Unknown language names are logged as warnings and skipped.
fn parse_language_filter(lang_arg: &str) -> Vec<Language> {
    lang_arg
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            match parse_language(s) {
                Some(lang) => Some(lang),
                None => {
                    tracing::warn!(language = s, "unknown language; skipping");
                    None
                }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `scan` subcommand.
///
/// Returns an [`ExitCode`] indicating the outcome of the scan.
pub fn execute(args: ScanArgs) -> Result<ExitCode, anyhow::Error> {
    // 1. Initialize tracing.
    //    Ignore the error if the subscriber is already set (e.g. in tests).
    let _ = atlas_core::init_tracing(args.verbose, args.quiet, false);

    // 2. Load configuration.
    let config = atlas_core::config::load_config(Some(&args.target))
        .context("failed to load configuration")?;

    // 3. Create the scan engine.
    let mut engine = ScanEngine::new();

    // 4. Load built-in rules from `rules/builtin/` relative to cwd.
    let builtin_rules_dir = PathBuf::from("rules/builtin");
    if builtin_rules_dir.is_dir() {
        engine
            .load_rules(&builtin_rules_dir)
            .context("failed to load built-in rules")?;
        info!(dir = %builtin_rules_dir.display(), "loaded built-in rules");
    } else {
        info!(
            dir = %builtin_rules_dir.display(),
            "built-in rules directory not found; continuing without built-in rules"
        );
    }

    // 5. Parse language filter from --lang flag.
    let language_filter: Option<Vec<Language>> = args.lang.as_deref().map(parse_language_filter);
    let language_filter_ref = language_filter.as_deref();

    // 6. Build scan options from CLI args and config.
    let scan_options = ScanOptions {
        max_file_size_kb: config.scan.max_file_size_kb,
        jobs: args.jobs,
    };

    // 7. Show progress spinner (unless --quiet).
    let spinner = if !args.quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["=>", "==>", "===>", "====>", "=====>", ""]),
        );
        pb.set_message(format!("Scanning {}...", args.target.display()));
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        Some(pb)
    } else {
        None
    };

    // 8. Run the scan.
    let result = engine
        .scan_with_options(&args.target, language_filter_ref, &scan_options)
        .context("scan engine failed")?;

    // Finish the progress spinner.
    if let Some(pb) = spinner {
        pb.finish_with_message(format!(
            "Scanned {} files ({} skipped), found {} findings",
            result.files_scanned, result.files_skipped, result.findings.len()
        ));
    }

    info!(
        findings = result.findings.len(),
        files_scanned = result.files_scanned,
        files_skipped = result.files_skipped,
        "scan completed"
    );

    // 9. Format output using the Atlas Findings JSON v1.0.0 formatter.
    let target_path = std::fs::canonicalize(&args.target)
        .unwrap_or_else(|_| args.target.clone())
        .display()
        .to_string();
    let json_output = format_report(
        &result,
        &target_path,
        engine.rules(),
        &config,
        args.timestamp,
    );

    // 10. Write output.
    if let Some(output_path) = &args.output {
        // Ensure the parent directory exists.
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create output directory '{}'", parent.display()))?;
            }
        }
        std::fs::write(output_path, &json_output)
            .with_context(|| format!("failed to write output to '{}'", output_path.display()))?;
        info!(path = %output_path.display(), "wrote scan results");
    } else {
        // Write to stdout.
        println!("{json_output}");
    }

    // 11. Determine exit code.
    //    For now, without policy gate evaluation, we always return Pass
    //    if the scan completed successfully.
    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_language_known_names() {
        assert_eq!(parse_language("typescript"), Some(Language::TypeScript));
        assert_eq!(parse_language("ts"), Some(Language::TypeScript));
        assert_eq!(parse_language("TypeScript"), Some(Language::TypeScript));
        assert_eq!(parse_language("javascript"), Some(Language::JavaScript));
        assert_eq!(parse_language("js"), Some(Language::JavaScript));
        assert_eq!(parse_language("java"), Some(Language::Java));
        assert_eq!(parse_language("python"), Some(Language::Python));
        assert_eq!(parse_language("py"), Some(Language::Python));
        assert_eq!(parse_language("go"), Some(Language::Go));
        assert_eq!(parse_language("golang"), Some(Language::Go));
        assert_eq!(parse_language("csharp"), Some(Language::CSharp));
        assert_eq!(parse_language("c#"), Some(Language::CSharp));
        assert_eq!(parse_language("cs"), Some(Language::CSharp));
    }

    #[test]
    fn parse_language_unknown() {
        assert_eq!(parse_language("rust"), None);
        assert_eq!(parse_language("ruby"), None);
        assert_eq!(parse_language(""), None);
    }

    #[test]
    fn parse_language_filter_multiple() {
        let langs = parse_language_filter("typescript,python,go");
        assert_eq!(langs.len(), 3);
        assert!(langs.contains(&Language::TypeScript));
        assert!(langs.contains(&Language::Python));
        assert!(langs.contains(&Language::Go));
    }

    #[test]
    fn parse_language_filter_with_spaces() {
        let langs = parse_language_filter("typescript , python , go");
        assert_eq!(langs.len(), 3);
    }

    #[test]
    fn parse_language_filter_single() {
        let langs = parse_language_filter("java");
        assert_eq!(langs.len(), 1);
        assert_eq!(langs[0], Language::Java);
    }

    #[test]
    fn parse_language_filter_empty() {
        let langs = parse_language_filter("");
        assert!(langs.is_empty());
    }

    #[test]
    fn parse_language_filter_with_unknown() {
        let langs = parse_language_filter("typescript,ruby,python");
        assert_eq!(langs.len(), 2);
        assert!(langs.contains(&Language::TypeScript));
        assert!(langs.contains(&Language::Python));
    }

    #[test]
    fn execute_with_nonexistent_target() {
        let args = ScanArgs {
            target: PathBuf::from("/nonexistent/path/unlikely"),
            format: "json".to_string(),
            output: None,
            policy: None,
            baseline: None,
            lang: None,
            jobs: None,
            no_cache: false,
            verbose: false,
            quiet: true,
            timestamp: false,
        };
        let result = execute(args);
        assert!(result.is_err());
    }

    #[test]
    fn execute_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let output_file = tmp.path().join("output.json");
        let args = ScanArgs {
            target: tmp.path().to_path_buf(),
            format: "json".to_string(),
            output: Some(output_file.clone()),
            policy: None,
            baseline: None,
            lang: None,
            jobs: None,
            no_cache: false,
            verbose: false,
            quiet: true,
            timestamp: false,
        };
        let result = execute(args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::Pass);

        // Verify the output file was created with Atlas Findings JSON v1.0.0 format.
        assert!(output_file.exists());
        let content = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["schema_version"], "1.0.0");
        assert_eq!(parsed["findings_count"]["total"], 0);
        assert_eq!(parsed["scan"]["files_scanned"], 0);
    }
}
