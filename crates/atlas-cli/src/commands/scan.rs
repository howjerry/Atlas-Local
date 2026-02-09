//! The `scan` CLI subcommand -- scans a project for security vulnerabilities.

use std::path::{Path, PathBuf};

use anyhow::Context;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::info;

use atlas_analysis::DiffStatus;
use atlas_core::diff;
use atlas_core::engine::{ScanEngine, ScanOptions};
use atlas_core::{Category, GateResult, Language, Severity};
use atlas_policy::baseline;
use atlas_policy::gate::{self, GateFinding};
use atlas_report::{
    BaselineDiff, DiffContextReport, GateBreachedThreshold, GateDetails, ReportOptions,
    generate_reports, parse_formats,
};

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

    /// Git reference for diff-aware scanning (e.g. HEAD, origin/main, v1.0.0).
    /// Only files changed since this reference will be scanned.
    #[arg(long = "diff")]
    pub diff_ref: Option<String>,

    /// Gate evaluation mode for diff-aware scans.
    /// "all" (default): count all findings in changed files.
    /// "new-only": count only findings on changed lines.
    #[arg(long = "diff-gate-mode", default_value = "all")]
    pub diff_gate_mode: DiffGateMode,
}

/// Gate evaluation mode for diff-aware scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DiffGateMode {
    /// Count all findings in changed files against the gate.
    All,
    /// Count only findings on changed lines (diff_status == new).
    #[value(name = "new-only")]
    NewOnly,
}

// ---------------------------------------------------------------------------
// GateFinding bridge
// ---------------------------------------------------------------------------

/// Thin wrapper that implements [`GateFinding`] for [`atlas_analysis::Finding`].
///
/// Required by Rust's orphan rules since both `GateFinding` and `Finding` are
/// defined in external crates. No conversion is needed — the enum types are
/// unified via re-exports.
struct FindingAdapter<'a>(&'a atlas_analysis::Finding);

impl GateFinding for FindingAdapter<'_> {
    fn severity(&self) -> Severity {
        self.0.severity
    }

    fn category(&self) -> Category {
        self.0.category
    }
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
// Output directory organisation
// ---------------------------------------------------------------------------

/// Resolves the final output directory for directory-mode output.
///
/// Given a base directory (the user's `--output` path) and the scan target,
/// produces `{base}/{project_name}/{YYYYMMDD-HHmmss}/` so that successive
/// scans never overwrite each other.
fn resolve_output_dir(base: &Path, target: &Path) -> PathBuf {
    let project_name = target
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("unknown"))
        .to_string_lossy();
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    base.join(project_name.as_ref())
        .join(timestamp.to_string())
}

/// Build compliance coverage summaries from findings and rules.
///
/// Loads framework definitions from `rules/compliance/`, computes per-framework
/// coverage (rules mapped), and enriches each category with the count of actual
/// findings that map to it via `metadata.compliance`.
fn build_compliance_summary(
    findings: &[atlas_analysis::Finding],
    rules: &[atlas_rules::Rule],
) -> Option<Vec<atlas_core::compliance::ComplianceSummary>> {
    let compliance_dir = PathBuf::from("rules/compliance");
    let frameworks = atlas_core::compliance::load_frameworks(&compliance_dir).ok()?;
    if frameworks.is_empty() {
        return None;
    }

    let mut summaries: Vec<atlas_core::compliance::ComplianceSummary> = frameworks
        .iter()
        .map(|fw| atlas_core::compliance::compute_coverage(fw, rules))
        .collect();

    // Enrich with finding counts from actual scan findings.
    for summary in &mut summaries {
        for finding in findings {
            if let Some(compliance_val) = finding.metadata.get("compliance") {
                if let Some(arr) = compliance_val.as_array() {
                    for entry in arr {
                        if let (Some(fw), Some(req)) = (
                            entry.get("framework").and_then(|v| v.as_str()),
                            entry.get("requirement").and_then(|v| v.as_str()),
                        ) {
                            if fw == summary.framework {
                                if let Some(cat) = summary
                                    .categories
                                    .iter_mut()
                                    .find(|c| c.category_id == req)
                                {
                                    cat.finding_count += 1;
                                }
                            }
                        }
                    }
                }
            }

            // Also count via CWE auto-mapping.
            if let Some(ref cwe_id) = finding.cwe_id {
                let fw = frameworks.iter().find(|f| f.id == summary.framework);
                if let Some(fw) = fw {
                    for fw_cat in &fw.categories {
                        if fw_cat.cwe_mappings.contains(cwe_id) {
                            if let Some(cat) = summary
                                .categories
                                .iter_mut()
                                .find(|c| c.category_id == fw_cat.id)
                            {
                                cat.finding_count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Some(summaries)
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

    // 1b. License validation (T077): if a licence file exists, validate it.
    //     Exit code 3 on invalid/expired licence; skip silently if no licence.
    if let Some(home) = dirs_next::home_dir() {
        let license_path = home.join(".atlas").join("license.json");
        if license_path.exists() {
            match atlas_license::validator::load_license(&license_path) {
                Ok(license) => {
                    let fp = atlas_license::node_locked::hardware_fingerprint();
                    let status = atlas_license::validator::license_status(&license, Some(&fp));
                    if !status.valid {
                        eprintln!(
                            "atlas: license validation failed: {}",
                            status.reason.unwrap_or_default()
                        );
                        return Ok(ExitCode::LicenseError);
                    }
                    info!(
                        license_id = %status.license_id,
                        "license validated"
                    );
                }
                Err(e) => {
                    eprintln!("atlas: failed to load license: {e}");
                    return Ok(ExitCode::LicenseError);
                }
            }
        }
    }

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

    // 6. Compute diff context if --diff was specified.
    let diff_context = if let Some(ref git_ref) = args.diff_ref {
        match diff::compute_diff(&args.target, git_ref) {
            Ok(dc) => {
                if dc.is_fallback {
                    info!("Not a git repository; falling back to full scan");
                }
                Some(dc)
            }
            Err(e) => {
                return Err(anyhow::anyhow!("{e}"));
            }
        }
    } else {
        None
    };

    // 6b. Build scan options from CLI args and config.
    let scan_options = ScanOptions {
        max_file_size_kb: config.scan.max_file_size_kb,
        jobs: args.jobs,
        no_cache: args.no_cache,
        diff_context,
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
    let mut result = engine
        .scan_with_options(&args.target, language_filter_ref, &scan_options)
        .context("scan engine failed")?;

    // Finish the progress spinner.
    if let Some(pb) = spinner {
        pb.finish_with_message(format!(
            "Scanned {} files ({} skipped), found {} findings",
            result.files_scanned,
            result.files_skipped,
            result.findings.len()
        ));
    }

    info!(
        findings = result.findings.len(),
        files_scanned = result.files_scanned,
        files_skipped = result.files_skipped,
        "scan completed"
    );

    // 9. Load policy and evaluate gate.
    let policy = if let Some(policy_path) = &args.policy {
        atlas_policy::load_policy(policy_path)
            .with_context(|| format!("failed to load policy from '{}'", policy_path.display()))?
    } else {
        atlas_policy::default_policy()
    };

    // 9.1. Apply suppressions from policy.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let suppressed_fps: std::collections::HashSet<&str> = policy
        .suppressions
        .iter()
        .filter(|s| {
            s.expires
                .as_ref()
                .map_or(true, |exp| exp.as_str() > today.as_str())
        })
        .map(|s| s.fingerprint.as_str())
        .collect();

    if !suppressed_fps.is_empty() {
        let before = result.findings.len();
        result
            .findings
            .retain(|f| !suppressed_fps.contains(f.fingerprint.as_str()));
        let suppressed_count = before - result.findings.len();
        if suppressed_count > 0 {
            info!(
                count = suppressed_count,
                unique_fingerprints = suppressed_fps.len(),
                "findings suppressed by policy"
            );
        }
    }

    // 9.5. Load and apply baseline (if provided via CLI or policy).
    let baseline_path_str = args
        .baseline
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| policy.baseline.clone());

    let baseline_diff_result = if let Some(ref bl_path) = baseline_path_str {
        let bl = baseline::load_baseline(std::path::Path::new(bl_path))
            .with_context(|| format!("failed to load baseline from '{bl_path}'"))?;

        let current_fps: Vec<String> = result
            .findings
            .iter()
            .map(|f| f.fingerprint.clone())
            .collect();

        let diff = baseline::diff_findings(&current_fps, &bl);
        info!(
            new = diff.new_count,
            baselined = diff.baselined_count,
            resolved = diff.resolved_count,
            "baseline diff computed"
        );
        Some(diff)
    } else {
        None
    };

    // Build report baseline_diff from the diff result.
    let report_baseline_diff = baseline_diff_result.as_ref().map(|d| BaselineDiff {
        new_count: d.new_count,
        baselined_count: d.baselined_count,
        resolved_count: d.resolved_count,
    });

    // Filter findings for gate evaluation.
    // Baseline filtering: only new findings (vs baseline) count.
    let findings_for_gate: Vec<&atlas_analysis::Finding> =
        if let Some(ref diff) = baseline_diff_result {
            let new_set: std::collections::HashSet<&str> =
                diff.new_fingerprints.iter().map(String::as_str).collect();
            result
                .findings
                .iter()
                .filter(|f| new_set.contains(f.fingerprint.as_str()))
                .collect()
        } else {
            result.findings.iter().collect()
        };

    // Diff-gate-mode filtering: in new-only mode, only count findings on changed lines.
    let findings_for_gate: Vec<&atlas_analysis::Finding> =
        if args.diff_gate_mode == DiffGateMode::NewOnly && args.diff_ref.is_some() {
            findings_for_gate
                .into_iter()
                .filter(|f| f.diff_status == Some(DiffStatus::New))
                .collect()
        } else {
            findings_for_gate
        };

    let adapted: Vec<FindingAdapter<'_>> = findings_for_gate
        .iter()
        .map(|f| FindingAdapter(f))
        .collect();
    let gate_eval = gate::evaluate_gate(
        &adapted,
        &policy.fail_on,
        policy.warn_on.as_ref(),
        policy.category_overrides.as_ref(),
    );

    let gate_status = gate_eval.result.to_string();
    let report_gate_details = if gate_eval.breached_thresholds.is_empty() {
        None
    } else {
        Some(GateDetails {
            breached_thresholds: gate_eval
                .breached_thresholds
                .iter()
                .map(|b| GateBreachedThreshold {
                    severity: b.severity.clone(),
                    category: b.category.clone(),
                    threshold: b.threshold,
                    actual: b.actual,
                    level: b.level.clone(),
                })
                .collect(),
        })
    };

    info!(
        gate_result = %gate_status,
        policy = %policy.name,
        "gate evaluation completed"
    );

    // 10. Parse output formats and generate reports.
    let formats = parse_formats(&args.format).map_err(|e| anyhow::anyhow!(e))?;

    let target_path = std::fs::canonicalize(&args.target)
        .unwrap_or_else(|_| args.target.clone())
        .display()
        .to_string();
    let report_diff_context = scan_options.diff_context.as_ref().map(|dc| {
        let total_new = result
            .findings
            .iter()
            .filter(|f| f.diff_status == Some(DiffStatus::New))
            .count() as u32;
        let total_context = result
            .findings
            .iter()
            .filter(|f| f.diff_status == Some(DiffStatus::Context))
            .count() as u32;
        DiffContextReport {
            git_ref: dc.git_ref.clone(),
            changed_files_count: dc.changed_files.len() as u32,
            total_new_findings: total_new,
            total_context_findings: total_context,
        }
    });

    // 10b. Build compliance summary from findings + framework definitions.
    let compliance_summary = build_compliance_summary(&result.findings, engine.rules());

    let report_options = ReportOptions {
        include_timestamp: args.timestamp,
        gate_status: Some(&gate_status),
        gate_details: report_gate_details,
        policy_name: Some(&policy.name),
        baseline_applied: baseline_path_str.as_deref(),
        baseline_diff: report_baseline_diff,
        diff_context: report_diff_context,
        compliance_summary,
    };

    let reports = generate_reports(
        &formats,
        &result,
        &target_path,
        engine.rules(),
        &config,
        &report_options,
    );

    // 11. Write output.
    if let Some(output_path) = &args.output {
        let is_dir =
            output_path.is_dir() || (formats.len() > 1 && output_path.extension().is_none());

        if is_dir || formats.len() > 1 {
            // Output to directory: organise under {project}/{timestamp}/.
            let final_dir = resolve_output_dir(output_path, &args.target);
            std::fs::create_dir_all(&final_dir).with_context(|| {
                format!(
                    "failed to create output directory '{}'",
                    final_dir.display()
                )
            })?;
            for report in &reports {
                let file_path = final_dir.join(report.format.default_filename());
                std::fs::write(&file_path, &report.content).with_context(|| {
                    format!(
                        "failed to write {} to '{}'",
                        report.format.extension(),
                        file_path.display()
                    )
                })?;
                info!(path = %file_path.display(), format = report.format.extension(), "wrote scan results");
            }
        } else {
            // Single format to a file path.
            if let Some(parent) = output_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create output directory '{}'", parent.display())
                    })?;
                }
            }
            std::fs::write(output_path, &reports[0].content).with_context(|| {
                format!("failed to write output to '{}'", output_path.display())
            })?;
            info!(path = %output_path.display(), "wrote scan results");
        }
    } else {
        // Write to stdout (first format only).
        println!("{}", reports[0].content);
    }

    // 12. Determine exit code from gate result.
    match gate_eval.result {
        GateResult::Fail => Ok(ExitCode::GateFail),
        GateResult::Pass | GateResult::Warn => Ok(ExitCode::Pass),
    }
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
            diff_ref: None,
            diff_gate_mode: DiffGateMode::All,
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
            diff_ref: None,
            diff_gate_mode: DiffGateMode::All,
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
        // Default policy should be applied and gate should PASS with no findings.
        assert_eq!(parsed["gate_result"]["status"], "PASS");
        assert_eq!(parsed["scan"]["policy_applied"], "atlas-default");
    }

    #[test]
    fn execute_with_policy_file() {
        use std::io::Write;

        let tmp = tempfile::tempdir().unwrap();
        let output_file = tmp.path().join("output.json");

        // Create a policy file.
        let policy_file = tmp.path().join("policy.yaml");
        let mut f = std::fs::File::create(&policy_file).unwrap();
        writeln!(
            f,
            r#"schema_version: "1.0.0"
name: test-custom-policy
fail_on:
  critical: 0
  high: 0"#
        )
        .unwrap();

        let args = ScanArgs {
            target: tmp.path().to_path_buf(),
            format: "json".to_string(),
            output: Some(output_file.clone()),
            policy: Some(policy_file),
            baseline: None,
            lang: None,
            jobs: None,
            no_cache: false,
            verbose: false,
            quiet: true,
            timestamp: false,
            diff_ref: None,
            diff_gate_mode: DiffGateMode::All,
        };
        let result = execute(args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::Pass);

        let content = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["scan"]["policy_applied"], "test-custom-policy");
        assert_eq!(parsed["gate_result"]["status"], "PASS");
    }

    #[test]
    fn execute_multi_format_output() {
        let tmp = tempfile::tempdir().unwrap();
        let output_dir = tmp.path().join("reports");
        let target = tmp.path().to_path_buf();
        let args = ScanArgs {
            target: target.clone(),
            format: "json,sarif,jsonl".to_string(),
            output: Some(output_dir.clone()),
            policy: None,
            baseline: None,
            lang: None,
            jobs: None,
            no_cache: false,
            verbose: false,
            quiet: true,
            timestamp: false,
            diff_ref: None,
            diff_gate_mode: DiffGateMode::All,
        };
        let result = execute(args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::Pass);

        // Directory mode now organises under {project}/{timestamp}/.
        // Discover the auto-created subdirectory.
        let project_name = target.file_name().unwrap().to_string_lossy().to_string();
        let project_dir = output_dir.join(&project_name);
        assert!(project_dir.is_dir(), "project subdirectory must exist");

        let mut ts_dirs: Vec<_> = std::fs::read_dir(&project_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        assert_eq!(ts_dirs.len(), 1, "exactly one timestamp dir expected");
        let ts_dir = ts_dirs.remove(0).path();

        // Verify all three output files were created.
        let json_file = ts_dir.join("atlas-report.json");
        let sarif_file = ts_dir.join("atlas-report.sarif");
        let jsonl_file = ts_dir.join("atlas-report.jsonl");

        assert!(json_file.exists(), "JSON report must exist");
        assert!(sarif_file.exists(), "SARIF report must exist");
        assert!(jsonl_file.exists(), "JSONL report must exist");

        // Validate JSON report.
        let json_content = std::fs::read_to_string(&json_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_content).unwrap();
        assert_eq!(parsed["schema_version"], "1.0.0");

        // Validate SARIF report.
        let sarif_content = std::fs::read_to_string(&sarif_file).unwrap();
        let sarif_parsed: serde_json::Value = serde_json::from_str(&sarif_content).unwrap();
        assert_eq!(sarif_parsed["version"], "2.1.0");

        // Validate JSONL report (each line is valid JSON).
        let jsonl_content = std::fs::read_to_string(&jsonl_file).unwrap();
        for line in jsonl_content.lines() {
            if !line.is_empty() {
                let _: serde_json::Value =
                    serde_json::from_str(line).expect("each JSONL line must be valid JSON");
            }
        }
    }

    #[test]
    fn resolve_output_dir_uses_project_and_timestamp() {
        let base = PathBuf::from("/tmp/reports");
        let target = PathBuf::from("/home/user/Projects/MyApp");
        let result = resolve_output_dir(&base, &target);

        // Should be /tmp/reports/MyApp/{YYYYMMDD-HHmmss}
        assert!(result.starts_with("/tmp/reports/MyApp/"));
        let ts_component = result.file_name().unwrap().to_string_lossy();
        // Timestamp format: YYYYMMDD-HHmmss (15 chars)
        assert_eq!(ts_component.len(), 15, "timestamp should be YYYYMMDD-HHmmss");
        assert!(ts_component.contains('-'), "timestamp should contain a dash");
    }

    #[test]
    fn resolve_output_dir_with_root_target() {
        let base = PathBuf::from("/tmp/reports");
        let target = PathBuf::from("/");
        let result = resolve_output_dir(&base, &target);
        // Root has no file_name, should fall back to "unknown".
        assert!(result.starts_with("/tmp/reports/unknown/"));
    }

    #[test]
    fn execute_single_file_output_unaffected() {
        // Single-file mode should write directly to the specified path (no sub-dirs).
        let tmp = tempfile::tempdir().unwrap();
        let output_file = tmp.path().join("custom.json");
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
            diff_ref: None,
            diff_gate_mode: DiffGateMode::All,
        };
        let result = execute(args);
        assert!(result.is_ok());
        assert!(output_file.exists(), "single-file output must exist at exact path");
    }

    #[test]
    fn execute_invalid_format() {
        let tmp = tempfile::tempdir().unwrap();
        let args = ScanArgs {
            target: tmp.path().to_path_buf(),
            format: "xml".to_string(),
            output: None,
            policy: None,
            baseline: None,
            lang: None,
            jobs: None,
            no_cache: false,
            verbose: false,
            quiet: true,
            timestamp: false,
            diff_ref: None,
            diff_gate_mode: DiffGateMode::All,
        };
        let result = execute(args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("xml"),
            "error should mention unknown format"
        );
    }
}
