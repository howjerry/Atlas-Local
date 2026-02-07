//! The `baseline` CLI subcommand -- create and diff baselines for incremental adoption.
//!
//! A baseline captures the fingerprints of all current scan findings so that
//! subsequent scans can distinguish between pre-existing ("baselined") and new
//! findings. This enables teams to adopt Atlas incrementally without being
//! overwhelmed by existing technical debt.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;
use tracing::info;

use atlas_core::engine::{ScanEngine, ScanOptions};

use crate::ExitCode;

// ---------------------------------------------------------------------------
// BaselineArgs
// ---------------------------------------------------------------------------

/// Manage baselines for incremental adoption.
#[derive(Debug, clap::Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub action: BaselineAction,
}

/// Baseline sub-subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum BaselineAction {
    /// Create a new baseline from the current scan findings.
    Create(CreateArgs),
    /// Show the diff between current findings and an existing baseline.
    Diff(DiffArgs),
}

// ---------------------------------------------------------------------------
// CreateArgs
// ---------------------------------------------------------------------------

/// Arguments for the `baseline create` command.
#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Target directory or file to scan.
    pub target: PathBuf,

    /// Path where the baseline file will be written.
    #[arg(long, short)]
    pub output: PathBuf,

    /// Policy file (optional).
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// DiffArgs
// ---------------------------------------------------------------------------

/// Arguments for the `baseline diff` command.
#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// Target directory or file to scan.
    pub target: PathBuf,

    /// Path to the baseline file to compare against.
    #[arg(long, short)]
    pub baseline: PathBuf,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generates a simple unique scan identifier.
///
/// This uses a timestamp-based ID for simplicity. In production, a proper
/// UUID library would be preferable, but this avoids adding a dependency.
fn uuid_v4_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = duration.as_nanos();
    format!("scan-{nanos:x}")
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `baseline` subcommand.
pub fn execute(args: BaselineArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, false, false);

    match args.action {
        BaselineAction::Create(create_args) => execute_create(create_args),
        BaselineAction::Diff(diff_args) => execute_diff(diff_args),
    }
}

// ---------------------------------------------------------------------------
// execute_create
// ---------------------------------------------------------------------------

/// Executes the `baseline create` subcommand.
///
/// 1. Load configuration.
/// 2. Create a `ScanEngine` and load rules.
/// 3. Run a scan on the target.
/// 4. Collect fingerprints from findings.
/// 5. Create and save a baseline file.
fn execute_create(args: CreateArgs) -> Result<ExitCode, anyhow::Error> {
    // 1. Load configuration.
    let config = atlas_core::config::load_config(Some(&args.target))
        .context("failed to load configuration")?;

    // 2. Create scan engine and load rules.
    let mut engine = ScanEngine::new();

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

    // 3. Build scan options and run scan.
    let scan_options = ScanOptions {
        max_file_size_kb: config.scan.max_file_size_kb,
        jobs: None,
        no_cache: false,
    };

    let result = engine
        .scan_with_options(&args.target, None, &scan_options)
        .context("scan engine failed")?;

    info!(
        findings = result.findings.len(),
        files_scanned = result.files_scanned,
        files_skipped = result.files_skipped,
        "scan completed for baseline creation"
    );

    // 4. Collect fingerprints from findings.
    let fingerprints: Vec<String> = result
        .findings
        .iter()
        .map(|f| f.fingerprint.clone())
        .collect();

    // 5. Create baseline and save to output path.
    let scan_id = uuid_v4_simple();
    let engine_version = env!("CARGO_PKG_VERSION");
    let baseline = atlas_policy::baseline::create_baseline(
        &scan_id,
        engine_version,
        &fingerprints,
        BTreeMap::new(),
    );
    atlas_policy::baseline::save_baseline(&baseline, &args.output)
        .with_context(|| format!("failed to save baseline to '{}'", args.output.display()))?;

    println!(
        "Created baseline with {} findings at {}",
        fingerprints.len(),
        args.output.display()
    );

    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// execute_diff
// ---------------------------------------------------------------------------

/// Executes the `baseline diff` subcommand.
///
/// 1. Load configuration.
/// 2. Create a `ScanEngine` and load rules.
/// 3. Run a scan on the target.
/// 4. Load the existing baseline.
/// 5. Diff current fingerprints against the baseline.
/// 6. Print summary.
fn execute_diff(args: DiffArgs) -> Result<ExitCode, anyhow::Error> {
    // 1. Load configuration.
    let config = atlas_core::config::load_config(Some(&args.target))
        .context("failed to load configuration")?;

    // 2. Create scan engine and load rules.
    let mut engine = ScanEngine::new();

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

    // 3. Build scan options and run scan.
    let scan_options = ScanOptions {
        max_file_size_kb: config.scan.max_file_size_kb,
        jobs: None,
        no_cache: false,
    };

    let result = engine
        .scan_with_options(&args.target, None, &scan_options)
        .context("scan engine failed")?;

    info!(
        findings = result.findings.len(),
        files_scanned = result.files_scanned,
        files_skipped = result.files_skipped,
        "scan completed for baseline diff"
    );

    // 4. Load existing baseline.
    let baseline = atlas_policy::baseline::load_baseline(&args.baseline)
        .with_context(|| format!("failed to load baseline from '{}'", args.baseline.display()))?;

    // 5. Collect current fingerprints and diff against baseline.
    let current_fingerprints: Vec<String> = result
        .findings
        .iter()
        .map(|f| f.fingerprint.clone())
        .collect();

    let diff = atlas_policy::baseline::diff_findings(&current_fingerprints, &baseline);

    // 6. Print summary.
    println!("Baseline diff:");
    println!("  New:       {} findings", diff.new_count);
    println!("  Baselined: {} findings", diff.baselined_count);
    println!("  Resolved:  {} findings", diff.resolved_count);

    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_args_construction() {
        let args = CreateArgs {
            target: PathBuf::from("/tmp/project"),
            output: PathBuf::from("/tmp/baseline.json"),
            policy: None,
        };
        assert_eq!(args.target, PathBuf::from("/tmp/project"));
        assert_eq!(args.output, PathBuf::from("/tmp/baseline.json"));
        assert!(args.policy.is_none());
    }

    #[test]
    fn create_args_with_policy() {
        let args = CreateArgs {
            target: PathBuf::from("/tmp/project"),
            output: PathBuf::from("/tmp/baseline.json"),
            policy: Some(PathBuf::from("/tmp/policy.yaml")),
        };
        assert_eq!(args.policy, Some(PathBuf::from("/tmp/policy.yaml")));
    }

    #[test]
    fn diff_args_construction() {
        let args = DiffArgs {
            target: PathBuf::from("/tmp/project"),
            baseline: PathBuf::from("/tmp/baseline.json"),
        };
        assert_eq!(args.target, PathBuf::from("/tmp/project"));
        assert_eq!(args.baseline, PathBuf::from("/tmp/baseline.json"));
    }

    #[test]
    fn baseline_action_variants() {
        // Verify that BaselineAction::Create and BaselineAction::Diff can be constructed.
        let create = BaselineAction::Create(CreateArgs {
            target: PathBuf::from("."),
            output: PathBuf::from("baseline.json"),
            policy: None,
        });
        assert!(matches!(create, BaselineAction::Create(_)));

        let diff = BaselineAction::Diff(DiffArgs {
            target: PathBuf::from("."),
            baseline: PathBuf::from("baseline.json"),
        });
        assert!(matches!(diff, BaselineAction::Diff(_)));
    }

    #[test]
    fn baseline_args_construction() {
        let args = BaselineArgs {
            action: BaselineAction::Create(CreateArgs {
                target: PathBuf::from("/src"),
                output: PathBuf::from("/out/baseline.json"),
                policy: None,
            }),
        };
        assert!(matches!(args.action, BaselineAction::Create(_)));
    }
}
