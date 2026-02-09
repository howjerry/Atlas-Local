//! The `audit` CLI subcommand — generate signed audit bundles.

use std::path::PathBuf;

use anyhow::Context;
use tracing::info;

use atlas_core::engine::{ScanEngine, ScanOptions};

use crate::ExitCode;

// ---------------------------------------------------------------------------
// AuditArgs
// ---------------------------------------------------------------------------

/// Generate audit bundles for compliance.
#[derive(Debug, clap::Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub action: AuditAction,
}

/// Audit sub-subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum AuditAction {
    /// Generate a signed audit bundle from a scan.
    Bundle(BundleArgs),
}

// ---------------------------------------------------------------------------
// BundleArgs
// ---------------------------------------------------------------------------

/// Arguments for the `audit bundle` command.
#[derive(Debug, clap::Args)]
pub struct BundleArgs {
    /// Target directory or file to scan.
    pub target: PathBuf,

    /// Output path for the audit bundle archive (.tar.gz).
    #[arg(long, short)]
    pub output: PathBuf,

    /// Policy file (optional).
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `audit` subcommand.
pub fn execute(args: AuditArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, false, false);

    match args.action {
        AuditAction::Bundle(a) => execute_bundle(a),
    }
}

// ---------------------------------------------------------------------------
// bundle
// ---------------------------------------------------------------------------

fn execute_bundle(args: BundleArgs) -> Result<ExitCode, anyhow::Error> {
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
    }

    // 3. Run scan.
    let scan_options = ScanOptions {
        max_file_size_kb: config.scan.max_file_size_kb,
        ..Default::default()
    };

    let result = engine
        .scan_with_options(&args.target, None, &scan_options)
        .context("scan engine failed")?;

    info!(
        findings = result.findings.len(),
        files_scanned = result.files_scanned,
        "scan completed for audit bundle"
    );

    // 4. Collect rule metadata from active rules.
    let rules_meta: Vec<atlas_audit::bundle::RuleMetadata> = engine
        .rules()
        .iter()
        .map(|r| atlas_audit::bundle::RuleMetadata {
            rule_id: r.id.clone(),
            name: r.name.clone(),
            version: r.version.clone(),
            category: r.category.to_string(),
            severity: r.severity.to_string(),
        })
        .collect();

    // 5. Build report JSON value.
    let report_value = serde_json::json!({
        "findings": result.findings.iter().map(|f| serde_json::json!({
            "rule_id": f.rule_id,
            "description": f.description,
            "file_path": f.file_path,
            "severity": f.severity.to_string(),
            "fingerprint": f.fingerprint,
        })).collect::<Vec<_>>(),
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
    });

    // 6. Build audit bundle.
    let engine_version = env!("CARGO_PKG_VERSION");
    let scan_id = format!("audit-{}", chrono::Utc::now().timestamp());

    let mut builder = atlas_audit::bundle::AuditBundleBuilder::new(scan_id, engine_version)
        .report(report_value)
        .rules_applied(rules_meta)
        .config_entry("target", serde_json::json!(args.target.to_string_lossy()))
        .config_entry(
            "max_file_size_kb",
            serde_json::json!(config.scan.max_file_size_kb),
        );

    // 7. Add policy if provided.
    if let Some(ref policy_path) = args.policy {
        let policy_data = std::fs::read_to_string(policy_path)
            .with_context(|| format!("reading policy file {}", policy_path.display()))?;
        let policy_value: serde_json::Value = serde_json::from_str(&policy_data).or_else(|_| {
            serde_yml::from_str::<serde_json::Value>(&policy_data)
                .map_err(|e| anyhow::anyhow!("parsing policy: {e}"))
        })?;
        builder = builder.policy(policy_value);
    }

    let bundle = builder.build().context("building audit bundle")?;

    // 8. Write archive.
    atlas_audit::bundle::write_bundle_archive(&bundle, &args.output)
        .context("writing audit bundle archive")?;

    println!(
        "Audit bundle written to {} ({} rules, {} findings)",
        args.output.display(),
        bundle.rules_applied.len(),
        bundle.report["findings"].as_array().map_or(0, |a| a.len()),
    );

    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_args_construction() {
        let args = BundleArgs {
            target: PathBuf::from("/tmp/project"),
            output: PathBuf::from("/tmp/audit.tar.gz"),
            policy: None,
        };
        assert_eq!(args.target, PathBuf::from("/tmp/project"));
        assert_eq!(args.output, PathBuf::from("/tmp/audit.tar.gz"));
        assert!(args.policy.is_none());
    }

    #[test]
    fn audit_action_variants() {
        let bundle = AuditAction::Bundle(BundleArgs {
            target: PathBuf::from("."),
            output: PathBuf::from("audit.tar.gz"),
            policy: None,
        });
        assert!(matches!(bundle, AuditAction::Bundle(_)));
    }
}
