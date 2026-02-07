//! The `rulepack` CLI subcommand -- manage signed rulepacks.

use std::path::PathBuf;

use anyhow::Context;
use tracing::info;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// RulepackArgs
// ---------------------------------------------------------------------------

/// Manage signed rulepacks (install, list, rollback).
#[derive(Debug, clap::Args)]
pub struct RulepackArgs {
    #[command(subcommand)]
    pub action: RulepackAction,
}

/// Rulepack sub-subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum RulepackAction {
    /// Install a rulepack from a .pack file.
    Install(InstallArgs),
    /// List installed rulepacks.
    List,
    /// Rollback a rulepack to its previous version.
    Rollback(RollbackArgs),
}

/// Arguments for the `rulepack install` command.
#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// Path to the .pack file to install.
    pub pack_file: PathBuf,

    /// Rulepack store directory (default: ~/.atlas/rulepacks).
    #[arg(long)]
    pub store_dir: Option<PathBuf>,
}

/// Arguments for the `rulepack rollback` command.
#[derive(Debug, clap::Args)]
pub struct RollbackArgs {
    /// ID of the rulepack to rollback.
    pub pack_id: String,

    /// Rulepack store directory (default: ~/.atlas/rulepacks).
    #[arg(long)]
    pub store_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the default rulepack store directory (~/.atlas/rulepacks/).
fn default_store_dir() -> Result<PathBuf, anyhow::Error> {
    let home = dirs_next::home_dir()
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
        .context("unable to determine home directory")?;
    Ok(home.join(".atlas").join("rulepacks"))
}

/// Resolves the store directory from an optional override or the default.
fn resolve_store_dir(override_dir: Option<&PathBuf>) -> Result<PathBuf, anyhow::Error> {
    match override_dir {
        Some(dir) => Ok(dir.clone()),
        None => default_store_dir(),
    }
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `rulepack` subcommand.
pub fn execute(args: RulepackArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, false, false);

    match args.action {
        RulepackAction::Install(install_args) => execute_install(install_args),
        RulepackAction::List => execute_list(None),
        RulepackAction::Rollback(rollback_args) => execute_rollback(rollback_args),
    }
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

fn execute_install(args: InstallArgs) -> Result<ExitCode, anyhow::Error> {
    let store_dir = resolve_store_dir(args.store_dir.as_ref())?;

    // Load trusted keys from config.
    let config = atlas_core::config::load_config(None).unwrap_or_default();
    let trusted_keys: Vec<String> = config.rulepacks.trusted_keys.clone();

    info!(
        pack_file = %args.pack_file.display(),
        store_dir = %store_dir.display(),
        "installing rulepack"
    );

    let result =
        atlas_rules::rulepack::install_rulepack(&args.pack_file, &store_dir, &trusted_keys)
            .with_context(|| {
                format!(
                    "failed to install rulepack from '{}'",
                    args.pack_file.display()
                )
            })?;

    println!(
        "Installed rulepack '{}' v{} ({} rules)",
        result.pack_id, result.version, result.rules_installed
    );

    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn execute_list(store_dir_override: Option<&PathBuf>) -> Result<ExitCode, anyhow::Error> {
    let store_dir = resolve_store_dir(store_dir_override)?;

    let packs = atlas_rules::rulepack::list_rulepacks(&store_dir)
        .context("failed to list installed rulepacks")?;

    if packs.is_empty() {
        println!("No rulepacks installed.");
    } else {
        println!("{:<30} {:<12} {:<8} AUTHOR", "ID", "VERSION", "RULES");
        println!("{}", "-".repeat(70));
        for pack in &packs {
            println!(
                "{:<30} {:<12} {:<8} {}",
                pack.id, pack.version, pack.rule_count, pack.author
            );
        }
        println!("\n{} rulepack(s) installed.", packs.len());
    }

    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------

fn execute_rollback(args: RollbackArgs) -> Result<ExitCode, anyhow::Error> {
    let store_dir = resolve_store_dir(args.store_dir.as_ref())?;

    info!(
        pack_id = %args.pack_id,
        store_dir = %store_dir.display(),
        "rolling back rulepack"
    );

    let result = atlas_rules::rulepack::rollback_rulepack(&args.pack_id, &store_dir)
        .with_context(|| format!("failed to rollback rulepack '{}'", args.pack_id))?;

    println!(
        "Rolled back '{}' to v{}",
        args.pack_id, result.restored_version
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
    fn default_store_dir_is_under_home() {
        let dir = default_store_dir();
        // May fail in CI if HOME is not set, but should succeed locally.
        if let Ok(dir) = dir {
            assert!(dir.to_string_lossy().contains(".atlas"));
            assert!(dir.to_string_lossy().contains("rulepacks"));
        }
    }

    #[test]
    fn resolve_store_dir_with_override() {
        let custom = PathBuf::from("/tmp/custom-store");
        let resolved = resolve_store_dir(Some(&custom)).unwrap();
        assert_eq!(resolved, custom);
    }

    #[test]
    fn resolve_store_dir_without_override() {
        let resolved = resolve_store_dir(None);
        // Should succeed if HOME is set.
        if let Ok(dir) = resolved {
            assert!(dir.to_string_lossy().contains("rulepacks"));
        }
    }
}
