//! The `license` CLI subcommand — activate, status, and deactivate licences.

use std::path::PathBuf;

use anyhow::Context;
use tracing::info;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// LicenseArgs
// ---------------------------------------------------------------------------

/// Manage Atlas Local licences.
#[derive(Debug, clap::Args)]
pub struct LicenseArgs {
    #[command(subcommand)]
    pub action: LicenseAction,
}

/// License sub-subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum LicenseAction {
    /// Activate a licence from a file.
    Activate(ActivateArgs),
    /// Show current licence status.
    Status(StatusArgs),
    /// Deactivate the current licence.
    Deactivate,
}

// ---------------------------------------------------------------------------
// ActivateArgs
// ---------------------------------------------------------------------------

/// Arguments for the `license activate` command.
#[derive(Debug, clap::Args)]
pub struct ActivateArgs {
    /// Path to the licence file.
    pub license_file: PathBuf,
}

// ---------------------------------------------------------------------------
// StatusArgs
// ---------------------------------------------------------------------------

/// Arguments for the `license status` command.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Path to the licence file (optional; defaults to ~/.atlas/license.json).
    #[arg(long)]
    pub license_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `license` subcommand.
pub fn execute(args: LicenseArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, false, false);

    match args.action {
        LicenseAction::Activate(a) => execute_activate(a),
        LicenseAction::Status(a) => execute_status(a),
        LicenseAction::Deactivate => execute_deactivate(),
    }
}

// ---------------------------------------------------------------------------
// activate
// ---------------------------------------------------------------------------

fn execute_activate(args: ActivateArgs) -> Result<ExitCode, anyhow::Error> {
    let license = atlas_license::validator::load_license(&args.license_file)
        .context("failed to load licence file")?;

    let fingerprint = atlas_license::node_locked::hardware_fingerprint();
    let status = atlas_license::validator::license_status(&license, Some(&fingerprint), None);

    if status.valid {
        // Copy licence to standard location.
        let dest = license_path()?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).context("failed to create ~/.atlas/ directory")?;
        }
        std::fs::copy(&args.license_file, &dest)
            .with_context(|| format!("failed to install licence to {}", dest.display()))?;

        println!("Licence activated successfully.");
        println!("  ID:           {}", status.license_id);
        println!("  Organization: {}", status.organization);
        println!("  Type:         {}", status.license_type);
        println!("  Expiry:       {}", status.expiry);
        println!("  Features:     {}", status.entitled_features.join(", "));
        println!("  Installed to: {}", dest.display());

        info!(license_id = %status.license_id, "license activated");
        Ok(ExitCode::Pass)
    } else {
        eprintln!(
            "Licence validation failed: {}",
            status.reason.unwrap_or_default()
        );
        Ok(ExitCode::LicenseError)
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn execute_status(args: StatusArgs) -> Result<ExitCode, anyhow::Error> {
    let path = args
        .license_file
        .unwrap_or_else(|| license_path().unwrap_or_else(|_| PathBuf::from("license.json")));

    if !path.exists() {
        println!("No licence file found at {}", path.display());
        return Ok(ExitCode::LicenseError);
    }

    let license =
        atlas_license::validator::load_license(&path).context("failed to load licence file")?;

    let fingerprint = atlas_license::node_locked::hardware_fingerprint();
    let status = atlas_license::validator::license_status(&license, Some(&fingerprint), None);

    println!("Licence Status:");
    println!(
        "  Valid:        {}",
        if status.valid { "yes" } else { "no" }
    );
    println!("  ID:           {}", status.license_id);
    println!("  Organization: {}", status.organization);
    println!("  Type:         {}", status.license_type);
    println!("  Expiry:       {}", status.expiry);
    println!("  Features:     {}", status.entitled_features.join(", "));
    if let Some(fp_match) = status.fingerprint_match {
        println!(
            "  Fingerprint:  {}",
            if fp_match { "match" } else { "MISMATCH" }
        );
    }
    if let Some(reason) = &status.reason {
        println!("  Reason:       {reason}");
    }

    if status.valid {
        Ok(ExitCode::Pass)
    } else {
        Ok(ExitCode::LicenseError)
    }
}

// ---------------------------------------------------------------------------
// deactivate
// ---------------------------------------------------------------------------

fn execute_deactivate() -> Result<ExitCode, anyhow::Error> {
    let path = license_path()?;
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove licence at {}", path.display()))?;
        println!("Licence deactivated (removed {}).", path.display());
    } else {
        println!("No licence file found at {}.", path.display());
    }
    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Returns the default licence file path: `~/.atlas/license.json`.
fn license_path() -> Result<PathBuf, anyhow::Error> {
    let home =
        dirs_next::home_dir().ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(home.join(".atlas").join("license.json"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activate_args_construction() {
        let args = ActivateArgs {
            license_file: PathBuf::from("/tmp/license.json"),
        };
        assert_eq!(args.license_file, PathBuf::from("/tmp/license.json"));
    }

    #[test]
    fn status_args_default() {
        let args = StatusArgs { license_file: None };
        assert!(args.license_file.is_none());
    }

    #[test]
    fn license_action_variants() {
        let activate = LicenseAction::Activate(ActivateArgs {
            license_file: PathBuf::from("lic.json"),
        });
        assert!(matches!(activate, LicenseAction::Activate(_)));

        let status = LicenseAction::Status(StatusArgs { license_file: None });
        assert!(matches!(status, LicenseAction::Status(_)));

        let deactivate = LicenseAction::Deactivate;
        assert!(matches!(deactivate, LicenseAction::Deactivate));
    }

    #[test]
    fn license_path_is_in_home_dir() {
        if let Ok(path) = license_path() {
            assert!(path.to_string_lossy().contains(".atlas"));
            assert!(path.to_string_lossy().contains("license.json"));
        }
        // OK if home_dir() is not available in CI.
    }
}
