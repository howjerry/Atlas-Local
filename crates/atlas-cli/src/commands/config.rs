//! The `config` CLI subcommand -- show and validate Atlas configuration.

use anyhow::Context;

use atlas_core::config;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// ConfigArgs
// ---------------------------------------------------------------------------

/// Manage Atlas configuration.
#[derive(Debug, clap::Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// Config sub-subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum ConfigAction {
    /// Show current configuration.
    Show,
    /// Validate configuration file.
    Validate,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `config` subcommand.
///
/// Returns an [`ExitCode`] indicating the outcome.
pub fn execute(args: ConfigArgs) -> Result<ExitCode, anyhow::Error> {
    match args.action {
        ConfigAction::Show => execute_show(),
        ConfigAction::Validate => execute_validate(),
    }
}

/// Loads the current configuration, serializes it to YAML, and prints it to stdout.
fn execute_show() -> Result<ExitCode, anyhow::Error> {
    let cfg = config::load_config(None).context("failed to load configuration")?;

    let yaml = serde_yml::to_string(&cfg).context("failed to serialize configuration to YAML")?;

    print!("{yaml}");

    Ok(ExitCode::Pass)
}

/// Loads the current configuration and reports whether it is valid.
fn execute_validate() -> Result<ExitCode, anyhow::Error> {
    match config::load_config(None) {
        Ok(_) => {
            println!("Configuration is valid.");
            Ok(ExitCode::Pass)
        }
        Err(e) => {
            eprintln!("Configuration error: {e}");
            Ok(ExitCode::ConfigError)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_show_succeeds() {
        let args = ConfigArgs {
            action: ConfigAction::Show,
        };
        let result = execute(args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::Pass);
    }

    #[test]
    fn execute_validate_succeeds() {
        let args = ConfigArgs {
            action: ConfigAction::Validate,
        };
        let result = execute(args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::Pass);
    }
}
