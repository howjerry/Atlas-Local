use clap::{Parser, Subcommand};

use atlas_cli::commands;

/// Atlas Local -- Offline SAST Code Analysis Tool.
#[derive(Parser)]
#[command(
    name = "atlas",
    about = "Atlas Local -- Offline SAST Code Analysis Tool"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project for security vulnerabilities.
    Scan(commands::scan::ScanArgs),
    /// Show or validate Atlas configuration.
    Config(commands::config::ConfigArgs),
    /// Manage signed rulepacks (install, list, rollback).
    Rulepack(commands::rulepack::RulepackArgs),
    /// Manage baselines for incremental adoption (create, diff).
    Baseline(commands::baseline::BaselineArgs),
    /// Manage Atlas licences (activate, status, deactivate).
    License(commands::license::LicenseArgs),
    /// Compliance framework coverage reporting.
    Compliance(commands::compliance::ComplianceArgs),
    /// Generate signed audit bundles for compliance.
    Audit(commands::audit::AuditArgs),
    /// Display diagnostic information.
    Diag(commands::diag::DiagArgs),
    /// SCA dependency vulnerability scanning and database management.
    Sca(commands::sca::ScaArgs),
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan(args) => commands::scan::execute(args),
        Commands::Compliance(args) => commands::compliance::execute(args),
        Commands::Config(args) => commands::config::execute(args),
        Commands::Rulepack(args) => commands::rulepack::execute(args),
        Commands::Baseline(args) => commands::baseline::execute(args),
        Commands::License(args) => commands::license::execute(args),
        Commands::Audit(args) => commands::audit::execute(args),
        Commands::Diag(args) => commands::diag::execute(args),
        Commands::Sca(args) => commands::sca::execute(args),
    };

    match result {
        Ok(code) => atlas_cli::terminate(code),
        Err(err) => {
            eprintln!("atlas: error: {err:#}");
            atlas_cli::terminate(atlas_cli::ExitCode::EngineError)
        }
    }
}
