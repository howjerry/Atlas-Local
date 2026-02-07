use clap::{Parser, Subcommand};

use atlas_cli::commands;

/// Atlas Local -- Offline SAST Code Analysis Tool.
#[derive(Parser)]
#[command(name = "atlas", about = "Atlas Local -- Offline SAST Code Analysis Tool")]
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
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan(args) => commands::scan::execute(args),
        Commands::Config(args) => commands::config::execute(args),
        Commands::Rulepack(args) => commands::rulepack::execute(args),
    };

    match result {
        Ok(code) => atlas_cli::terminate(code),
        Err(err) => {
            eprintln!("atlas: error: {err:#}");
            atlas_cli::terminate(atlas_cli::ExitCode::EngineError)
        }
    }
}
