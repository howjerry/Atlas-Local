//! `atlas compliance` subcommand — compliance coverage reporting.

use std::path::PathBuf;
use anyhow::{Context, bail};
use clap::{Args, Subcommand, ValueEnum};
use tracing::info;

use atlas_core::compliance::{self, ComplianceSummary};
use atlas_rules::declarative::DeclarativeRuleLoader;

use crate::ExitCode;

/// Compliance framework mapping and coverage reporting.
#[derive(Debug, Args)]
pub struct ComplianceArgs {
    #[command(subcommand)]
    command: ComplianceCommand,
}

#[derive(Debug, Subcommand)]
enum ComplianceCommand {
    /// Compute and display compliance coverage for one or more frameworks.
    Coverage(CoverageArgs),
}

#[derive(Debug, Args)]
struct CoverageArgs {
    /// Framework IDs to compute coverage for (e.g. owasp-top-10-2021, pci-dss-4.0).
    #[arg(required = true)]
    frameworks: Vec<String>,

    /// Output format.
    #[arg(long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

pub fn execute(args: ComplianceArgs) -> anyhow::Result<ExitCode> {
    match args.command {
        ComplianceCommand::Coverage(coverage_args) => execute_coverage(coverage_args),
    }
}

fn execute_coverage(args: CoverageArgs) -> anyhow::Result<ExitCode> {
    // 1. Load framework definitions from rules/compliance/.
    let compliance_dir = PathBuf::from("rules/compliance");
    let frameworks = compliance::load_frameworks(&compliance_dir)
        .context("failed to load compliance framework definitions")?;

    if frameworks.is_empty() {
        bail!(
            "No compliance framework definitions found in {}",
            compliance_dir.display()
        );
    }

    // 2. Validate requested framework IDs.
    let available_ids: Vec<&str> = frameworks.iter().map(|f| f.id.as_str()).collect();
    for requested in &args.frameworks {
        if !available_ids.contains(&requested.as_str()) {
            bail!(
                "Unknown framework: '{}'. Available frameworks: {}",
                requested,
                available_ids.join(", ")
            );
        }
    }

    // 3. Load rules from rules/builtin/.
    let builtin_dir = PathBuf::from("rules/builtin");
    let rules = if builtin_dir.is_dir() {
        let loader = DeclarativeRuleLoader;
        loader
            .load_from_dir(&builtin_dir)
            .map_err(|e| anyhow::anyhow!("failed to load rules: {e}"))?
    } else {
        Vec::new()
    };

    let security_rules: Vec<_> = rules
        .iter()
        .filter(|r| {
            r.category == atlas_rules::Category::Security
                || r.category == atlas_rules::Category::Secrets
        })
        .collect();

    if security_rules.is_empty() {
        eprintln!(
            "Warning: No security or secrets rules loaded. Coverage will be 0% for all frameworks."
        );
    }

    info!(
        rule_count = rules.len(),
        security_count = security_rules.len(),
        "loaded rules for compliance coverage"
    );

    // 4. Compute coverage for each requested framework.
    let mut summaries: Vec<ComplianceSummary> = Vec::new();
    for fw in &frameworks {
        if args.frameworks.contains(&fw.id) {
            let summary = compliance::compute_coverage(fw, &rules);
            summaries.push(summary);
        }
    }

    // 5. Render output.
    match args.format {
        OutputFormat::Table => render_table(&summaries),
        OutputFormat::Json => render_json(&summaries)?,
    }

    Ok(ExitCode::Pass)
}

fn render_table(summaries: &[ComplianceSummary]) {
    for (i, summary) in summaries.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!(
            "Framework: {} ({})",
            summary.framework_name, summary.framework
        );
        println!(
            "{:<20} {:<45} {:>8} {:>14}",
            "Category", "Title", "Rules", "Status"
        );
        println!("{}", "-".repeat(90));

        for cat in &summary.categories {
            println!(
                "{:<20} {:<45} {:>8} {:>14}",
                cat.category_id,
                truncate(&cat.category_title, 45),
                cat.mapped_rules,
                cat.status
            );
        }

        println!("{}", "-".repeat(90));
        println!(
            "Coverage: {}/{} categories covered ({:.1}%) | {} total rules mapped",
            summary.covered_categories,
            summary.categories.len(),
            summary.coverage_percentage,
            summary.total_rules
        );
    }
}

fn render_json(summaries: &[ComplianceSummary]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(summaries)
        .context("failed to serialise compliance coverage to JSON")?;
    println!("{json}");
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
