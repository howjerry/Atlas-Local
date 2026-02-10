//! `atlas sca` CLI 子命令 — SCA 漏洞資料庫管理。

use std::path::PathBuf;

use anyhow::Context;
use tracing::info;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// ScaArgs
// ---------------------------------------------------------------------------

/// SCA (Software Composition Analysis) dependency vulnerability scanning.
#[derive(Debug, clap::Args)]
pub struct ScaArgs {
    #[command(subcommand)]
    pub command: ScaCommand,
}

/// SCA 子命令。
#[derive(Debug, clap::Subcommand)]
pub enum ScaCommand {
    /// Update the local vulnerability database from a signed bundle.
    UpdateDb(UpdateDbArgs),
    /// Show vulnerability database status and metadata.
    Status(StatusArgs),
}

/// `atlas sca update-db` 的參數。
#[derive(Debug, clap::Args)]
pub struct UpdateDbArgs {
    /// 已簽署的漏洞資料庫 bundle 路徑。
    #[arg(long)]
    pub bundle: PathBuf,

    /// 安裝目標路徑（預設 ~/.atlas/vuln.db）。
    #[arg(long)]
    pub target: Option<PathBuf>,
}

/// `atlas sca status` 的參數。
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// 資料庫路徑（預設 ~/.atlas/vuln.db）。
    #[arg(long = "db")]
    pub db_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// 執行 `atlas sca` 子命令。
pub fn execute(args: ScaArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, false, false);

    match args.command {
        ScaCommand::UpdateDb(update_args) => execute_update_db(update_args),
        ScaCommand::Status(status_args) => execute_status(status_args),
    }
}

/// 執行 `atlas sca update-db`：驗證簽章並安裝漏洞資料庫。
fn execute_update_db(args: UpdateDbArgs) -> Result<ExitCode, anyhow::Error> {
    let target = args.target.unwrap_or_else(|| {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".atlas")
            .join("vuln.db")
    });

    // 確保目標目錄存在
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
    }

    atlas_sca::update::update_database(&args.bundle, &target)
        .with_context(|| format!("failed to update vulnerability database from '{}'", args.bundle.display()))?;

    info!(
        bundle = %args.bundle.display(),
        target = %target.display(),
        "vulnerability database updated"
    );

    // 顯示更新後的 metadata
    let db = atlas_sca::database::VulnDatabase::open(&target)
        .context("failed to open updated database")?;
    let meta = db.metadata().context("failed to read database metadata")?;

    println!("Vulnerability database updated successfully.");
    println!("  Path: {}", target.display());
    println!("  Advisories: {}", meta.advisory_count);
    if let Some(ref updated) = meta.last_updated {
        println!("  Last updated: {updated}");
    }

    Ok(ExitCode::Pass)
}

/// 執行 `atlas sca status`：顯示漏洞資料庫狀態。
fn execute_status(args: StatusArgs) -> Result<ExitCode, anyhow::Error> {
    let db_path = args.db_path.unwrap_or_else(|| {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".atlas")
            .join("vuln.db")
    });

    if !db_path.exists() {
        println!("SCA vulnerability database not found at: {}", db_path.display());
        println!("Run 'atlas sca update-db --bundle <path>' to install.");
        return Ok(ExitCode::Pass);
    }

    let db = atlas_sca::database::VulnDatabase::open(&db_path)
        .with_context(|| format!("failed to open database '{}'", db_path.display()))?;
    let meta = db.metadata().context("failed to read database metadata")?;

    println!("SCA Vulnerability Database");
    println!("  Path: {}", db_path.display());
    println!("  Advisories: {}", meta.advisory_count);
    if let Some(ref updated) = meta.last_updated {
        println!("  Last updated: {updated}");
    } else {
        println!("  Last updated: unknown");
    }

    Ok(ExitCode::Pass)
}
