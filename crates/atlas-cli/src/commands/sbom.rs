//! `atlas sbom` CLI 子命令 — SBOM 產生。

use std::path::PathBuf;

use anyhow::Context;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// SbomArgs
// ---------------------------------------------------------------------------

/// Generate Software Bill of Materials (SBOM) in industry-standard formats.
#[derive(Debug, clap::Args)]
pub struct SbomArgs {
    #[command(subcommand)]
    pub command: SbomCommand,
}

/// SBOM 子命令。
#[derive(Debug, clap::Subcommand)]
pub enum SbomCommand {
    /// Generate an SBOM from detected lockfiles.
    Generate(GenerateArgs),
}

/// `atlas sbom generate` 的參數。
#[derive(Debug, clap::Args)]
pub struct GenerateArgs {
    /// 掃描目標目錄（預設為當前目錄）。
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// SBOM 輸出格式：cyclonedx-json（預設）或 spdx-json。
    #[arg(long, default_value = "cyclonedx-json")]
    pub format: String,

    /// 輸出檔案路徑（省略則輸出至 stdout）。
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// SCA 漏洞資料庫路徑（預設 ~/.atlas/vuln.db）。
    /// 僅在 CycloneDX 格式中嵌入漏洞資訊。
    #[arg(long)]
    pub sca_db: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// 執行 `atlas sbom` 子命令。
pub fn execute(args: SbomArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, false, false);

    match args.command {
        SbomCommand::Generate(gen_args) => execute_generate(gen_args),
    }
}

/// 執行 `atlas sbom generate`。
fn execute_generate(args: GenerateArgs) -> Result<ExitCode, anyhow::Error> {
    // 解析格式
    let format: atlas_sca::sbom::SbomFormat = args
        .format
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // 解析目標目錄
    let scan_dir = args.target.canonicalize().with_context(|| {
        format!("target directory '{}' not found", args.target.display())
    })?;

    // 開啟漏洞資料庫（可選）
    let db_path = args.sca_db.unwrap_or_else(|| {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".atlas")
            .join("vuln.db")
    });

    let db = if db_path.exists() {
        match atlas_sca::database::VulnDatabase::open(&db_path) {
            Ok(d) => {
                tracing::debug!(db = %db_path.display(), "vulnerability database loaded");
                Some(d)
            }
            Err(e) => {
                tracing::warn!(
                    db = %db_path.display(),
                    error = %e,
                    "Vulnerability database not found"
                );
                None
            }
        }
    } else {
        tracing::info!(
            db = %db_path.display(),
            "Vulnerability database not found, generating SBOM without vulnerability data"
        );
        None
    };

    // 產生 SBOM
    let output = atlas_sca::sbom::generate_sbom(
        &scan_dir,
        format,
        db.as_ref(),
    )
    .with_context(|| "failed to generate SBOM")?;

    // 輸出
    match args.output {
        Some(ref path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create output directory '{}'", parent.display())
                })?;
            }
            std::fs::write(path, &output).with_context(|| {
                format!("failed to write SBOM to '{}'", path.display())
            })?;
            eprintln!("SBOM written to: {}", path.display());
        }
        None => {
            print!("{output}");
        }
    }

    Ok(ExitCode::Pass)
}
