//! The `diag` CLI subcommand — display diagnostic information.
//!
//! Outputs engine version, rulepack version, licence status, environment
//! info, and cache statistics for troubleshooting.

use std::path::PathBuf;

use anyhow::Context;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// DiagArgs
// ---------------------------------------------------------------------------

/// Display diagnostic information about the Atlas installation.
#[derive(Debug, clap::Args)]
pub struct DiagArgs {
    /// Output in JSON format.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

/// Executes the `diag` subcommand.
pub fn execute(args: DiagArgs) -> Result<ExitCode, anyhow::Error> {
    let _ = atlas_core::init_tracing(false, true, false); // quiet mode

    let info = collect_diag_info();

    if args.json {
        let json = serde_json::to_string_pretty(&info)
            .context("serializing diagnostic info")?;
        println!("{json}");
    } else {
        print_diag_info(&info);
    }

    Ok(ExitCode::Pass)
}

// ---------------------------------------------------------------------------
// DiagInfo
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
struct DiagInfo {
    engine_version: String,
    rulepack_version: String,
    license_status: String,
    license_type: Option<String>,
    license_expiry: Option<String>,
    environment: EnvInfo,
    cache: CacheInfo,
}

#[derive(Debug, serde::Serialize)]
struct EnvInfo {
    os: String,
    arch: String,
    hostname: String,
    rust_version: String,
}

#[derive(Debug, serde::Serialize)]
struct CacheInfo {
    path: String,
    exists: bool,
    size_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// collect
// ---------------------------------------------------------------------------

fn collect_diag_info() -> DiagInfo {
    let engine_version = env!("CARGO_PKG_VERSION").to_string();

    // Rulepack version: hash of rule files in builtin directory.
    let rulepack_version = compute_rulepack_version();

    // Licence status.
    let (license_status, license_type, license_expiry) = check_license_status();

    // Environment info.
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let environment = EnvInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname,
        rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
    };

    // Cache info.
    let cache_path = dirs_next::home_dir()
        .map(|h| h.join(".atlas").join("cache.db"))
        .unwrap_or_else(|| PathBuf::from("cache.db"));

    let cache_exists = cache_path.exists();
    let cache_size = if cache_exists {
        std::fs::metadata(&cache_path).ok().map(|m| m.len())
    } else {
        None
    };

    let cache = CacheInfo {
        path: cache_path.to_string_lossy().to_string(),
        exists: cache_exists,
        size_bytes: cache_size,
    };

    DiagInfo {
        engine_version,
        rulepack_version,
        license_status,
        license_type,
        license_expiry,
        environment,
        cache,
    }
}

fn compute_rulepack_version() -> String {
    use sha2::{Digest, Sha256};

    let builtin_dir = PathBuf::from("rules/builtin");
    if !builtin_dir.is_dir() {
        return "no-rules".to_string();
    }

    let mut hasher = Sha256::new();
    let mut count = 0u32;

    // Walk rule files and hash their names and sizes.
    if let Ok(entries) = std::fs::read_dir(&builtin_dir) {
        let mut paths: Vec<_> = entries
            .filter_map(|e| e.ok())
            .flat_map(|e| {
                if e.path().is_dir() {
                    // Read subdirectory
                    std::fs::read_dir(e.path())
                        .ok()
                        .into_iter()
                        .flat_map(|rd| rd.filter_map(|e| e.ok()).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                } else {
                    vec![e]
                }
            })
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .map(|e| e.path())
            .collect();

        paths.sort();

        for path in &paths {
            hasher.update(path.to_string_lossy().as_bytes());
            if let Ok(meta) = std::fs::metadata(path) {
                hasher.update(meta.len().to_le_bytes());
            }
            count += 1;
        }
    }

    if count == 0 {
        return "no-rules".to_string();
    }

    let hash = hasher.finalize();
    format!("{} rules ({})", count, &hex::encode(hash)[..12])
}

fn check_license_status() -> (String, Option<String>, Option<String>) {
    let license_path = dirs_next::home_dir()
        .map(|h| h.join(".atlas").join("license.json"))
        .unwrap_or_else(|| PathBuf::from("license.json"));

    if !license_path.exists() {
        return ("not-installed".to_string(), None, None);
    }

    match atlas_license::validator::load_license(&license_path) {
        Ok(license) => {
            let fingerprint = atlas_license::node_locked::hardware_fingerprint();
            let status = atlas_license::validator::license_status(&license, Some(&fingerprint));
            let status_str = if status.valid { "valid" } else { "invalid" };
            (
                status_str.to_string(),
                Some(status.license_type.to_string()),
                Some(status.expiry),
            )
        }
        Err(e) => (format!("error: {e}"), None, None),
    }
}

// ---------------------------------------------------------------------------
// display
// ---------------------------------------------------------------------------

fn print_diag_info(info: &DiagInfo) {
    println!("Atlas Local Diagnostics");
    println!("=======================");
    println!();
    println!("Engine:    v{}", info.engine_version);
    println!("Rulepacks: {}", info.rulepack_version);
    println!();
    println!("License:");
    println!("  Status: {}", info.license_status);
    if let Some(ref lt) = info.license_type {
        println!("  Type:   {lt}");
    }
    if let Some(ref exp) = info.license_expiry {
        println!("  Expiry: {exp}");
    }
    println!();
    println!("Environment:");
    println!("  OS:       {}", info.environment.os);
    println!("  Arch:     {}", info.environment.arch);
    println!("  Hostname: {}", info.environment.hostname);
    println!("  Rust:     {}", info.environment.rust_version);
    println!();
    println!("Cache:");
    println!("  Path:   {}", info.cache.path);
    println!("  Exists: {}", info.cache.exists);
    if let Some(size) = info.cache.size_bytes {
        println!("  Size:   {} bytes", size);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_args_construction() {
        let args = DiagArgs { json: false };
        assert!(!args.json);
    }

    #[test]
    fn diag_args_json_mode() {
        let args = DiagArgs { json: true };
        assert!(args.json);
    }

    #[test]
    fn collect_diag_info_returns_data() {
        let info = collect_diag_info();
        assert!(!info.engine_version.is_empty());
        assert!(!info.rulepack_version.is_empty());
        assert!(!info.license_status.is_empty());
        assert!(!info.environment.os.is_empty());
        assert!(!info.environment.arch.is_empty());
    }

    #[test]
    fn rulepack_version_computation() {
        let version = compute_rulepack_version();
        // Should either be "no-rules" or "N rules (hash)"
        assert!(!version.is_empty());
    }
}
