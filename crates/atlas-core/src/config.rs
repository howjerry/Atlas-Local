//! Configuration loading and merging for Atlas Local.
//!
//! Atlas resolves configuration from multiple sources with CLI > project > home > defaults
//! precedence. Configuration is loaded from `.atlas.yaml` files.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{AnalysisLevel, CoreError};

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

/// Top-level Atlas configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AtlasConfig {
    /// Scan-related settings.
    pub scan: ScanConfig,
    /// Analysis depth settings.
    pub analysis: AnalysisConfig,
    /// Cache settings.
    pub cache: CacheConfig,
    /// Reporting settings.
    pub reporting: ReportingConfig,
    /// Rulepack settings.
    pub rulepacks: RulepackConfig,
}

// ---------------------------------------------------------------------------
// ScanConfig
// ---------------------------------------------------------------------------

/// Scan-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Languages to scan. Empty means all supported languages.
    pub languages: Vec<String>,
    /// Glob patterns for files/directories to exclude.
    pub exclude_patterns: Vec<String>,
    /// Whether to follow symlinks during scanning.
    pub follow_symlinks: bool,
    /// Maximum file size in KiB. Files larger than this are skipped.
    pub max_file_size_kb: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            languages: Vec::new(),
            exclude_patterns: vec![
                // === Minified / Bundled ===
                "**/*.min.js".into(),
                "**/*.min.css".into(),
                "**/*.bundle.js".into(),
                "**/*.chunk.js".into(),
                // === 第三方套件 ===
                "**/node_modules/**".into(),
                "**/vendor/**".into(),
                "**/bower_components/**".into(),
                // === Python 虛擬環境 / 快取 ===
                "**/venv/**".into(),
                "**/.venv/**".into(),
                "**/__pycache__/**".into(),
                "**/.tox/**".into(),
                "**/site-packages/**".into(),
                // === .NET 編譯產物 ===
                "**/bin/Debug/**".into(),
                "**/bin/Release/**".into(),
                "**/obj/**".into(),
                // === 通用 Build Artifacts ===
                "**/dist/**".into(),
                "**/build/output/**".into(),
                // === IDE / 工具 ===
                "**/.idea/**".into(),
                "**/.vs/**".into(),
                "**/.vscode/**".into(),
            ],
            follow_symlinks: true,
            max_file_size_kb: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// AnalysisConfig
// ---------------------------------------------------------------------------

/// Analysis depth settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    /// Maximum analysis depth level.
    pub max_depth: AnalysisLevel,
    /// Maximum call chain depth for L3 inter-procedural analysis.
    pub l3_call_depth: u32,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_depth: AnalysisLevel::L2,
            l3_call_depth: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// CacheConfig
// ---------------------------------------------------------------------------

/// Cache settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Whether caching is enabled.
    pub enabled: bool,
    /// Maximum cache size in MiB.
    pub max_size_mb: u64,
    /// Path to the cache directory.
    pub path: Option<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_mb: 500,
            path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ReportingConfig
// ---------------------------------------------------------------------------

/// Reporting settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportingConfig {
    /// Default output format.
    pub default_format: String,
    /// Whether to include timestamps in output (disabled by default for determinism).
    pub timestamp: bool,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            default_format: "json".to_string(),
            timestamp: false,
        }
    }
}

// ---------------------------------------------------------------------------
// RulepackConfig
// ---------------------------------------------------------------------------

/// Rulepack settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RulepackConfig {
    /// Trusted ed25519 public keys (base64-encoded).
    pub trusted_keys: Vec<String>,
    /// Path to the rulepack store directory.
    pub store_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/// Load and merge configuration from multiple sources.
///
/// Resolution order (highest priority first):
/// 1. CLI overrides (applied by the caller after loading)
/// 2. `.atlas.yaml` in the project directory (scan target)
/// 3. `.atlas.yaml` in the user home directory
/// 4. Built-in defaults
///
/// # Errors
///
/// Returns [`CoreError::Config`] if a config file exists but is malformed.
pub fn load_config(project_dir: Option<&Path>) -> Result<AtlasConfig, CoreError> {
    let mut config = AtlasConfig::default();

    // Layer 1: Home directory config.
    if let Some(home) = home_dir() {
        let home_config = home.join(".atlas.yaml");
        if home_config.is_file() {
            debug!(path = %home_config.display(), "loading home config");
            let layer = load_config_file(&home_config)?;
            config = merge_config(config, layer);
        }
    }

    // Layer 2: Project directory config.
    if let Some(dir) = project_dir {
        let project_config = dir.join(".atlas.yaml");
        if project_config.is_file() {
            debug!(path = %project_config.display(), "loading project config");
            let layer = load_config_file(&project_config)?;
            config = merge_config(config, layer);
        }
    }

    info!("configuration loaded");
    Ok(config)
}

/// Load a single config file and deserialize it.
fn load_config_file(path: &Path) -> Result<AtlasConfig, CoreError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        CoreError::Config(format!(
            "failed to read config file '{}': {e}",
            path.display()
        ))
    })?;

    serde_yml::from_str(&content).map_err(|e| {
        CoreError::Config(format!(
            "failed to parse config file '{}': {e}",
            path.display()
        ))
    })
}

/// Merge `overlay` on top of `base`. Non-default values in `overlay` win.
///
/// For simplicity, this uses a "full replacement at section level" strategy:
/// if the overlay specifies any field in a section, that section's values
/// from the overlay take precedence. This matches the user expectation that
/// a project config overrides the home config.
fn merge_config(base: AtlasConfig, overlay: AtlasConfig) -> AtlasConfig {
    AtlasConfig {
        scan: merge_scan(base.scan, overlay.scan),
        analysis: merge_analysis(base.analysis, overlay.analysis),
        cache: merge_cache(base.cache, overlay.cache),
        reporting: merge_reporting(base.reporting, overlay.reporting),
        rulepacks: merge_rulepacks(base.rulepacks, overlay.rulepacks),
    }
}

fn merge_scan(base: ScanConfig, overlay: ScanConfig) -> ScanConfig {
    ScanConfig {
        languages: if overlay.languages.is_empty() {
            base.languages
        } else {
            overlay.languages
        },
        exclude_patterns: if overlay.exclude_patterns.is_empty() {
            base.exclude_patterns
        } else {
            // Union exclude patterns from both levels.
            let mut merged = base.exclude_patterns;
            for p in overlay.exclude_patterns {
                if !merged.contains(&p) {
                    merged.push(p);
                }
            }
            merged
        },
        follow_symlinks: overlay.follow_symlinks,
        max_file_size_kb: overlay.max_file_size_kb,
    }
}

fn merge_analysis(base: AnalysisConfig, overlay: AnalysisConfig) -> AnalysisConfig {
    // Overlay values always win (they default to the same as base defaults,
    // so an explicitly set value will take effect).
    let _ = base;
    overlay
}

fn merge_cache(base: CacheConfig, overlay: CacheConfig) -> CacheConfig {
    CacheConfig {
        enabled: overlay.enabled,
        max_size_mb: overlay.max_size_mb,
        path: overlay.path.or(base.path),
    }
}

fn merge_reporting(base: ReportingConfig, overlay: ReportingConfig) -> ReportingConfig {
    let _ = base;
    overlay
}

fn merge_rulepacks(base: RulepackConfig, overlay: RulepackConfig) -> RulepackConfig {
    RulepackConfig {
        trusted_keys: if overlay.trusted_keys.is_empty() {
            base.trusted_keys
        } else {
            // Union keys from both levels.
            let mut merged = base.trusted_keys;
            for k in overlay.trusted_keys {
                if !merged.contains(&k) {
                    merged.push(k);
                }
            }
            merged
        },
        store_path: overlay.store_path.or(base.store_path),
    }
}

/// Get the user home directory.
fn home_dir() -> Option<PathBuf> {
    // Use the HOME environment variable (works on macOS/Linux).
    // Falls back to USERPROFILE on Windows.
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn default_config() {
        let config = AtlasConfig::default();
        assert!(config.scan.languages.is_empty());
        // 預設排除模式應包含常見的第三方/build/minified 路徑
        assert!(
            !config.scan.exclude_patterns.is_empty(),
            "default exclude_patterns should not be empty"
        );
        assert!(
            config.scan.exclude_patterns.contains(&"**/node_modules/**".to_string()),
            "default excludes should contain node_modules"
        );
        assert!(config.scan.follow_symlinks);
        assert_eq!(config.scan.max_file_size_kb, 1024);
        assert_eq!(config.analysis.max_depth, AnalysisLevel::L2);
        assert_eq!(config.analysis.l3_call_depth, 5);
        assert!(config.cache.enabled);
        assert_eq!(config.cache.max_size_mb, 500);
        assert_eq!(config.reporting.default_format, "json");
        assert!(!config.reporting.timestamp);
    }

    #[test]
    fn load_config_from_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let yaml = r#"
scan:
  languages: [typescript, java]
  exclude_patterns:
    - "node_modules/**"
  follow_symlinks: false
  max_file_size_kb: 2048
analysis:
  max_depth: L1
  l3_call_depth: 3
cache:
  enabled: false
  max_size_mb: 200
reporting:
  default_format: sarif
  timestamp: true
"#;
        let config_path = tmp.path().join(".atlas.yaml");
        fs::write(&config_path, yaml).unwrap();

        let config = load_config(Some(tmp.path())).unwrap();

        assert_eq!(config.scan.languages, vec!["typescript", "java"]);
        // 合併邏輯是 union：預設排除 + overlay 排除
        assert!(
            config.scan.exclude_patterns.contains(&"node_modules/**".to_string()),
            "overlay pattern should be merged"
        );
        assert!(
            config.scan.exclude_patterns.contains(&"**/node_modules/**".to_string()),
            "default patterns should be preserved"
        );
        assert!(!config.scan.follow_symlinks);
        assert_eq!(config.scan.max_file_size_kb, 2048);
        assert_eq!(config.analysis.max_depth, AnalysisLevel::L1);
        assert_eq!(config.analysis.l3_call_depth, 3);
        assert!(!config.cache.enabled);
        assert_eq!(config.cache.max_size_mb, 200);
        assert_eq!(config.reporting.default_format, "sarif");
        assert!(config.reporting.timestamp);
    }

    #[test]
    fn load_config_missing_file_returns_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let config = load_config(Some(tmp.path())).unwrap();
        assert_eq!(config, AtlasConfig::default());
    }

    #[test]
    fn load_config_malformed_yaml_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(".atlas.yaml"), "invalid: [yaml: {broken").unwrap();
        let result = load_config(Some(tmp.path()));
        assert!(result.is_err());
        if let Err(CoreError::Config(msg)) = result {
            assert!(msg.contains("failed to parse"));
        }
    }

    #[test]
    fn load_config_partial_yaml_uses_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let yaml = r#"
scan:
  max_file_size_kb: 4096
"#;
        fs::write(tmp.path().join(".atlas.yaml"), yaml).unwrap();

        let config = load_config(Some(tmp.path())).unwrap();

        // Specified value overrides default.
        assert_eq!(config.scan.max_file_size_kb, 4096);
        // Unspecified values remain default.
        assert!(config.scan.follow_symlinks);
        assert!(config.scan.languages.is_empty());
        assert_eq!(config.analysis.max_depth, AnalysisLevel::L2);
    }

    #[test]
    fn merge_exclude_patterns_unions() {
        let base = ScanConfig {
            exclude_patterns: vec!["vendor/**".to_string()],
            ..Default::default()
        };
        let overlay = ScanConfig {
            exclude_patterns: vec!["vendor/**".to_string(), "dist/**".to_string()],
            ..Default::default()
        };

        let merged = merge_scan(base, overlay);
        assert_eq!(merged.exclude_patterns, vec!["vendor/**", "dist/**"]);
    }

    #[test]
    fn merge_trusted_keys_unions() {
        let base = RulepackConfig {
            trusted_keys: vec!["key-a".to_string()],
            ..Default::default()
        };
        let overlay = RulepackConfig {
            trusted_keys: vec!["key-a".to_string(), "key-b".to_string()],
            ..Default::default()
        };

        let merged = merge_rulepacks(base, overlay);
        assert_eq!(merged.trusted_keys, vec!["key-a", "key-b"]);
    }

    #[test]
    fn merge_cache_path_overlay_wins() {
        let base = CacheConfig {
            path: Some("/home/user/.atlas/cache".to_string()),
            ..Default::default()
        };
        let overlay = CacheConfig {
            path: Some("/project/.cache".to_string()),
            ..Default::default()
        };

        let merged = merge_cache(base, overlay);
        assert_eq!(merged.path, Some("/project/.cache".to_string()));
    }

    #[test]
    fn merge_cache_path_base_kept_when_overlay_none() {
        let base = CacheConfig {
            path: Some("/home/user/.atlas/cache".to_string()),
            ..Default::default()
        };
        let overlay = CacheConfig {
            path: None,
            ..Default::default()
        };

        let merged = merge_cache(base, overlay);
        assert_eq!(merged.path, Some("/home/user/.atlas/cache".to_string()));
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = AtlasConfig::default();
        let yaml = serde_yml::to_string(&config).unwrap();
        let back: AtlasConfig = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn load_config_no_project_dir() {
        let config = load_config(None).unwrap();
        // Should return at least defaults (home config may or may not exist).
        assert!(config.scan.follow_symlinks);
    }

    // PartialEq is needed for test assertions.
    impl PartialEq for AtlasConfig {
        fn eq(&self, other: &Self) -> bool {
            self.scan == other.scan
                && self.analysis == other.analysis
                && self.cache == other.cache
                && self.reporting == other.reporting
                && self.rulepacks == other.rulepacks
        }
    }

    impl PartialEq for ScanConfig {
        fn eq(&self, other: &Self) -> bool {
            self.languages == other.languages
                && self.exclude_patterns == other.exclude_patterns
                && self.follow_symlinks == other.follow_symlinks
                && self.max_file_size_kb == other.max_file_size_kb
        }
    }

    impl PartialEq for AnalysisConfig {
        fn eq(&self, other: &Self) -> bool {
            self.max_depth == other.max_depth && self.l3_call_depth == other.l3_call_depth
        }
    }

    impl PartialEq for CacheConfig {
        fn eq(&self, other: &Self) -> bool {
            self.enabled == other.enabled
                && self.max_size_mb == other.max_size_mb
                && self.path == other.path
        }
    }

    impl PartialEq for ReportingConfig {
        fn eq(&self, other: &Self) -> bool {
            self.default_format == other.default_format && self.timestamp == other.timestamp
        }
    }

    impl PartialEq for RulepackConfig {
        fn eq(&self, other: &Self) -> bool {
            self.trusted_keys == other.trusted_keys && self.store_path == other.store_path
        }
    }
}
