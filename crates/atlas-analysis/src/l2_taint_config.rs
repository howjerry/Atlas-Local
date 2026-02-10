//! L2 污染追蹤配置 — source/sink/sanitizer 定義。
//!
//! 每個支援的語言都有一份 `taint_config.yaml`，定義：
//! - **Sources**: 使用者輸入來源模式（如 `req.body`）
//! - **Sinks**: 危險函數及其受污染的參數位置（如 `db.query` arg 0）
//! - **Sanitizers**: 清除污染的函數（如 `parseInt`）

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 配置型別
// ---------------------------------------------------------------------------

/// 單一語言的完整污染追蹤配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintConfig {
    /// 使用者輸入來源模式。
    #[serde(default)]
    pub sources: Vec<TaintSource>,
    /// 危險接收函數。
    #[serde(default)]
    pub sinks: Vec<TaintSink>,
    /// 淨化函數。
    #[serde(default)]
    pub sanitizers: Vec<TaintSanitizer>,
}

/// 污染來源 — 代表使用者可控的輸入模式。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// 匹配模式（如 `req.body`、`request.getParameter`）。
    pub pattern: String,
    /// 人類可讀的標籤。
    #[serde(default)]
    pub label: String,
}

/// 污染接收點 — 接收受污染資料時產生漏洞的函數。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// 函數名稱或模式（如 `db.query`）。
    pub function: String,
    /// 受污染的參數索引位置。
    #[serde(default)]
    pub tainted_args: Vec<u32>,
    /// 對應的漏洞類型（如 `sql-injection`）。
    #[serde(default)]
    pub vulnerability: String,
    /// CWE 識別碼（如 `CWE-89`）。
    #[serde(default)]
    pub cwe: String,
}

/// 淨化函數 — 清除污染狀態的函數。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSanitizer {
    /// 函數名稱（如 `parseInt`、`escapeHtml`）。
    pub function: String,
}

// ---------------------------------------------------------------------------
// 嵌入式配置載入
// ---------------------------------------------------------------------------

// 編譯時嵌入各語言的 taint_config.yaml。
const TYPESCRIPT_CONFIG: &str = include_str!("../../../rules/l2/typescript/taint_config.yaml");
const JAVA_CONFIG: &str = include_str!("../../../rules/l2/java/taint_config.yaml");
const PYTHON_CONFIG: &str = include_str!("../../../rules/l2/python/taint_config.yaml");
const CSHARP_CONFIG: &str = include_str!("../../../rules/l2/csharp/taint_config.yaml");
const GO_CONFIG: &str = include_str!("../../../rules/l2/go/taint_config.yaml");

/// 根據語言取得對應的 `TaintConfig`。
///
/// # Errors
///
/// 若 YAML 反序列化失敗則回傳錯誤。
pub fn load_taint_config(language: atlas_lang::Language) -> Result<TaintConfig, String> {
    let yaml = match language {
        atlas_lang::Language::TypeScript | atlas_lang::Language::JavaScript => TYPESCRIPT_CONFIG,
        atlas_lang::Language::Java => JAVA_CONFIG,
        atlas_lang::Language::Python => PYTHON_CONFIG,
        atlas_lang::Language::CSharp => CSHARP_CONFIG,
        atlas_lang::Language::Go => GO_CONFIG,
        // 新語言尚未支援 L2 分析
        _ => return Err(format!("L2 taint config not available for {language}")),
    };
    serde_yml::from_str(yaml)
        .map_err(|e| format!("failed to parse taint config for {language}: {e}"))
}

// ---------------------------------------------------------------------------
// 自訂 Taint Config（atlas-taint.yaml）
// ---------------------------------------------------------------------------

/// 使用者自訂的污染追蹤配置（來自專案根目錄 `atlas-taint.yaml`）。
///
/// 結構複用 L2 TaintConfig 的 sources/sinks/sanitizers，
/// 新增 `max_depth` 控制 L3 跨函數分析深度。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomTaintConfig {
    /// 自訂污染來源模式。
    #[serde(default)]
    pub sources: Vec<TaintSource>,
    /// 自訂污染接收函數。
    #[serde(default)]
    pub sinks: Vec<TaintSink>,
    /// 自訂淨化函數。
    #[serde(default)]
    pub sanitizers: Vec<TaintSanitizer>,
    /// L3 跨函數分析最大深度（覆蓋預設值 5）。
    #[serde(default)]
    pub max_depth: Option<u32>,
}

/// 從專案目錄載入自訂 taint config。
///
/// 在 `scan_dir` 中尋找 `atlas-taint.yaml` 或 `atlas-taint.yml`。
/// 若檔案不存在則回傳 `Ok(None)`。
///
/// # Errors
///
/// 若檔案存在但 YAML 格式無效則回傳描述性錯誤。
pub fn load_custom_taint_config(
    scan_dir: &std::path::Path,
) -> Result<Option<CustomTaintConfig>, String> {
    // 嘗試兩種副檔名
    let yaml_path = scan_dir.join("atlas-taint.yaml");
    let yml_path = scan_dir.join("atlas-taint.yml");

    let path = if yaml_path.exists() {
        yaml_path
    } else if yml_path.exists() {
        yml_path
    } else {
        return Ok(None);
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    let config: CustomTaintConfig = serde_yml::from_str(&content)
        .map_err(|e| format!("invalid atlas-taint.yaml at {}: {e}", path.display()))?;

    Ok(Some(config))
}

/// 合併 built-in 與自訂 taint config（append 語義）。
///
/// 自訂的 sources/sinks/sanitizers 會被 append 到 built-in 後面。
/// 回傳合併後的 `TaintConfig` 及自訂 `max_depth`（若有）。
pub fn merge_taint_config(
    mut builtin: TaintConfig,
    custom: CustomTaintConfig,
) -> (TaintConfig, Option<u32>) {
    builtin.sources.extend(custom.sources);
    builtin.sinks.extend(custom.sinks);
    builtin.sanitizers.extend(custom.sanitizers);
    (builtin, custom.max_depth)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_lang::Language;

    #[test]
    fn load_typescript_config() {
        let config = load_taint_config(Language::TypeScript).unwrap();
        assert!(!config.sources.is_empty(), "TypeScript 應有 sources");
        assert!(!config.sinks.is_empty(), "TypeScript 應有 sinks");
        assert!(!config.sanitizers.is_empty(), "TypeScript 應有 sanitizers");
    }

    #[test]
    fn load_java_config() {
        let config = load_taint_config(Language::Java).unwrap();
        assert!(!config.sources.is_empty());
        assert!(!config.sinks.is_empty());
        assert!(!config.sanitizers.is_empty());
    }

    #[test]
    fn load_python_config() {
        let config = load_taint_config(Language::Python).unwrap();
        assert!(!config.sources.is_empty());
        assert!(!config.sinks.is_empty());
        assert!(!config.sanitizers.is_empty());
    }

    #[test]
    fn load_csharp_config() {
        let config = load_taint_config(Language::CSharp).unwrap();
        assert!(!config.sources.is_empty());
        assert!(!config.sinks.is_empty());
        assert!(!config.sanitizers.is_empty());
    }

    #[test]
    fn load_go_config() {
        let config = load_taint_config(Language::Go).unwrap();
        assert!(!config.sources.is_empty());
        assert!(!config.sinks.is_empty());
        assert!(!config.sanitizers.is_empty());
    }

    #[test]
    fn javascript_uses_typescript_config() {
        let ts = load_taint_config(Language::TypeScript).unwrap();
        let js = load_taint_config(Language::JavaScript).unwrap();
        assert_eq!(ts.sources.len(), js.sources.len());
    }

    #[test]
    fn all_sinks_have_vulnerability_and_cwe() {
        for lang in [
            Language::TypeScript,
            Language::Java,
            Language::Python,
            Language::CSharp,
            Language::Go,
        ] {
            let config = load_taint_config(lang).unwrap();
            for sink in &config.sinks {
                assert!(
                    !sink.vulnerability.is_empty(),
                    "{lang}: sink '{}' 缺少 vulnerability",
                    sink.function
                );
                assert!(
                    !sink.cwe.is_empty(),
                    "{lang}: sink '{}' 缺少 cwe",
                    sink.function
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // 自訂 Taint Config 測試
    // -------------------------------------------------------------------

    #[test]
    fn no_custom_config_returns_none() {
        let dir = std::env::temp_dir().join("atlas-test-no-custom");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("atlas-taint.yaml"));
        let _ = std::fs::remove_file(dir.join("atlas-taint.yml"));

        let result = load_custom_taint_config(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn custom_sources_appended_to_builtin() {
        let builtin = TaintConfig {
            sources: vec![TaintSource {
                pattern: "req.body".to_string(),
                label: "HTTP body".to_string(),
            }],
            sinks: vec![],
            sanitizers: vec![],
        };
        let custom = CustomTaintConfig {
            sources: vec![TaintSource {
                pattern: "custom_input()".to_string(),
                label: "Custom source".to_string(),
            }],
            sinks: vec![TaintSink {
                function: "custom_exec".to_string(),
                tainted_args: vec![0],
                vulnerability: "command-injection".to_string(),
                cwe: "CWE-78".to_string(),
            }],
            sanitizers: vec![TaintSanitizer {
                function: "custom_sanitize".to_string(),
            }],
            max_depth: None,
        };

        let (merged, depth) = merge_taint_config(builtin, custom);
        assert_eq!(merged.sources.len(), 2);
        assert_eq!(merged.sources[0].pattern, "req.body");
        assert_eq!(merged.sources[1].pattern, "custom_input()");
        assert_eq!(merged.sinks.len(), 1);
        assert_eq!(merged.sanitizers.len(), 1);
        assert!(depth.is_none());
    }

    #[test]
    fn custom_max_depth_overrides_default() {
        let builtin = TaintConfig {
            sources: vec![],
            sinks: vec![],
            sanitizers: vec![],
        };
        let custom = CustomTaintConfig {
            sources: vec![],
            sinks: vec![],
            sanitizers: vec![],
            max_depth: Some(3),
        };

        let (_merged, depth) = merge_taint_config(builtin, custom);
        assert_eq!(depth, Some(3));
    }

    #[test]
    fn invalid_yaml_returns_descriptive_error() {
        let dir = std::env::temp_dir().join("atlas-test-invalid-yaml");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("atlas-taint.yaml"), "{{invalid yaml::: [[[")
            .expect("write test file");

        let result = load_custom_taint_config(&dir);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("invalid atlas-taint.yaml"),
            "Error should be descriptive, got: {err}"
        );

        let _ = std::fs::remove_file(dir.join("atlas-taint.yaml"));
    }

    #[test]
    fn load_custom_config_from_yaml_file() {
        let dir = std::env::temp_dir().join("atlas-test-custom-config");
        let _ = std::fs::create_dir_all(&dir);
        let yaml = r#"
sources:
  - pattern: "env.get"
    label: "Environment variable"
sinks:
  - function: "subprocess.run"
    tainted_args: [0]
    vulnerability: "command-injection"
    cwe: "CWE-78"
sanitizers:
  - function: "shlex.quote"
max_depth: 8
"#;
        std::fs::write(dir.join("atlas-taint.yaml"), yaml).expect("write test yaml");

        let config = load_custom_taint_config(&dir).unwrap().unwrap();
        assert_eq!(config.sources.len(), 1);
        assert_eq!(config.sources[0].pattern, "env.get");
        assert_eq!(config.sinks.len(), 1);
        assert_eq!(config.sinks[0].function, "subprocess.run");
        assert_eq!(config.sanitizers.len(), 1);
        assert_eq!(config.max_depth, Some(8));

        let _ = std::fs::remove_file(dir.join("atlas-taint.yaml"));
    }
}
