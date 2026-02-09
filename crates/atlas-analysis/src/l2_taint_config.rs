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
    };
    serde_yml::from_str(yaml)
        .map_err(|e| format!("failed to parse taint config for {language}: {e}"))
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
}
