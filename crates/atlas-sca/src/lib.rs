//! Atlas SCA — 軟體組成分析（Software Composition Analysis）。
//!
//! 提供鎖檔解析、離線漏洞資料庫查詢、版本匹配引擎，
//! 以及 SCA finding 產生功能。

pub mod database;
pub mod lockfile;
pub mod matcher;
pub mod update;

use std::path::Path;

use atlas_analysis::finding::{Finding, FindingBuilder, LineRange};
use atlas_core::{AnalysisLevel, Category, Confidence, Severity};
use serde::{Deserialize, Serialize};

use database::VulnDatabase;
use lockfile::discover_lockfiles;
use matcher::version_matches;

// ---------------------------------------------------------------------------
// Ecosystem
// ---------------------------------------------------------------------------

/// 套件管理生態系。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Maven,
    Go,
    PyPI,
    NuGet,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Maven => "maven",
            Self::Go => "go",
            Self::PyPI => "pypi",
            Self::NuGet => "nuget",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// Dependency
// ---------------------------------------------------------------------------

/// 從鎖檔解析出的第三方依賴。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// 套件名稱。
    pub name: String,
    /// 安裝的版本。
    pub version: String,
    /// 所屬生態系。
    pub ecosystem: Ecosystem,
    /// 鎖檔路徑。
    pub lockfile_path: String,
    /// 依賴在鎖檔中的行號（1-indexed，0 表示未知）。
    pub line: u32,
}

// ---------------------------------------------------------------------------
// Advisory
// ---------------------------------------------------------------------------

/// 漏洞資料庫中的 advisory 記錄。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    /// CVE 識別碼（如 "CVE-2021-23337"）。
    pub id: String,
    /// 所屬生態系。
    pub ecosystem: Ecosystem,
    /// 受影響的套件名稱。
    pub package_name: String,
    /// 受影響的版本範圍（如 "< 4.17.21"）。
    pub affected_range: String,
    /// 修復版本（可能為空）。
    pub fixed_version: Option<String>,
    /// CVSS v3 分數（0.0-10.0，可能為空）。
    pub cvss_score: Option<f64>,
    /// 嚴重度。
    pub severity: String,
    /// 說明。
    pub description: String,
    /// Advisory URL。
    pub advisory_url: Option<String>,
}

// ---------------------------------------------------------------------------
// ScaError
// ---------------------------------------------------------------------------

/// SCA 模組的錯誤類型。
#[derive(Debug, thiserror::Error)]
pub enum ScaError {
    #[error("鎖檔解析失敗: {path}: {reason}")]
    LockfileParse { path: String, reason: String },

    #[error("漏洞資料庫錯誤: {0}")]
    Database(String),

    #[error("簽章驗證失敗: {0}")]
    SignatureInvalid(String),

    #[error("IO 錯誤: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// CVSS → Severity 映射
// ---------------------------------------------------------------------------

/// 將 CVSS v3 分數映射為 Atlas Severity。
///
/// - Critical: 9.0–10.0
/// - High: 7.0–8.9
/// - Medium: 4.0–6.9
/// - Low: 0.1–3.9
/// - None/null → Medium（預設）
#[must_use]
pub fn cvss_to_severity(cvss: Option<f64>) -> Severity {
    match cvss {
        Some(score) if score >= 9.0 => Severity::Critical,
        Some(score) if score >= 7.0 => Severity::High,
        Some(score) if score >= 4.0 => Severity::Medium,
        Some(score) if score >= 0.1 => Severity::Low,
        Some(_) => Severity::Info,
        None => Severity::Medium, // 無 CVSS 預設為 Medium
    }
}

// ---------------------------------------------------------------------------
// SCA Finding 建構
// ---------------------------------------------------------------------------

/// 從匹配的 advisory 建構 SCA Finding。
pub fn create_sca_finding(
    dep: &Dependency,
    advisory: &Advisory,
) -> Result<Finding, atlas_analysis::finding::AnalysisError> {
    let severity = cvss_to_severity(advisory.cvss_score);
    let rule_id = format!("atlas/sca/{}/{}", dep.ecosystem, advisory.id.to_lowercase());

    let line = if dep.line > 0 { dep.line } else { 1 };

    FindingBuilder::new()
        .rule_id(&rule_id)
        .severity(severity)
        .category(Category::Sca)
        .file_path(&dep.lockfile_path)
        .line_range(LineRange::new(line, 0, line, 0)?)
        .snippet(format!("{}@{}", dep.name, dep.version))
        .description(format!(
            "{} {} 存在已知漏洞 {} (CVSS {})。{}",
            dep.name,
            dep.version,
            advisory.id,
            advisory
                .cvss_score
                .map_or("N/A".to_string(), |s| format!("{s:.1}")),
            advisory.description,
        ))
        .remediation(if let Some(ref fixed) = advisory.fixed_version {
            format!("升級 {} 至 {} 或更高版本。", dep.name, fixed)
        } else {
            format!("目前無已知修復版本，請評估是否可替換 {}。", dep.name)
        })
        .analysis_level(AnalysisLevel::L1)
        .confidence(Confidence::High)
        .meta("cve_id", serde_json::json!(advisory.id))
        .meta(
            "cvss_score",
            serde_json::json!(advisory.cvss_score.unwrap_or(0.0)),
        )
        .meta("package_name", serde_json::json!(dep.name))
        .meta("ecosystem", serde_json::json!(dep.ecosystem.to_string()))
        .meta("installed_version", serde_json::json!(dep.version))
        .meta("fixed_version", serde_json::json!(advisory.fixed_version))
        .meta("advisory_url", serde_json::json!(advisory.advisory_url))
        .build()
}

// ---------------------------------------------------------------------------
// scan_dependencies — 公開 API
// ---------------------------------------------------------------------------

/// 掃描指定目錄中的鎖檔，比對漏洞資料庫，回傳 SCA findings。
///
/// # Errors
///
/// 資料庫開啟失敗時回傳錯誤。鎖檔解析錯誤會 log warning 並跳過。
pub fn scan_dependencies(
    scan_dir: &Path,
    db: &VulnDatabase,
) -> Result<Vec<Finding>, ScaError> {
    // 1. 偵測鎖檔
    let lockfiles = discover_lockfiles(scan_dir);
    if lockfiles.is_empty() {
        tracing::debug!("No lockfile found; skipping SCA");
        return Ok(Vec::new());
    }

    // 2. 解析所有鎖檔
    let mut all_deps = Vec::new();
    for (path, parser) in &lockfiles {
        match std::fs::read_to_string(path) {
            Ok(content) => match parser.parse(&content, path) {
                Ok(deps) => {
                    tracing::debug!(
                        lockfile = %path.display(),
                        count = deps.len(),
                        "解析鎖檔完成"
                    );
                    all_deps.extend(deps);
                }
                Err(e) => {
                    tracing::warn!(
                        lockfile = %path.display(),
                        error = %e,
                        "鎖檔解析失敗，跳過"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    lockfile = %path.display(),
                    error = %e,
                    "無法讀取鎖檔"
                );
            }
        }
    }

    if all_deps.is_empty() {
        return Ok(Vec::new());
    }

    // 3. 批次查詢漏洞資料庫
    let advisories_map = db
        .query_batch(&all_deps)
        .map_err(|e| ScaError::Database(e.to_string()))?;

    // 4. 版本匹配 + 產生 findings
    let mut findings = Vec::new();
    for dep in &all_deps {
        let key = (dep.ecosystem, dep.name.clone());
        if let Some(advisories) = advisories_map.get(&key) {
            for advisory in advisories {
                if version_matches(&dep.version, &advisory.affected_range, dep.ecosystem) {
                    match create_sca_finding(dep, advisory) {
                        Ok(f) => findings.push(f),
                        Err(e) => {
                            tracing::warn!(
                                package = %dep.name,
                                cve = %advisory.id,
                                error = %e,
                                "無法建構 SCA finding"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_critical() {
        assert_eq!(cvss_to_severity(Some(9.0)), Severity::Critical);
        assert_eq!(cvss_to_severity(Some(10.0)), Severity::Critical);
    }

    #[test]
    fn cvss_high() {
        assert_eq!(cvss_to_severity(Some(7.0)), Severity::High);
        assert_eq!(cvss_to_severity(Some(8.9)), Severity::High);
    }

    #[test]
    fn cvss_medium() {
        assert_eq!(cvss_to_severity(Some(4.0)), Severity::Medium);
        assert_eq!(cvss_to_severity(Some(6.9)), Severity::Medium);
    }

    #[test]
    fn cvss_low() {
        assert_eq!(cvss_to_severity(Some(0.1)), Severity::Low);
        assert_eq!(cvss_to_severity(Some(3.9)), Severity::Low);
    }

    #[test]
    fn cvss_none_defaults_to_medium() {
        assert_eq!(cvss_to_severity(None), Severity::Medium);
    }

    #[test]
    fn e2e_scan_with_known_vulnerable_dependency() {
        // 端對端測試：建立含漏洞依賴的專案目錄，驗證完整管線
        let dir = tempfile::tempdir().unwrap();

        // 1. 建立測試用漏洞資料庫
        let db_path = dir.path().join("vuln.db");
        let db = database::VulnDatabase::create(&db_path).unwrap();
        db.insert_advisory(&Advisory {
            id: "CVE-2021-23337".to_string(),
            ecosystem: Ecosystem::Npm,
            package_name: "lodash".to_string(),
            affected_range: "< 4.17.21".to_string(),
            fixed_version: Some("4.17.21".to_string()),
            cvss_score: Some(7.2),
            severity: "high".to_string(),
            description: "Prototype pollution in lodash".to_string(),
            advisory_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()),
        })
        .unwrap();

        // 2. 建立含已知漏洞依賴的 package-lock.json
        let project_dir = dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(
            project_dir.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": { "version": "4.17.20" },
                    "node_modules/express": { "version": "4.18.2" }
                }
            }"#,
        )
        .unwrap();

        // 3. 執行 SCA 掃描
        let findings = scan_dependencies(&project_dir, &db).unwrap();

        // 4. 驗證結果
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::Sca);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].rule_id.contains("cve-2021-23337"));
        assert_eq!(
            findings[0].metadata.get("package_name").unwrap(),
            &serde_json::json!("lodash")
        );
        assert_eq!(
            findings[0].metadata.get("installed_version").unwrap(),
            &serde_json::json!("4.17.20")
        );
    }

    #[test]
    fn e2e_no_findings_when_not_affected() {
        let dir = tempfile::tempdir().unwrap();

        // 資料庫有 lodash < 4.17.21 的 advisory
        let db_path = dir.path().join("vuln.db");
        let db = database::VulnDatabase::create(&db_path).unwrap();
        db.insert_advisory(&Advisory {
            id: "CVE-2021-23337".to_string(),
            ecosystem: Ecosystem::Npm,
            package_name: "lodash".to_string(),
            affected_range: "< 4.17.21".to_string(),
            fixed_version: Some("4.17.21".to_string()),
            cvss_score: Some(7.2),
            severity: "high".to_string(),
            description: "Prototype pollution".to_string(),
            advisory_url: None,
        })
        .unwrap();

        // 安裝的是已修復版本
        let project_dir = dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(
            project_dir.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": { "version": "4.17.21" }
                }
            }"#,
        )
        .unwrap();

        let findings = scan_dependencies(&project_dir, &db).unwrap();
        assert!(findings.is_empty(), "Fixed version should not trigger findings");
    }

    #[test]
    fn performance_500_dependencies() {
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();

        // 建立含 500 個 advisories 的資料庫
        let db_path = dir.path().join("vuln.db");
        let db = database::VulnDatabase::create(&db_path).unwrap();
        for i in 0..500 {
            db.insert_advisory(&Advisory {
                id: format!("CVE-2024-{i:05}"),
                ecosystem: Ecosystem::Npm,
                package_name: format!("pkg-{i}"),
                affected_range: "< 2.0.0".to_string(),
                fixed_version: Some("2.0.0".to_string()),
                cvss_score: Some(5.0),
                severity: "medium".to_string(),
                description: format!("Vulnerability in pkg-{i}"),
                advisory_url: None,
            })
            .unwrap();
        }

        // 建立含 500 個依賴的 package-lock.json
        let project_dir = dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();

        let mut packages = String::from("{\"lockfileVersion\": 3, \"packages\": {");
        for i in 0..500 {
            if i > 0 {
                packages.push(',');
            }
            packages.push_str(&format!(
                "\"node_modules/pkg-{i}\": {{\"version\": \"1.0.0\"}}"
            ));
        }
        packages.push_str("}}");
        std::fs::write(project_dir.join("package-lock.json"), &packages).unwrap();

        // 計時
        let start = Instant::now();
        let findings = scan_dependencies(&project_dir, &db).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(findings.len(), 500);
        assert!(
            elapsed.as_secs() < 3,
            "500 依賴 SCA 掃描應在 3 秒內完成，實際耗時 {elapsed:?}"
        );
    }

    #[test]
    fn create_finding_has_correct_metadata() {
        let dep = Dependency {
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            ecosystem: Ecosystem::Npm,
            lockfile_path: "package-lock.json".to_string(),
            line: 10,
        };
        let advisory = Advisory {
            id: "CVE-2021-23337".to_string(),
            ecosystem: Ecosystem::Npm,
            package_name: "lodash".to_string(),
            affected_range: "< 4.17.21".to_string(),
            fixed_version: Some("4.17.21".to_string()),
            cvss_score: Some(7.2),
            severity: "high".to_string(),
            description: "Prototype pollution".to_string(),
            advisory_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()),
        };

        let finding = create_sca_finding(&dep, &advisory).unwrap();
        assert_eq!(finding.category, Category::Sca);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.rule_id,
            "atlas/sca/npm/cve-2021-23337"
        );
        assert_eq!(
            finding.metadata.get("cve_id").unwrap(),
            &serde_json::json!("CVE-2021-23337")
        );
        assert_eq!(
            finding.metadata.get("package_name").unwrap(),
            &serde_json::json!("lodash")
        );
        assert_eq!(
            finding.metadata.get("installed_version").unwrap(),
            &serde_json::json!("4.17.20")
        );
    }
}
