//! SBOM 產生器 — 核心編排模組。
//!
//! 複用 SCA 引擎的鎖檔解析結果，輸出 CycloneDX v1.5 或 SPDX v2.3 JSON 格式。

use std::collections::HashSet;
use std::path::Path;

use crate::cyclonedx::format_cyclonedx;
use crate::database::VulnDatabase;
use crate::lockfile::discover_lockfiles;
use crate::matcher::version_matches;
use crate::spdx::format_spdx;
use crate::{Advisory, Dependency, ScaError};

// ---------------------------------------------------------------------------
// SbomFormat
// ---------------------------------------------------------------------------

/// SBOM 輸出格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    /// CycloneDX v1.5 JSON
    CycloneDxJson,
    /// SPDX v2.3 JSON
    SpdxJson,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CycloneDxJson => f.write_str("cyclonedx-json"),
            Self::SpdxJson => f.write_str("spdx-json"),
        }
    }
}

impl std::str::FromStr for SbomFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cyclonedx-json" | "cyclonedx" => Ok(Self::CycloneDxJson),
            "spdx-json" | "spdx" => Ok(Self::SpdxJson),
            other => Err(format!("unknown SBOM format: '{other}' (expected 'cyclonedx-json' or 'spdx-json')")),
        }
    }
}

// ---------------------------------------------------------------------------
// generate_sbom — 公開 API
// ---------------------------------------------------------------------------

/// 產生 SBOM JSON 字串。
///
/// 1. 偵測 `scan_dir` 中的鎖檔
/// 2. 解析所有依賴
/// 3. 依 (name, version, ecosystem) 去重
/// 4. 若提供漏洞資料庫，匹配已知漏洞
/// 5. 依指定格式輸出 JSON
///
/// # Errors
///
/// 鎖檔解析失敗會 log warning 並跳過。僅在 I/O 或資料庫錯誤時回傳 `Err`。
pub fn generate_sbom(
    scan_dir: &Path,
    format: SbomFormat,
    db: Option<&VulnDatabase>,
) -> Result<String, ScaError> {
    // 推導專案名稱（目錄名稱）
    let project_name = scan_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown-project");

    // 1. 偵測鎖檔
    let lockfiles = discover_lockfiles(scan_dir);
    if lockfiles.is_empty() {
        tracing::warn!("No lockfiles found in '{}'", scan_dir.display());
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

    // 3. 去重：相同 (name, version, ecosystem) 只保留一次
    let deps = dedup_dependencies(all_deps);

    // 4. 漏洞匹配（僅 CycloneDX 需要嵌入漏洞資訊）
    let vulns = match (format, db) {
        (SbomFormat::CycloneDxJson, Some(vuln_db)) => {
            match_vulnerabilities(&deps, vuln_db)?
        }
        _ => Vec::new(),
    };

    // 5. 格式化輸出
    let output = match format {
        SbomFormat::CycloneDxJson => format_cyclonedx(&deps, &vulns, project_name),
        SbomFormat::SpdxJson => format_spdx(&deps, project_name),
    };

    Ok(output)
}

// ---------------------------------------------------------------------------
// 依賴去重
// ---------------------------------------------------------------------------

/// 依 (name, version, ecosystem) 去重，保留首次出現的依賴。
fn dedup_dependencies(deps: Vec<Dependency>) -> Vec<Dependency> {
    let mut seen = HashSet::new();
    deps.into_iter()
        .filter(|dep| {
            seen.insert((dep.name.clone(), dep.version.clone(), dep.ecosystem))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 漏洞匹配
// ---------------------------------------------------------------------------

/// 從漏洞資料庫比對已知漏洞，回傳匹配的 (Dependency, Advisory) 對。
fn match_vulnerabilities(
    deps: &[Dependency],
    db: &VulnDatabase,
) -> Result<Vec<(Dependency, Advisory)>, ScaError> {
    let advisories_map = db
        .query_batch(deps)
        .map_err(|e| ScaError::Database(e.to_string()))?;

    let mut vulns = Vec::new();
    for dep in deps {
        let key = (dep.ecosystem, dep.name.clone());
        if let Some(advisories) = advisories_map.get(&key) {
            for advisory in advisories {
                if version_matches(&dep.version, &advisory.affected_range, dep.ecosystem) {
                    vulns.push((dep.clone(), advisory.clone()));
                }
            }
        }
    }

    Ok(vulns)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ecosystem;

    fn test_dep(name: &str, version: &str, eco: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: eco,
            lockfile_path: String::new(),
            line: 0,
        }
    }

    #[test]
    fn sbom_format_display() {
        assert_eq!(SbomFormat::CycloneDxJson.to_string(), "cyclonedx-json");
        assert_eq!(SbomFormat::SpdxJson.to_string(), "spdx-json");
    }

    #[test]
    fn sbom_format_from_str() {
        assert_eq!(
            "cyclonedx-json".parse::<SbomFormat>().unwrap(),
            SbomFormat::CycloneDxJson
        );
        assert_eq!(
            "spdx-json".parse::<SbomFormat>().unwrap(),
            SbomFormat::SpdxJson
        );
        assert_eq!(
            "cyclonedx".parse::<SbomFormat>().unwrap(),
            SbomFormat::CycloneDxJson
        );
        assert_eq!(
            "spdx".parse::<SbomFormat>().unwrap(),
            SbomFormat::SpdxJson
        );
        assert!("unknown".parse::<SbomFormat>().is_err());
    }

    #[test]
    fn dedup_removes_duplicates() {
        let deps = vec![
            test_dep("lodash", "4.17.21", Ecosystem::Npm),
            test_dep("lodash", "4.17.21", Ecosystem::Npm),
            test_dep("lodash", "4.17.20", Ecosystem::Npm), // 不同版本，保留
            test_dep("lodash", "4.17.21", Ecosystem::Cargo), // 不同生態系，保留
        ];
        let result = dedup_dependencies(deps);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn dedup_preserves_first_occurrence() {
        let mut dep1 = test_dep("a", "1.0.0", Ecosystem::Npm);
        dep1.lockfile_path = "first.json".to_string();
        let mut dep2 = test_dep("a", "1.0.0", Ecosystem::Npm);
        dep2.lockfile_path = "second.json".to_string();

        let result = dedup_dependencies(vec![dep1, dep2]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].lockfile_path, "first.json");
    }

    #[test]
    fn generate_sbom_empty_dir_cyclonedx() {
        let dir = tempfile::tempdir().unwrap();
        let output = generate_sbom(dir.path(), SbomFormat::CycloneDxJson, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert_eq!(parsed["components"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn generate_sbom_empty_dir_spdx() {
        let dir = tempfile::tempdir().unwrap();
        let output = generate_sbom(dir.path(), SbomFormat::SpdxJson, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        // 空依賴：只有 root package
        assert_eq!(parsed["packages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn generate_sbom_with_lockfile_cyclonedx() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": { "version": "4.17.21" },
                    "node_modules/express": { "version": "4.18.2" }
                }
            }"#,
        )
        .unwrap();

        let output = generate_sbom(dir.path(), SbomFormat::CycloneDxJson, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["components"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn generate_sbom_with_lockfile_spdx() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": { "version": "4.17.21" }
                }
            }"#,
        )
        .unwrap();

        let output = generate_sbom(dir.path(), SbomFormat::SpdxJson, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        // root + 1 dep = 2 packages
        assert_eq!(parsed["packages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn generate_sbom_with_vulns() {
        let dir = tempfile::tempdir().unwrap();

        // 建立漏洞資料庫
        let db_path = dir.path().join("vuln.db");
        let db = crate::database::VulnDatabase::create(&db_path).unwrap();
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

        // 建立含漏洞版本的鎖檔
        let project_dir = dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(
            project_dir.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": { "version": "4.17.20" }
                }
            }"#,
        )
        .unwrap();

        let output = generate_sbom(&project_dir, SbomFormat::CycloneDxJson, Some(&db)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let vulns = parsed["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "CVE-2021-23337");
    }

    #[test]
    fn generate_sbom_no_vulns_without_db() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": { "version": "4.17.20" }
                }
            }"#,
        )
        .unwrap();

        let output = generate_sbom(dir.path(), SbomFormat::CycloneDxJson, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        // 無漏洞資料庫 → 不含 vulnerabilities 欄位
        assert!(parsed.get("vulnerabilities").is_none());
    }

    #[test]
    fn dedup_different_ecosystems_kept() {
        let deps = vec![
            test_dep("lodash", "4.17.21", Ecosystem::Npm),
            test_dep("lodash", "4.17.21", Ecosystem::Cargo),
        ];
        let result = dedup_dependencies(deps);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn performance_500_deps_sbom() {
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();

        // 建立含 500 個依賴的 package-lock.json
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
        std::fs::write(dir.path().join("package-lock.json"), &packages).unwrap();

        let start = Instant::now();
        let output = generate_sbom(dir.path(), SbomFormat::CycloneDxJson, None).unwrap();
        let elapsed = start.elapsed();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["components"].as_array().unwrap().len(), 500);
        assert!(
            elapsed.as_secs() < 2,
            "500 依賴 SBOM 產生應在 2 秒內完成，實際耗時 {elapsed:?}"
        );
    }
}
