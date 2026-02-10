//! npm `package-lock.json` v2/v3 解析器。

use std::path::Path;

use serde::Deserialize;

use crate::{Dependency, Ecosystem, ScaError};
use super::LockfileParser;

pub struct NpmParser;

/// npm lockfile v2/v3 的 `packages` 欄位結構。
#[derive(Deserialize)]
struct PackageLock {
    #[serde(default)]
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u32>,

    /// v2/v3: 扁平化的 packages map（key = node_modules/... path）。
    #[serde(default)]
    packages: std::collections::HashMap<String, PackageEntry>,
}

#[derive(Deserialize)]
struct PackageEntry {
    #[serde(default)]
    version: Option<String>,
}

impl LockfileParser for NpmParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let lock: PackageLock = serde_json::from_str(content).map_err(|e| ScaError::LockfileParse {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        let path_str = path.display().to_string();
        let mut deps = Vec::new();

        // v2/v3 使用 packages map
        for (key, entry) in &lock.packages {
            // 跳過根專案（空 key）
            if key.is_empty() {
                continue;
            }

            // 從 key 提取套件名稱（如 "node_modules/lodash" → "lodash"）
            let name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key);

            if let Some(ref version) = entry.version {
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name: name.to_string(),
                        version: version.clone(),
                        ecosystem: Ecosystem::Npm,
                        lockfile_path: path_str.clone(),
                        line: 0, // JSON 格式不追蹤行號
                    });
                }
            }
        }

        // 若 packages 為空但有 lockfileVersion，可能是 v1 格式
        if deps.is_empty() && lock.lockfile_version == Some(1) {
            tracing::debug!(
                path = %path.display(),
                "npm lockfile v1 格式不支援，請升級至 v2/v3"
            );
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v3_lockfile() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "my-app", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" },
                "node_modules/express": { "version": "4.18.2" }
            }
        }"#;

        let parser = NpmParser;
        let deps = parser.parse(content, Path::new("package-lock.json")).unwrap();
        assert_eq!(deps.len(), 2);

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.20");
        assert_eq!(lodash.ecosystem, Ecosystem::Npm);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
    }

    #[test]
    fn parse_v2_lockfile() {
        let content = r#"{
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "app" },
                "node_modules/axios": { "version": "1.6.0" }
            }
        }"#;

        let parser = NpmParser;
        let deps = parser.parse(content, Path::new("package-lock.json")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "axios");
        assert_eq!(deps[0].version, "1.6.0");
    }

    #[test]
    fn parse_scoped_package() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/@types/node": { "version": "20.10.0" }
            }
        }"#;

        let parser = NpmParser;
        let deps = parser.parse(content, Path::new("package-lock.json")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "@types/node");
    }

    #[test]
    fn malformed_json_returns_error() {
        let parser = NpmParser;
        let result = parser.parse("not valid json", Path::new("package-lock.json"));
        assert!(result.is_err());
    }
}
