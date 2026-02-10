//! NuGet `packages.lock.json` 解析器。

use std::path::Path;

use serde::Deserialize;

use crate::{Dependency, Ecosystem, ScaError};
use super::LockfileParser;

pub struct NugetParser;

/// NuGet packages.lock.json 的頂層結構。
#[derive(Deserialize)]
struct NugetLock {
    /// 按 target framework 分組的依賴。
    #[serde(default)]
    dependencies: std::collections::HashMap<String, std::collections::HashMap<String, NugetPackage>>,
}

#[derive(Deserialize)]
struct NugetPackage {
    #[serde(default)]
    resolved: Option<String>,
}

impl LockfileParser for NugetParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let lock: NugetLock = serde_json::from_str(content).map_err(|e| ScaError::LockfileParse {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        let path_str = path.display().to_string();
        let mut deps = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // 遍歷所有 target frameworks
        for packages in lock.dependencies.values() {
            for (name, pkg) in packages {
                if let Some(ref version) = pkg.resolved {
                    let key = format!("{}@{}", name, version);
                    if seen.insert(key) {
                        deps.push(Dependency {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: Ecosystem::NuGet,
                            lockfile_path: path_str.clone(),
                            line: 0,
                        });
                    }
                }
            }
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nuget_lock() {
        let content = r#"{
            "version": 2,
            "dependencies": {
                "net6.0": {
                    "Newtonsoft.Json": { "resolved": "13.0.3" },
                    "Serilog": { "resolved": "3.1.1" }
                }
            }
        }"#;

        let parser = NugetParser;
        let deps = parser.parse(content, Path::new("packages.lock.json")).unwrap();
        assert_eq!(deps.len(), 2);

        let nj = deps.iter().find(|d| d.name == "Newtonsoft.Json").unwrap();
        assert_eq!(nj.version, "13.0.3");
        assert_eq!(nj.ecosystem, Ecosystem::NuGet);

        let slog = deps.iter().find(|d| d.name == "Serilog").unwrap();
        assert_eq!(slog.version, "3.1.1");
    }

    #[test]
    fn deduplicates_across_frameworks() {
        let content = r#"{
            "version": 2,
            "dependencies": {
                "net6.0": { "Pkg": { "resolved": "1.0.0" } },
                "net7.0": { "Pkg": { "resolved": "1.0.0" } }
            }
        }"#;

        let parser = NugetParser;
        let deps = parser.parse(content, Path::new("packages.lock.json")).unwrap();
        assert_eq!(deps.len(), 1); // 去重
    }

    #[test]
    fn malformed_json_returns_error() {
        let parser = NugetParser;
        let result = parser.parse("not json", Path::new("packages.lock.json"));
        assert!(result.is_err());
    }
}
