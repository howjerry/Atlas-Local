//! Python `requirements.txt` 和 `Pipfile.lock` 解析器。

use std::path::Path;

use crate::{Dependency, Ecosystem, ScaError};
use super::LockfileParser;

// ---------------------------------------------------------------------------
// requirements.txt 解析器
// ---------------------------------------------------------------------------

pub struct RequirementsParser;

impl LockfileParser for RequirementsParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let path_str = path.display().to_string();
        let mut deps = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // 跳過空行、註解、選項行
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }

            // 嘗試解析 name==version（pinned）
            if let Some((name, version)) = line.split_once("==") {
                let name = name.trim();
                let version = version.trim().split(';').next().unwrap_or("").trim();
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name: name.to_lowercase(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::PyPI,
                        lockfile_path: path_str.clone(),
                        line: (line_num + 1) as u32,
                    });
                    continue;
                }
            }

            // 嘗試解析 name>=version（range，取下界）
            if let Some((name, version)) = line.split_once(">=") {
                let name = name.trim();
                let version = version.trim().split(',').next().unwrap_or("").trim();
                let version = version.split(';').next().unwrap_or("").trim();
                if !name.is_empty() && !version.is_empty() {
                    deps.push(Dependency {
                        name: name.to_lowercase(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::PyPI,
                        lockfile_path: path_str.clone(),
                        line: (line_num + 1) as u32,
                    });
                }
            }
        }

        Ok(deps)
    }
}

// ---------------------------------------------------------------------------
// Pipfile.lock 解析器
// ---------------------------------------------------------------------------

pub struct PipfileParser;

impl LockfileParser for PipfileParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let path_str = path.display().to_string();
        let parsed: serde_json::Value =
            serde_json::from_str(content).map_err(|e| ScaError::LockfileParse {
                path: path_str.clone(),
                reason: e.to_string(),
            })?;

        let mut deps = Vec::new();

        // 從 default 和 develop sections 提取
        for section in &["default", "develop"] {
            if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
                for (name, info) in obj {
                    if let Some(version_str) = info.get("version").and_then(|v| v.as_str()) {
                        // 版本格式: "==1.2.3" → "1.2.3"
                        let version = version_str.strip_prefix("==").unwrap_or(version_str);
                        deps.push(Dependency {
                            name: name.to_lowercase(),
                            version: version.to_string(),
                            ecosystem: Ecosystem::PyPI,
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
    fn parse_requirements_pinned() {
        let content = "requests==2.31.0\nflask==3.0.0\n";
        let parser = RequirementsParser;
        let deps = parser.parse(content, Path::new("requirements.txt")).unwrap();

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.31.0");
        assert_eq!(deps[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(deps[0].line, 1);

        assert_eq!(deps[1].name, "flask");
        assert_eq!(deps[1].version, "3.0.0");
        assert_eq!(deps[1].line, 2);
    }

    #[test]
    fn parse_requirements_range() {
        let content = "requests>=2.0,<3.0\n";
        let parser = RequirementsParser;
        let deps = parser.parse(content, Path::new("requirements.txt")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.0"); // 取下界
    }

    #[test]
    fn parse_requirements_skips_comments() {
        let content = "# comment\nrequests==2.31.0\n  # another comment\n";
        let parser = RequirementsParser;
        let deps = parser.parse(content, Path::new("requirements.txt")).unwrap();
        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn parse_pipfile_lock() {
        let content = r#"{
            "_meta": {},
            "default": {
                "requests": { "version": "==2.31.0" },
                "flask": { "version": "==3.0.0" }
            },
            "develop": {
                "pytest": { "version": "==7.4.3" }
            }
        }"#;

        let parser = PipfileParser;
        let deps = parser.parse(content, Path::new("Pipfile.lock")).unwrap();
        assert_eq!(deps.len(), 3);

        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"pytest"));

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0"); // == prefix 已移除
    }

    #[test]
    fn malformed_pipfile_returns_error() {
        let parser = PipfileParser;
        let result = parser.parse("not json", Path::new("Pipfile.lock"));
        assert!(result.is_err());
    }
}
