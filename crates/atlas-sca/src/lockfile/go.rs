//! Go `go.sum` 解析器。

use std::collections::HashSet;
use std::path::Path;

use crate::{Dependency, Ecosystem, ScaError};
use super::LockfileParser;

pub struct GoParser;

impl LockfileParser for GoParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let path_str = path.display().to_string();
        let mut seen = HashSet::new();
        let mut deps = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // go.sum 格式: module version hash
            // 例如: golang.org/x/text v0.14.0 h1:ScX5w1eTa3Q...
            //       golang.org/x/text v0.14.0/go.mod h1:3Q7...
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let module = parts[0];
            let version_raw = parts[1];

            // 去除 /go.mod 後綴
            let version_clean = version_raw.split("/go.mod").next().unwrap_or(version_raw);

            // 去除 v prefix
            let version = version_clean.strip_prefix('v').unwrap_or(version_clean);

            // 去重：同一 module+version 只保留一筆
            let key = format!("{}@{}", module, version);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);

            deps.push(Dependency {
                name: module.to_string(),
                version: version.to_string(),
                ecosystem: Ecosystem::Go,
                lockfile_path: path_str.clone(),
                line: (line_num + 1) as u32,
            });
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_sum() {
        let content = r#"golang.org/x/text v0.14.0 h1:ScX5w1eTa3Q...
golang.org/x/text v0.14.0/go.mod h1:3Q7...
golang.org/x/net v0.19.0 h1:zTwL6...
golang.org/x/net v0.19.0/go.mod h1:CfAk..."#;

        let parser = GoParser;
        let deps = parser.parse(content, Path::new("go.sum")).unwrap();

        // 去重後應只有 2 個
        assert_eq!(deps.len(), 2);

        let text = deps.iter().find(|d| d.name == "golang.org/x/text").unwrap();
        assert_eq!(text.version, "0.14.0"); // v prefix 已移除
        assert_eq!(text.ecosystem, Ecosystem::Go);

        let net = deps.iter().find(|d| d.name == "golang.org/x/net").unwrap();
        assert_eq!(net.version, "0.19.0");
    }

    #[test]
    fn deduplicates_entries() {
        let content = "example.com/mod v1.2.3 h1:abc\nexample.com/mod v1.2.3/go.mod h1:def\n";
        let parser = GoParser;
        let deps = parser.parse(content, Path::new("go.sum")).unwrap();
        assert_eq!(deps.len(), 1);
    }
}
