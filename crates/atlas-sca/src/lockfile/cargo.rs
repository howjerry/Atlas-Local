//! Rust `Cargo.lock` 解析器。

use std::path::Path;

use serde::Deserialize;

use crate::{Dependency, Ecosystem, ScaError};
use super::LockfileParser;

pub struct CargoParser;

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

impl LockfileParser for CargoParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let lock: CargoLock = toml::from_str(content).map_err(|e| ScaError::LockfileParse {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        let path_str = path.display().to_string();
        let deps = lock
            .package
            .into_iter()
            .map(|pkg| Dependency {
                name: pkg.name,
                version: pkg.version,
                ecosystem: Ecosystem::Cargo,
                lockfile_path: path_str.clone(),
                line: 0,
            })
            .collect();

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_lock() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.193"

[[package]]
name = "serde_json"
version = "1.0.108"
"#;

        let parser = CargoParser;
        let deps = parser.parse(content, Path::new("Cargo.lock")).unwrap();
        assert_eq!(deps.len(), 2);

        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.193");
        assert_eq!(deps[0].ecosystem, Ecosystem::Cargo);

        assert_eq!(deps[1].name, "serde_json");
        assert_eq!(deps[1].version, "1.0.108");
    }

    #[test]
    fn malformed_toml_returns_error() {
        let parser = CargoParser;
        let result = parser.parse("not valid toml {{{}}", Path::new("Cargo.lock"));
        assert!(result.is_err());
    }
}
