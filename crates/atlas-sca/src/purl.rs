//! Package URL (purl) 產生器 — 依 purl 規範為各生態系依賴產生標準化識別碼。

use crate::{Dependency, Ecosystem};

/// 將依賴轉換為 Package URL 字串。
///
/// 格式：`pkg:{type}/{namespace}/{name}@{version}`
///
/// 各生態系映射：
/// - npm → `pkg:npm/{name}@{version}`（scoped: `pkg:npm/%40scope/name@version`）
/// - Cargo → `pkg:cargo/{name}@{version}`
/// - Maven → `pkg:maven/{groupId}/{artifactId}@{version}`
/// - Go → `pkg:golang/{module_path}@{version}`
/// - PyPI → `pkg:pypi/{name}@{version}`（名稱小寫化）
/// - NuGet → `pkg:nuget/{name}@{version}`
pub fn dependency_to_purl(dep: &Dependency) -> String {
    match dep.ecosystem {
        Ecosystem::Npm => {
            // npm scoped packages: @scope/name → %40scope/name
            let encoded = dep.name.replace('@', "%40");
            format!("pkg:npm/{}@{}", encoded, dep.version)
        }
        Ecosystem::Cargo => {
            format!("pkg:cargo/{}@{}", dep.name, dep.version)
        }
        Ecosystem::Maven => {
            // Maven name 格式可能是 "groupId:artifactId"
            if let Some((group, artifact)) = dep.name.split_once(':') {
                format!("pkg:maven/{}/{}@{}", group, artifact, dep.version)
            } else {
                format!("pkg:maven/{}@{}", dep.name, dep.version)
            }
        }
        Ecosystem::Go => {
            format!("pkg:golang/{}@{}", dep.name, dep.version)
        }
        Ecosystem::PyPI => {
            // PyPI 名稱小寫化
            format!("pkg:pypi/{}@{}", dep.name.to_lowercase(), dep.version)
        }
        Ecosystem::NuGet => {
            format!("pkg:nuget/{}@{}", dep.name, dep.version)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: &str, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            lockfile_path: String::new(),
            line: 0,
        }
    }

    // -- npm --

    #[test]
    fn npm_simple() {
        assert_eq!(
            dependency_to_purl(&dep("lodash", "4.17.21", Ecosystem::Npm)),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn npm_scoped() {
        assert_eq!(
            dependency_to_purl(&dep("@types/node", "20.0.0", Ecosystem::Npm)),
            "pkg:npm/%40types/node@20.0.0"
        );
    }

    // -- Cargo --

    #[test]
    fn cargo_simple() {
        assert_eq!(
            dependency_to_purl(&dep("serde", "1.0.0", Ecosystem::Cargo)),
            "pkg:cargo/serde@1.0.0"
        );
    }

    #[test]
    fn cargo_hyphenated() {
        assert_eq!(
            dependency_to_purl(&dep("serde_json", "1.0.100", Ecosystem::Cargo)),
            "pkg:cargo/serde_json@1.0.100"
        );
    }

    // -- Maven --

    #[test]
    fn maven_with_group() {
        assert_eq!(
            dependency_to_purl(&dep("org.apache:commons-lang3", "3.12.0", Ecosystem::Maven)),
            "pkg:maven/org.apache/commons-lang3@3.12.0"
        );
    }

    #[test]
    fn maven_without_group() {
        assert_eq!(
            dependency_to_purl(&dep("junit", "4.13.2", Ecosystem::Maven)),
            "pkg:maven/junit@4.13.2"
        );
    }

    // -- Go --

    #[test]
    fn go_long_path() {
        assert_eq!(
            dependency_to_purl(&dep("github.com/gin-gonic/gin", "v1.9.0", Ecosystem::Go)),
            "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
        );
    }

    #[test]
    fn go_stdlib() {
        assert_eq!(
            dependency_to_purl(&dep("golang.org/x/text", "v0.14.0", Ecosystem::Go)),
            "pkg:golang/golang.org/x/text@v0.14.0"
        );
    }

    // -- PyPI --

    #[test]
    fn pypi_lowercase() {
        assert_eq!(
            dependency_to_purl(&dep("requests", "2.31.0", Ecosystem::PyPI)),
            "pkg:pypi/requests@2.31.0"
        );
    }

    #[test]
    fn pypi_mixed_case() {
        // PyPI 名稱應小寫化
        assert_eq!(
            dependency_to_purl(&dep("Flask", "3.0.0", Ecosystem::PyPI)),
            "pkg:pypi/flask@3.0.0"
        );
    }

    // -- NuGet --

    #[test]
    fn nuget_simple() {
        assert_eq!(
            dependency_to_purl(&dep("Newtonsoft.Json", "13.0.3", Ecosystem::NuGet)),
            "pkg:nuget/Newtonsoft.Json@13.0.3"
        );
    }

    #[test]
    fn nuget_dotted() {
        assert_eq!(
            dependency_to_purl(&dep("Microsoft.Extensions.Logging", "8.0.0", Ecosystem::NuGet)),
            "pkg:nuget/Microsoft.Extensions.Logging@8.0.0"
        );
    }
}
