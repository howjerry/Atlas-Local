//! SPDX v2.3 JSON 序列化器。

use serde_json::{json, Value};

use crate::purl::dependency_to_purl;
use crate::Dependency;

/// 產生 SPDX v2.3 JSON SBOM 字串。
///
/// - `deps`: 已去重的依賴列表
/// - `project_name`: 根專案名稱
pub fn format_spdx(deps: &[Dependency], project_name: &str) -> String {
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let doc_namespace = format!(
        "https://atlas.local/spdx/{}/{}",
        project_name,
        simple_uuid()
    );

    // 根專案 package
    let root_package = json!({
        "SPDXID": "SPDXRef-RootPackage",
        "name": project_name,
        "versionInfo": "",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
    });

    // 依賴 packages
    let dep_packages: Vec<Value> = deps
        .iter()
        .enumerate()
        .map(|(i, dep)| {
            json!({
                "SPDXID": format!("SPDXRef-Package-{i}"),
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": dependency_to_purl(dep),
                }],
            })
        })
        .collect();

    // 所有 packages = root + dependencies
    let mut packages = vec![root_package];
    packages.extend(dep_packages);

    // relationships
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "SPDXRef-RootPackage",
        "relationshipType": "DESCRIBES",
    })];

    for i in 0..deps.len() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-RootPackage",
            "relatedSpdxElement": format!("SPDXRef-Package-{i}"),
            "relationshipType": "DEPENDS_ON",
        }));
    }

    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{project_name}-sbom"),
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: atlas-local"],
        },
        "packages": packages,
        "relationships": relationships,
    });

    serde_json::to_string_pretty(&doc).expect("SPDX JSON serialization should not fail")
}

/// 簡易 UUID 產生（不依賴外部 crate）。
fn simple_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (seed & 0xFFFF_FFFF) as u32,
        ((seed >> 32) & 0xFFFF) as u16,
        ((seed >> 48) & 0x0FFF) as u16,
        (((seed >> 60) & 0x3F) | 0x80) as u16 | 0x8000,
        (seed >> 64) as u64 & 0xFFFF_FFFF_FFFF,
    )
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
    fn spdx_basic_structure() {
        let deps = vec![
            test_dep("lodash", "4.17.21", Ecosystem::Npm),
            test_dep("express", "4.18.2", Ecosystem::Npm),
        ];

        let output = format_spdx(&deps, "my-project");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        assert_eq!(parsed["dataLicense"], "CC0-1.0");
        assert_eq!(parsed["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(parsed["documentNamespace"]
            .as_str()
            .unwrap()
            .starts_with("https://atlas.local/spdx/my-project/"));
    }

    #[test]
    fn spdx_creation_info() {
        let output = format_spdx(&[], "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let info = &parsed["creationInfo"];
        assert!(info["created"].is_string());
        assert_eq!(info["creators"][0], "Tool: atlas-local");
    }

    #[test]
    fn spdx_packages_count() {
        let deps = vec![
            test_dep("a", "1.0.0", Ecosystem::Npm),
            test_dep("b", "2.0.0", Ecosystem::Cargo),
        ];
        let output = format_spdx(&deps, "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        // root + 2 deps = 3 packages
        assert_eq!(parsed["packages"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn spdx_root_package() {
        let output = format_spdx(&[], "my-app");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let root = &parsed["packages"][0];
        assert_eq!(root["SPDXID"], "SPDXRef-RootPackage");
        assert_eq!(root["name"], "my-app");
        assert_eq!(root["downloadLocation"], "NOASSERTION");
    }

    #[test]
    fn spdx_dep_package_has_purl() {
        let deps = vec![test_dep("requests", "2.31.0", Ecosystem::PyPI)];
        let output = format_spdx(&deps, "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let pkg = &parsed["packages"][1]; // index 0 is root
        assert_eq!(pkg["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(pkg["name"], "requests");
        assert_eq!(pkg["versionInfo"], "2.31.0");

        let ext_ref = &pkg["externalRefs"][0];
        assert_eq!(ext_ref["referenceType"], "purl");
        assert_eq!(ext_ref["referenceLocator"], "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn spdx_relationships() {
        let deps = vec![
            test_dep("a", "1.0.0", Ecosystem::Npm),
            test_dep("b", "2.0.0", Ecosystem::Npm),
        ];
        let output = format_spdx(&deps, "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let rels = parsed["relationships"].as_array().unwrap();
        // 1 DESCRIBES + 2 DEPENDS_ON = 3
        assert_eq!(rels.len(), 3);

        // 第一個是 DESCRIBES
        assert_eq!(rels[0]["relationshipType"], "DESCRIBES");
        assert_eq!(rels[0]["spdxElementId"], "SPDXRef-DOCUMENT");

        // 其餘是 DEPENDS_ON
        assert_eq!(rels[1]["relationshipType"], "DEPENDS_ON");
        assert_eq!(rels[2]["relationshipType"], "DEPENDS_ON");
    }

    #[test]
    fn spdx_noassertion_download() {
        let deps = vec![test_dep("pkg", "1.0.0", Ecosystem::NuGet)];
        let output = format_spdx(&deps, "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["packages"][1]["downloadLocation"], "NOASSERTION");
    }

    #[test]
    fn spdx_empty_deps() {
        let output = format_spdx(&[], "empty");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        // 只有 root package
        assert_eq!(parsed["packages"].as_array().unwrap().len(), 1);
        // 只有 DESCRIBES
        assert_eq!(parsed["relationships"].as_array().unwrap().len(), 1);
    }
}
