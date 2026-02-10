//! CycloneDX v1.5 JSON 序列化器。

use serde_json::{json, Value};

use crate::purl::dependency_to_purl;
use crate::{Advisory, Dependency};

/// 產生 CycloneDX v1.5 JSON SBOM 字串。
///
/// - `deps`: 已去重的依賴列表
/// - `vulns`: 依賴對應的漏洞列表（可為空）
/// - `project_name`: 根專案名稱
pub fn format_cyclonedx(
    deps: &[Dependency],
    vulns: &[(Dependency, Advisory)],
    project_name: &str,
) -> String {
    let serial = format!("urn:uuid:{}", uuid_v4());
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // components
    let components: Vec<Value> = deps
        .iter()
        .enumerate()
        .map(|(i, dep)| {
            json!({
                "type": "library",
                "bom-ref": format!("comp-{i}"),
                "name": dep.name,
                "version": dep.version,
                "purl": dependency_to_purl(dep),
            })
        })
        .collect();

    // dependencies（根專案 → 所有 components）
    let comp_refs: Vec<Value> = (0..deps.len())
        .map(|i| json!(format!("comp-{i}")))
        .collect();

    let mut dependencies = vec![json!({
        "ref": "root-component",
        "dependsOn": comp_refs,
    })];
    // 每個 component 也需要 dependency entry（空 dependsOn）
    for i in 0..deps.len() {
        dependencies.push(json!({
            "ref": format!("comp-{i}"),
            "dependsOn": [],
        }));
    }

    let mut bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{ "name": "atlas-local", "version": env!("CARGO_PKG_VERSION") }],
            "component": {
                "type": "application",
                "bom-ref": "root-component",
                "name": project_name,
            }
        },
        "components": components,
        "dependencies": dependencies,
    });

    // 漏洞（僅在有匹配時加入）
    if !vulns.is_empty() {
        let vulnerabilities: Vec<Value> = vulns
            .iter()
            .map(|(dep, advisory)| {
                // 找到 dep 在 components 中的 bom-ref
                let bom_ref = deps
                    .iter()
                    .position(|d| d.name == dep.name && d.version == dep.version && d.ecosystem == dep.ecosystem)
                    .map(|i| format!("comp-{i}"))
                    .unwrap_or_default();

                let mut vuln = json!({
                    "id": advisory.id,
                    "source": { "name": "NVD" },
                    "affects": [{ "ref": bom_ref }],
                });

                if let Some(score) = advisory.cvss_score {
                    vuln["ratings"] = json!([{
                        "score": score,
                        "severity": advisory.severity,
                        "method": "CVSSv3",
                    }]);
                }

                vuln
            })
            .collect();

        bom["vulnerabilities"] = json!(vulnerabilities);
    }

    serde_json::to_string_pretty(&bom).expect("CycloneDX JSON serialization should not fail")
}

/// 產生簡單的 UUID v4（不依賴外部 crate）。
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // 簡易偽 UUID，足以作為 serialNumber
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
    fn cyclonedx_basic_structure() {
        let deps = vec![
            test_dep("lodash", "4.17.21", Ecosystem::Npm),
            test_dep("express", "4.18.2", Ecosystem::Npm),
        ];

        let output = format_cyclonedx(&deps, &[], "my-project");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert!(parsed["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(parsed["components"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn cyclonedx_metadata() {
        let output = format_cyclonedx(&[], &[], "test-app");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let metadata = &parsed["metadata"];
        assert!(metadata["timestamp"].is_string());
        assert_eq!(metadata["tools"][0]["name"], "atlas-local");
        assert_eq!(metadata["component"]["name"], "test-app");
        assert_eq!(metadata["component"]["type"], "application");
    }

    #[test]
    fn cyclonedx_components_have_purl() {
        let deps = vec![test_dep("serde", "1.0.0", Ecosystem::Cargo)];
        let output = format_cyclonedx(&deps, &[], "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let comp = &parsed["components"][0];
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "serde");
        assert_eq!(comp["version"], "1.0.0");
        assert_eq!(comp["purl"], "pkg:cargo/serde@1.0.0");
        assert_eq!(comp["bom-ref"], "comp-0");
    }

    #[test]
    fn cyclonedx_no_vulnerabilities_when_empty() {
        let output = format_cyclonedx(&[], &[], "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert!(parsed.get("vulnerabilities").is_none());
    }

    #[test]
    fn cyclonedx_vulnerabilities_included() {
        let dep = test_dep("lodash", "4.17.20", Ecosystem::Npm);
        let advisory = Advisory {
            id: "CVE-2021-23337".to_string(),
            ecosystem: Ecosystem::Npm,
            package_name: "lodash".to_string(),
            affected_range: "< 4.17.21".to_string(),
            fixed_version: Some("4.17.21".to_string()),
            cvss_score: Some(7.2),
            severity: "high".to_string(),
            description: "Prototype pollution".to_string(),
            advisory_url: None,
        };

        let deps = vec![dep.clone()];
        let vulns = vec![(dep, advisory)];
        let output = format_cyclonedx(&deps, &vulns, "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let vuln_arr = parsed["vulnerabilities"].as_array().unwrap();
        assert_eq!(vuln_arr.len(), 1);
        assert_eq!(vuln_arr[0]["id"], "CVE-2021-23337");
        assert_eq!(vuln_arr[0]["source"]["name"], "NVD");
        assert_eq!(vuln_arr[0]["ratings"][0]["score"], 7.2);
        assert_eq!(vuln_arr[0]["affects"][0]["ref"], "comp-0");
    }

    #[test]
    fn cyclonedx_dependencies_flat() {
        let deps = vec![
            test_dep("a", "1.0.0", Ecosystem::Npm),
            test_dep("b", "2.0.0", Ecosystem::Npm),
        ];
        let output = format_cyclonedx(&deps, &[], "proj");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let dep_arr = parsed["dependencies"].as_array().unwrap();
        // root + 2 components = 3 entries
        assert_eq!(dep_arr.len(), 3);
        // root depends on both
        let root_deps = dep_arr[0]["dependsOn"].as_array().unwrap();
        assert_eq!(root_deps.len(), 2);
    }

    #[test]
    fn cyclonedx_empty_components() {
        let output = format_cyclonedx(&[], &[], "empty-project");
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["components"].as_array().unwrap().len(), 0);
    }
}
