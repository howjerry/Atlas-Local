//! Compliance framework mapping — types, framework loading, and coverage computation.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use atlas_rules::Rule;

use crate::CoreError;

// ---------------------------------------------------------------------------
// Framework definition types (deserialised from YAML)
// ---------------------------------------------------------------------------

/// A compliance framework definition (e.g. OWASP Top 10 2021).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    /// Unique identifier (e.g. `"owasp-top-10-2021"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Framework version string.
    pub version: String,
    /// Categories / requirements within this framework.
    pub categories: Vec<ComplianceCategory>,
}

/// A single category within a compliance framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCategory {
    /// Category identifier (e.g. `"A03:2021"`).
    pub id: String,
    /// Short title.
    pub title: String,
    /// Longer description.
    pub description: String,
    /// CWE identifiers that map to this category (e.g. `["CWE-89", "CWE-79"]`).
    #[serde(default)]
    pub cwe_mappings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Rule-level compliance mapping (stored in rule YAML metadata.compliance)
// ---------------------------------------------------------------------------

/// A single compliance mapping entry on a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapping {
    /// Framework identifier (must match a `ComplianceFramework.id`).
    pub framework: String,
    /// Requirement or category ID within the framework.
    pub requirement: String,
    /// Human-readable description of the mapping.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Coverage computation output
// ---------------------------------------------------------------------------

/// Per-category detail within a coverage summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCoverage {
    /// Category identifier.
    pub category_id: String,
    /// Category title.
    pub category_title: String,
    /// Number of rules mapped to this category.
    pub mapped_rules: u32,
    /// Number of findings in this category (populated by report, 0 for rule-only coverage).
    pub finding_count: u32,
    /// `"Covered"` or `"No Coverage"`.
    pub status: String,
}

/// Aggregated compliance coverage for one framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Framework identifier.
    pub framework: String,
    /// Framework name.
    pub framework_name: String,
    /// Per-category breakdown.
    pub categories: Vec<ComplianceCoverage>,
    /// Total number of rules mapped to any category in this framework.
    pub total_rules: u32,
    /// Number of categories with at least one mapped rule.
    pub covered_categories: u32,
    /// `covered_categories / total_categories * 100`.
    pub coverage_percentage: f64,
}

// ---------------------------------------------------------------------------
// Framework loading
// ---------------------------------------------------------------------------

/// Load all compliance framework definitions from YAML files in `dir`.
pub fn load_frameworks(dir: &Path) -> Result<Vec<ComplianceFramework>, CoreError> {
    let mut frameworks = Vec::new();

    if !dir.exists() {
        return Ok(frameworks);
    }

    for entry in WalkDir::new(dir).max_depth(1).follow_links(true) {
        let entry = entry.map_err(|e| CoreError::Io(e.into()))?;
        let path = entry.path();
        if path.is_file() {
            match path.extension().and_then(|e| e.to_str()) {
                Some("yaml" | "yml") => {}
                _ => continue,
            }
            let contents = std::fs::read_to_string(path)?;
            let fw: ComplianceFramework = serde_yml::from_str(&contents)
                .map_err(|e| CoreError::Config(format!("failed to parse {}: {e}", path.display())))?;
            frameworks.push(fw);
        }
    }

    frameworks.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(frameworks)
}

// ---------------------------------------------------------------------------
// Coverage computation
// ---------------------------------------------------------------------------

/// Compute compliance coverage for a single framework against a set of rules.
///
/// Resolution order per rule:
/// 1. Explicit `metadata.compliance` entries matching this framework (highest priority).
/// 2. CWE-based auto-mapping: `Rule.cwe_id` matched against `ComplianceCategory.cwe_mappings`.
pub fn compute_coverage(framework: &ComplianceFramework, rules: &[Rule]) -> ComplianceSummary {
    // For each category, collect the set of rule IDs that map to it.
    let mut category_rules: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for cat in &framework.categories {
        category_rules.insert(cat.id.clone(), Vec::new());
    }

    // Build a lookup: category_id → set of CWEs for fast matching.
    let cwe_to_categories: BTreeMap<String, Vec<String>> = {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for cat in &framework.categories {
            for cwe in &cat.cwe_mappings {
                map.entry(cwe.clone()).or_default().push(cat.id.clone());
            }
        }
        map
    };

    for rule in rules {
        let mut matched_categories: Vec<String> = Vec::new();

        // 1. Explicit metadata.compliance entries.
        if let Some(compliance_val) = rule.metadata.get("compliance") {
            if let Some(arr) = compliance_val.as_array() {
                for entry in arr {
                    if let (Some(fw), Some(req)) = (
                        entry.get("framework").and_then(|v| v.as_str()),
                        entry.get("requirement").and_then(|v| v.as_str()),
                    ) {
                        if fw == framework.id
                            && category_rules.contains_key(req)
                            && !matched_categories.contains(&req.to_string())
                        {
                            matched_categories.push(req.to_string());
                        }
                    }
                }
            }
        }

        // 2. CWE-based auto-mapping (only for categories not already matched explicitly).
        if let Some(ref cwe_id) = rule.cwe_id {
            if let Some(cats) = cwe_to_categories.get(cwe_id) {
                for cat_id in cats {
                    if !matched_categories.contains(cat_id) {
                        matched_categories.push(cat_id.clone());
                    }
                }
            }
        }

        // Record the rule in each matched category.
        for cat_id in matched_categories {
            if let Some(rule_list) = category_rules.get_mut(&cat_id) {
                if !rule_list.contains(&rule.id) {
                    rule_list.push(rule.id.clone());
                }
            }
        }
    }

    // Build per-category coverage.
    let mut categories = Vec::new();
    let mut covered_count = 0u32;
    let mut total_unique_rules = std::collections::HashSet::new();

    for cat in &framework.categories {
        let rule_list = category_rules.get(&cat.id).cloned().unwrap_or_default();
        let mapped = rule_list.len() as u32;
        let status = if mapped > 0 { "Covered" } else { "No Coverage" };
        if mapped > 0 {
            covered_count += 1;
        }
        for r in &rule_list {
            total_unique_rules.insert(r.clone());
        }
        categories.push(ComplianceCoverage {
            category_id: cat.id.clone(),
            category_title: cat.title.clone(),
            mapped_rules: mapped,
            finding_count: 0,
            status: status.to_string(),
        });
    }

    let total_categories = framework.categories.len() as f64;
    let coverage_pct = if total_categories > 0.0 {
        (covered_count as f64 / total_categories) * 100.0
    } else {
        0.0
    };

    ComplianceSummary {
        framework: framework.id.clone(),
        framework_name: framework.name.clone(),
        categories,
        total_rules: total_unique_rules.len() as u32,
        covered_categories: covered_count,
        coverage_percentage: coverage_pct,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_rules::*;
    use std::collections::BTreeMap;

    fn make_rule(id: &str, cwe: Option<&str>, compliance: Option<serde_json::Value>) -> Rule {
        let mut metadata = BTreeMap::new();
        if let Some(c) = compliance {
            metadata.insert("compliance".to_string(), c);
        }
        Rule {
            id: id.to_string(),
            name: "Test Rule".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            category: Category::Security,
            language: Language::TypeScript,
            analysis_level: AnalysisLevel::L1,
            rule_type: RuleType::Declarative,
            confidence: Confidence::High,
            pattern: Some("(identifier)".to_string()),
            script: None,
            plugin: None,
            cwe_id: cwe.map(|s| s.to_string()),
            remediation: "Fix it".to_string(),
            references: vec![],
            tags: vec![],
            version: "1.0.0".to_string(),
            metadata,
        }
    }

    fn make_framework() -> ComplianceFramework {
        ComplianceFramework {
            id: "test-framework".to_string(),
            name: "Test Framework".to_string(),
            version: "1.0".to_string(),
            categories: vec![
                ComplianceCategory {
                    id: "CAT-A".to_string(),
                    title: "Category A".to_string(),
                    description: "First category".to_string(),
                    cwe_mappings: vec!["CWE-89".to_string(), "CWE-79".to_string()],
                },
                ComplianceCategory {
                    id: "CAT-B".to_string(),
                    title: "Category B".to_string(),
                    description: "Second category".to_string(),
                    cwe_mappings: vec!["CWE-22".to_string()],
                },
                ComplianceCategory {
                    id: "CAT-C".to_string(),
                    title: "Category C".to_string(),
                    description: "Third category".to_string(),
                    cwe_mappings: vec![],
                },
            ],
        }
    }

    #[test]
    fn coverage_cwe_auto_mapping() {
        let fw = make_framework();
        let rules = vec![make_rule("rule-1", Some("CWE-89"), None)];
        let summary = compute_coverage(&fw, &rules);

        assert_eq!(summary.framework, "test-framework");
        assert_eq!(summary.covered_categories, 1);
        assert_eq!(summary.total_rules, 1);
        assert!((summary.coverage_percentage - 33.333).abs() < 1.0);
        assert_eq!(summary.categories[0].mapped_rules, 1); // CAT-A
        assert_eq!(summary.categories[0].status, "Covered");
        assert_eq!(summary.categories[1].mapped_rules, 0); // CAT-B
        assert_eq!(summary.categories[2].mapped_rules, 0); // CAT-C
        assert_eq!(summary.categories[2].status, "No Coverage");
    }

    #[test]
    fn coverage_explicit_mapping_priority() {
        let fw = make_framework();
        // Rule has CWE-79 (maps to CAT-A via auto) but explicit mapping to CAT-B.
        let compliance = serde_json::json!([
            { "framework": "test-framework", "requirement": "CAT-B", "description": "Override" }
        ]);
        let rules = vec![make_rule("rule-1", Some("CWE-79"), Some(compliance))];
        let summary = compute_coverage(&fw, &rules);

        // Rule should appear in both CAT-A (CWE auto) and CAT-B (explicit).
        assert_eq!(summary.categories[0].mapped_rules, 1); // CAT-A via CWE
        assert_eq!(summary.categories[1].mapped_rules, 1); // CAT-B via explicit
        assert_eq!(summary.covered_categories, 2);
    }

    #[test]
    fn coverage_multi_category_rule() {
        let fw = make_framework();
        let compliance = serde_json::json!([
            { "framework": "test-framework", "requirement": "CAT-A", "description": "Map A" },
            { "framework": "test-framework", "requirement": "CAT-B", "description": "Map B" },
            { "framework": "test-framework", "requirement": "CAT-C", "description": "Map C" }
        ]);
        let rules = vec![make_rule("rule-1", None, Some(compliance))];
        let summary = compute_coverage(&fw, &rules);

        assert_eq!(summary.covered_categories, 3);
        assert!((summary.coverage_percentage - 100.0).abs() < 0.01);
        assert_eq!(summary.total_rules, 1); // one unique rule
    }

    #[test]
    fn coverage_zero_rules() {
        let fw = make_framework();
        let summary = compute_coverage(&fw, &[]);

        assert_eq!(summary.covered_categories, 0);
        assert_eq!(summary.total_rules, 0);
        assert!((summary.coverage_percentage - 0.0).abs() < 0.01);
        for cat in &summary.categories {
            assert_eq!(cat.status, "No Coverage");
        }
    }

    #[test]
    fn coverage_ignores_other_frameworks() {
        let fw = make_framework();
        let compliance = serde_json::json!([
            { "framework": "other-framework", "requirement": "X", "description": "Unrelated" }
        ]);
        let rules = vec![make_rule("rule-1", None, Some(compliance))];
        let summary = compute_coverage(&fw, &rules);

        assert_eq!(summary.covered_categories, 0);
        assert_eq!(summary.total_rules, 0);
    }

    #[test]
    fn load_frameworks_from_nonexistent_dir() {
        let result = load_frameworks(Path::new("/nonexistent/path"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn load_all_builtin_framework_definitions() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let compliance_dir = manifest_dir.parent().unwrap().parent().unwrap().join("rules/compliance");
        let frameworks = load_frameworks(&compliance_dir).unwrap();
        assert_eq!(frameworks.len(), 4, "expected 4 framework definitions");

        // Verify each framework has required fields and expected category counts.
        let fw_map: BTreeMap<String, &ComplianceFramework> =
            frameworks.iter().map(|f| (f.id.clone(), f)).collect();

        let hipaa = fw_map.get("hipaa-security").expect("missing hipaa-security");
        assert_eq!(hipaa.categories.len(), 5);
        assert!(!hipaa.name.is_empty());
        assert!(!hipaa.version.is_empty());

        let nist = fw_map.get("nist-800-53").expect("missing nist-800-53");
        assert_eq!(nist.categories.len(), 12);

        let owasp = fw_map.get("owasp-top-10-2021").expect("missing owasp-top-10-2021");
        assert_eq!(owasp.categories.len(), 10);

        let pci = fw_map.get("pci-dss-4.0").expect("missing pci-dss-4.0");
        assert_eq!(pci.categories.len(), 15);

        // Every category must have id, title, description.
        for fw in &frameworks {
            for cat in &fw.categories {
                assert!(!cat.id.is_empty(), "empty category id in {}", fw.id);
                assert!(!cat.title.is_empty(), "empty category title in {}", fw.id);
                assert!(!cat.description.is_empty(), "empty category description in {}", fw.id);
            }
        }
    }

    #[test]
    fn all_security_rules_have_owasp_compliance_mapping() {
        use atlas_rules::declarative::DeclarativeRuleLoader;

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let builtin_dir = manifest_dir.parent().unwrap().parent().unwrap().join("rules/builtin");
        let loader = DeclarativeRuleLoader;
        let rules = loader.load_from_dir(&builtin_dir).expect("failed to load rules");

        let security_rules: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.category == atlas_rules::Category::Security
                    || r.category == atlas_rules::Category::Secrets
            })
            .collect();

        // We expect 27 security + 6 secrets = 33 total security/secrets rules.
        assert!(
            security_rules.len() >= 27,
            "expected at least 27 security/secrets rules, got {}",
            security_rules.len()
        );

        // Every security rule must have at least one OWASP compliance mapping.
        let mut rules_with_two_plus_frameworks = 0;
        for rule in &security_rules {
            let compliance = rule
                .metadata
                .get("compliance")
                .unwrap_or_else(|| panic!("rule {} missing metadata.compliance", rule.id));
            let entries = compliance
                .as_array()
                .unwrap_or_else(|| panic!("rule {} metadata.compliance is not an array", rule.id));

            let has_owasp = entries.iter().any(|e| {
                e.get("framework")
                    .and_then(|v| v.as_str())
                    .map_or(false, |fw| fw == "owasp-top-10-2021")
            });
            assert!(
                has_owasp,
                "rule {} is missing OWASP Top 10 2021 compliance mapping",
                rule.id
            );

            // Count distinct frameworks.
            let frameworks: std::collections::HashSet<_> = entries
                .iter()
                .filter_map(|e| e.get("framework").and_then(|v| v.as_str()))
                .collect();
            if frameworks.len() >= 2 {
                rules_with_two_plus_frameworks += 1;
            }
        }

        // At least 20 security/secrets rules should map to 2+ frameworks.
        assert!(
            rules_with_two_plus_frameworks >= 20,
            "expected at least 20 rules with 2+ framework mappings, got {}",
            rules_with_two_plus_frameworks
        );
    }

    #[test]
    fn load_frameworks_from_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
id: test-fw
name: Test Framework
version: "1.0"
categories:
  - id: C1
    title: Category 1
    description: First
    cwe_mappings: ["CWE-89"]
"#;
        std::fs::write(dir.path().join("test.yaml"), yaml).unwrap();
        std::fs::write(dir.path().join("ignore.txt"), "not yaml").unwrap();

        let frameworks = load_frameworks(dir.path()).unwrap();
        assert_eq!(frameworks.len(), 1);
        assert_eq!(frameworks[0].id, "test-fw");
        assert_eq!(frameworks[0].categories.len(), 1);
        assert_eq!(frameworks[0].categories[0].cwe_mappings, vec!["CWE-89"]);
    }
}
