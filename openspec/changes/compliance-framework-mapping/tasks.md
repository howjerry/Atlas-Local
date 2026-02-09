## 1. Core Compliance Types

- [x] 1.1 Create `crates/atlas-core/src/compliance.rs` with `ComplianceFramework`, `ComplianceCategory`, `ComplianceMapping`, `ComplianceSummary`, and `ComplianceCoverage` structs (all with Serialize/Deserialize)
- [x] 1.2 Add `load_frameworks(dir: &Path) -> Result<Vec<ComplianceFramework>>` function that reads all `.yaml` files from a directory and deserialises them
- [x] 1.3 Add `compute_coverage(framework: &ComplianceFramework, rules: &[Rule]) -> ComplianceSummary` function implementing dual resolution: explicit `metadata.compliance` (priority) then CWE-based auto-mapping (fallback)
- [x] 1.4 Register `pub mod compliance;` in `crates/atlas-core/src/lib.rs` and re-export key types
- [x] 1.5 Write unit tests for `load_frameworks` (parse 4 definitions), `compute_coverage` (explicit mapping, CWE auto-mapping, multi-category rule, 0% coverage edge case)

## 2. Framework Definition YAML Files

- [x] 2.1 Create `rules/compliance/owasp-top-10-2021.yaml` with 10 categories (A01–A10), each with `id`, `title`, `description`, and `cwe_mappings[]`
- [x] 2.2 Create `rules/compliance/pci-dss-4.0.yaml` with Requirement 6 sub-requirements (6.2.1–6.2.4, 6.3.1–6.3.2, 6.4.1–6.4.3, 6.5.1–6.5.6), each with `id`, `title`, `description`, and `cwe_mappings[]`
- [x] 2.3 Create `rules/compliance/nist-800-53.yaml` with relevant controls (SI-10, SI-11, SC-28, IA-5, AC-3, AU-2, etc.), each with `id`, `title`, `description`, and `cwe_mappings[]`
- [x] 2.4 Create `rules/compliance/hipaa-security.yaml` with relevant safeguards (Access Control, Audit Controls, Integrity, Transmission Security), each with `id`, `title`, `description`, and `cwe_mappings[]`
- [x] 2.5 Write a test that loads all 4 framework definitions and asserts correct category counts and required fields

## 3. Security Rule Compliance Backfill

- [x] 3.1 Add `metadata.compliance` to all 5 TypeScript security rules (sql-injection, xss, path-traversal, code-injection, insecure-deserialization) with OWASP + applicable PCI DSS/NIST/HIPAA mappings
- [x] 3.2 Add `metadata.compliance` to all 4 Java security rules with OWASP + applicable framework mappings
- [x] 3.3 Add `metadata.compliance` to all 4 Python security rules with OWASP + applicable framework mappings
- [x] 3.4 Add `metadata.compliance` to all 5 C# security rules with OWASP + applicable framework mappings
- [x] 3.5 Add `metadata.compliance` to all 3 Go security rules with OWASP + applicable framework mappings
- [x] 3.6 Add `metadata.compliance` to applicable secrets rules (hardcoded credentials → PCI DSS 6.2.4, NIST IA-5, OWASP A07)
- [x] 3.7 Run full test suite to verify zero regressions on rule matching after backfill
- [x] 3.8 Write a test asserting all 27 security rules have at least one OWASP mapping and at least 20 have 2+ frameworks

## 4. CLI Compliance Subcommand

- [x] 4.1 Create `crates/atlas-cli/src/commands/compliance.rs` with `ComplianceArgs` (clap subcommand: `coverage <framework-ids>` positional args, `--format {table|json}` flag)
- [x] 4.2 Implement `execute()`: load rules via `DeclarativeRuleLoader`, load frameworks from `rules/compliance/`, call `compute_coverage()`, render output
- [x] 4.3 Implement table output: category ID, title, mapped rule count, Covered/No Coverage status, overall coverage percentage
- [x] 4.4 Implement JSON output: `{framework, categories[], total_rules, covered_categories, coverage_percentage}`
- [x] 4.5 Handle error cases: invalid framework ID (list available), no security rules (0% + warning)
- [x] 4.6 Register `Compliance(commands::compliance::ComplianceArgs)` variant in `Commands` enum in `main.rs` and add `pub mod compliance;` to `commands/mod.rs`

## 5. Report Integration

- [x] 5.1 Add `compliance_summary: Option<Vec<ComplianceSummary>>` field to `AtlasReport` in `json.rs` with `skip_serializing_if`
- [x] 5.2 Add `compliance_summary: Option<Vec<ComplianceSummary>>` to `ReportOptions` in `json.rs`
- [x] 5.3 Build `compliance_summary` from findings in `scan.rs`: iterate findings, extract `metadata["compliance"]`, group by framework and category, count findings per category
- [x] 5.4 Add `compliance: Option<Vec<serde_json::Value>>` to `SarifDescriptorProperties` in `sarif.rs` with `skip_serializing_if`; populate from `Rule.metadata["compliance"]` in `rule_to_descriptor()`
- [x] 5.5 Write unit tests: JSON report with/without compliance summary, SARIF rule properties with/without compliance metadata

## 6. E2E and Integration Tests

- [x] 6.1 E2E test: `atlas compliance coverage owasp-top-10-2021` produces table output with 10 categories and coverage percentage
- [x] 6.2 E2E test: `atlas compliance coverage owasp-top-10-2021 --format json` produces valid JSON with expected schema
- [x] 6.3 E2E test: `atlas compliance coverage nonexistent` returns error with available framework list
- [x] 6.4 E2E test: scan with compliance-mapped rules produces JSON report with `compliance_summary`
- [x] 6.5 E2E test: scan with compliance-mapped rules produces SARIF report with `properties.compliance` on rule descriptors
- [x] 6.6 E2E test: verify existing scan tests pass unchanged (non-regression)
