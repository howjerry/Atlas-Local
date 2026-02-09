## ADDED Requirements

### Requirement: Compliance metadata schema
Each security rule YAML SHALL support an optional `metadata.compliance` field containing an array of compliance framework mappings. Each mapping SHALL include `framework` (string identifier matching a framework definition ID), `requirement` (the framework-specific requirement ID), and `description` (human-readable label). The `metadata.compliance` array SHALL be propagated from `Rule.metadata["compliance"]` to `Finding.metadata["compliance"]` at match time using the existing metadata pipeline.

#### Scenario: Rule YAML with compliance metadata loads correctly
- **WHEN** a security rule YAML contains `metadata.compliance` with entries for OWASP and PCI DSS
- **THEN** the loaded `Rule.metadata["compliance"]` contains a JSON array with both framework mappings including `framework`, `requirement`, and `description` fields

#### Scenario: Finding inherits compliance metadata from matched rule
- **WHEN** a finding is produced by a rule that has `metadata.compliance` entries
- **THEN** the finding's `metadata["compliance"]` contains the same array of framework mappings as the rule

#### Scenario: Rule without compliance metadata loads normally
- **WHEN** a quality rule YAML has no `metadata.compliance` field
- **THEN** the rule loads successfully and `metadata` does not contain a `compliance` key

### Requirement: Security rule compliance backfill
All 27 existing security rules SHALL be backfilled with compliance mappings for at least OWASP Top 10 2021. PCI DSS 4.0, NIST 800-53, and HIPAA mappings SHALL be included where the rule's CWE is applicable to those frameworks. At least 20 of 27 security rules SHALL have mappings to 2 or more frameworks.

#### Scenario: All security rules have OWASP mappings
- **WHEN** all 27 security rules are loaded
- **THEN** every rule's `metadata.compliance` contains at least one entry with `framework: "owasp-top-10-2021"`

#### Scenario: Multi-framework coverage target met
- **WHEN** all security rules are loaded and their compliance mappings are inspected
- **THEN** at least 20 rules have mappings to 2 or more distinct frameworks

#### Scenario: SQL injection rule maps to correct frameworks
- **WHEN** the `atlas/security/typescript/sql-injection` rule (CWE-89) is loaded
- **THEN** its compliance mappings include OWASP A03:2021 (Injection), PCI DSS 6.2.4, and NIST SI-10

### Requirement: Secrets rule compliance mappings
Secrets rules SHALL include compliance mappings where applicable. Hardcoded credential rules SHALL map to PCI DSS 6.2.4, NIST IA-5, and HIPAA where relevant.

#### Scenario: Hardcoded credentials rule has compliance mappings
- **WHEN** a secrets rule for hardcoded credentials is loaded
- **THEN** its `metadata.compliance` includes entries for PCI DSS and NIST IA-5

#### Scenario: Secrets rules included in coverage reporting
- **WHEN** `atlas compliance coverage owasp-top-10-2021` is run with secrets rules loaded
- **THEN** secrets rules that have OWASP mappings are counted in the coverage report

### Requirement: Embedded framework definitions
Atlas SHALL ship with embedded definitions for four compliance frameworks: OWASP Top 10 2021 (10 categories), PCI DSS 4.0 Requirement 6 (sub-requirements), NIST 800-53 (relevant controls), and HIPAA Security Rule (relevant safeguards). Each framework definition SHALL include `id`, `name`, `version`, and `categories[]` where each category has `id`, `title`, `description`, and `cwe_mappings[]`.

#### Scenario: OWASP Top 10 2021 framework definition
- **WHEN** the OWASP Top 10 2021 framework definition is loaded from `rules/compliance/owasp-top-10-2021.yaml`
- **THEN** it contains exactly 10 categories (A01 through A10) with id, title, description, and CWE mappings for each

#### Scenario: PCI DSS 4.0 framework definition
- **WHEN** the PCI DSS 4.0 framework definition is loaded from `rules/compliance/pci-dss-4.0.yaml`
- **THEN** it contains sub-requirements under Requirement 6 with id, title, and description for each

#### Scenario: All four framework definitions parseable
- **WHEN** all YAML files in `rules/compliance/` are loaded
- **THEN** 4 framework definitions are parsed successfully with valid `id`, `name`, `version`, and non-empty `categories`

### Requirement: Framework definition storage
Framework definitions SHALL be stored as YAML files in the `rules/compliance/` directory. The compliance module SHALL load all `.yaml` files from this directory at runtime.

#### Scenario: Framework YAML files located in rules/compliance
- **WHEN** the `rules/compliance/` directory is listed
- **THEN** it contains `owasp-top-10-2021.yaml`, `pci-dss-4.0.yaml`, `nist-800-53.yaml`, and `hipaa-security.yaml`

#### Scenario: Framework loader reads all definitions from directory
- **WHEN** `load_frameworks("rules/compliance/")` is called
- **THEN** 4 `ComplianceFramework` structs are returned, one per YAML file

### Requirement: Coverage CLI subcommand
A new `atlas compliance coverage <framework>` subcommand SHALL compute and display compliance coverage for the specified framework. Coverage output SHALL show each framework category, the number of mapped rules, and a coverage status (Covered / No Coverage). Coverage percentage SHALL be calculated as `(categories with ≥1 mapped rule) / (total categories) × 100`.

#### Scenario: OWASP coverage table output
- **WHEN** `atlas compliance coverage owasp-top-10-2021` is run with security rules loaded
- **THEN** a table is displayed showing all 10 OWASP categories with category ID, title, mapped rule count, and Covered/No Coverage status, followed by an overall coverage percentage

#### Scenario: Category with no mapped rules shows No Coverage
- **WHEN** the coverage report is generated and an OWASP category has no rules mapped to it
- **THEN** that category shows 0 mapped rules and status "No Coverage"

#### Scenario: Coverage percentage calculation
- **WHEN** 7 of 10 OWASP categories have at least 1 mapped rule
- **THEN** the coverage percentage is reported as 70.0%

#### Scenario: Invalid framework ID
- **WHEN** `atlas compliance coverage nonexistent-framework` is run
- **THEN** an error message is displayed listing available framework IDs

### Requirement: Coverage output formats
The `--format` flag on `atlas compliance coverage` SHALL support `table` (default, human-readable) and `json` (machine-readable) output formats.

#### Scenario: Default table format
- **WHEN** `atlas compliance coverage owasp-top-10-2021` is run without `--format`
- **THEN** output is rendered as a human-readable table

#### Scenario: JSON format output
- **WHEN** `atlas compliance coverage owasp-top-10-2021 --format json` is run
- **THEN** valid JSON is produced with `framework`, `categories[]`, `total_rules`, `covered_categories`, and `coverage_percentage` fields

#### Scenario: Multiple frameworks in JSON
- **WHEN** `atlas compliance coverage owasp-top-10-2021 pci-dss-4.0 --format json` is run
- **THEN** the JSON output contains separate sections for each specified framework

### Requirement: Coverage operates on rules only
The `atlas compliance coverage` command SHALL operate on loaded rules and framework definitions only, without requiring a prior scan. It answers "what categories can Atlas detect?" based on rule metadata, not "what did a scan find?". The command SHALL execute in less than 2 seconds.

#### Scenario: Coverage without prior scan
- **WHEN** `atlas compliance coverage owasp-top-10-2021` is run without any prior scan
- **THEN** coverage is computed from loaded rule metadata and framework definitions, completing in under 2 seconds

#### Scenario: No security rules loaded
- **WHEN** `atlas compliance coverage owasp-top-10-2021` is run with no security rules available
- **THEN** all categories show 0 mapped rules, coverage is 0%, and a warning is displayed

### Requirement: CWE-based framework resolution
Each framework definition SHALL include `cwe_mappings` per category. Coverage SHALL be computed by matching `Rule.cwe_id` against framework category CWE lists, supplemented by explicit `metadata.compliance` entries. Explicit `metadata.compliance` entries SHALL take priority over CWE-based auto-mapping.

#### Scenario: Rule matched via CWE auto-mapping
- **WHEN** a rule has `cwe_id: CWE-89` and the OWASP framework defines CWE-89 under category A03
- **THEN** the rule is counted as covering OWASP A03 even without explicit `metadata.compliance` for OWASP

#### Scenario: Explicit mapping overrides CWE mapping
- **WHEN** a rule has both `cwe_id: CWE-79` and an explicit `metadata.compliance` entry mapping to OWASP A03
- **THEN** the explicit mapping to A03 is used (not the CWE-based mapping to A07)

#### Scenario: Rule with multiple CWE-matching categories
- **WHEN** a rule's CWE maps to multiple categories in a framework
- **THEN** the rule is counted in all matching categories

### Requirement: JSON report compliance summary
JSON reports SHALL include a `compliance_summary` section when compliance-mapped findings are present. The summary SHALL be grouped by framework with per-category finding counts. When no compliance-mapped findings are present, the `compliance_summary` field SHALL be absent from the report.

#### Scenario: JSON report includes compliance summary
- **WHEN** a scan produces findings from rules with compliance metadata and JSON report is generated
- **THEN** the report includes `compliance_summary` with per-framework breakdowns containing category IDs, finding counts, and overall statistics

#### Scenario: Compliance summary grouped by framework
- **WHEN** findings map to both OWASP and PCI DSS frameworks
- **THEN** `compliance_summary` contains separate entries for each framework, each with its own categories and finding counts

#### Scenario: No compliance findings omits summary
- **WHEN** a scan produces only quality findings (no compliance metadata)
- **THEN** the JSON report does not include a `compliance_summary` field

### Requirement: SARIF report compliance properties
SARIF reports SHALL include compliance metadata in each rule's `properties.compliance` as an array of framework references when the rule has compliance mappings.

#### Scenario: SARIF rule properties include compliance
- **WHEN** a SARIF report is generated from rules with compliance metadata
- **THEN** each rule descriptor's `properties` includes a `compliance` array with `{framework, requirement, description}` entries

#### Scenario: SARIF rule without compliance metadata
- **WHEN** a SARIF report includes a quality rule without compliance mappings
- **THEN** that rule descriptor's `properties` does not include a `compliance` field

### Requirement: Non-regression on rule matching
Adding compliance metadata to rule YAML files SHALL NOT affect rule matching behaviour. The pattern engine SHALL remain metadata-agnostic. All existing scan, gate, and report functionality SHALL continue to work without modification.

#### Scenario: Rule matching unaffected by compliance metadata
- **WHEN** compliance metadata is added to a security rule YAML
- **THEN** the rule produces identical findings (same file, line, snippet) as before the metadata was added

#### Scenario: Existing tests pass after compliance backfill
- **WHEN** all rule YAML files have been updated with compliance metadata
- **THEN** the full test suite passes with zero regressions

### Requirement: Rule mapping to multiple categories
When a rule maps to multiple categories within a single framework, the rule SHALL be counted in all mapped categories. Findings from that rule SHALL appear under each relevant category in compliance reports.

#### Scenario: Rule counted in multiple OWASP categories
- **WHEN** a rule's compliance metadata maps to both OWASP A03 (Injection) and OWASP A10 (SSRF)
- **THEN** the rule is counted in both categories in the coverage report

#### Scenario: Finding appears under multiple categories in summary
- **WHEN** a finding is produced by a rule mapped to OWASP A03 and A10
- **THEN** the finding is counted in both A03 and A10 in the `compliance_summary`
