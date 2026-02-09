# Feature Specification: Atlas Local — Compliance Framework Mapping

**Feature Branch**: `003-compliance-framework-mapping`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, rule metadata, report formats)

## Overview & Scope

Atlas-Local detects security and quality vulnerabilities but does not map findings to industry compliance frameworks. Security teams need to demonstrate compliance coverage against standards like OWASP Top 10 2021, PCI DSS 4.0, NIST 800-53, and HIPAA. This specification adds structured compliance metadata to security rules and introduces compliance coverage reporting.

**Purpose**: Enable organisations to map Atlas findings to compliance frameworks, generate coverage reports, and demonstrate regulatory adherence using existing scan results.

**Scope**: Compliance metadata on existing security rules, coverage reporting, and a CLI subcommand. No new detection logic — only metadata enrichment and reporting.

**Exclusions** (deferred to future specs):
- Custom compliance framework definitions (user-authored YAML frameworks)
- Compliance drift tracking across scans (requires dashboard — see 010)
- Automated remediation priority ranking by compliance impact
- SOC 2 / ISO 27001 / CIS Benchmark mappings (future framework additions)
- Compliance-specific policy gating (e.g., "fail if OWASP A01 coverage < 80%")

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Security Engineer Generates OWASP Coverage Report (Priority: P1)

A security engineer needs to demonstrate to auditors that their codebase is scanned for all OWASP Top 10 2021 categories. They run `atlas compliance coverage owasp-top-10-2021` and get a summary showing which OWASP categories are covered by Atlas rules, which findings map to each category, and which categories have no rule coverage.

**Why this priority**: Compliance coverage visibility is the primary value proposition — without it, the feature has no utility.

**Independent Test**: Run a compliance coverage command against a project with known security findings and verify the output lists all 10 OWASP categories with correct finding counts and coverage percentages.

**Acceptance Scenarios**:

1. **Given** a project scanned with Atlas security rules, **When** `atlas compliance coverage owasp-top-10-2021` is run, **Then** a table is displayed showing all 10 OWASP categories (A01–A10), the number of rules mapped to each, the number of findings in each, and overall coverage percentage.
2. **Given** an OWASP category with no mapped rules (e.g., A08 Software and Data Integrity), **When** the coverage report is generated, **Then** that category shows 0 rules, 0 findings, and is flagged as "No Coverage".
3. **Given** a scan with SQL injection findings, **When** the compliance report is viewed, **Then** those findings appear under A03 (Injection) with the correct CWE cross-references.

---

### User Story 2 — Auditor Reviews PCI DSS Mapping in Scan Report (Priority: P1)

An auditor receives an Atlas JSON report and needs to verify that static analysis covers PCI DSS 4.0 Requirement 6 (Develop and Maintain Secure Systems and Software). The report includes a `compliance_summary` section mapping findings to PCI DSS requirements.

**Why this priority**: Report integration is essential for audit workflows — auditors consume reports, not CLI output.

**Independent Test**: Generate a JSON report from a scan of a project with known vulnerabilities, verify the `compliance_summary` section is present, and confirm PCI DSS requirement mappings are accurate.

**Acceptance Scenarios**:

1. **Given** a scan report in JSON format, **When** the report includes security findings, **Then** a `compliance_summary` object is present with per-framework breakdowns (OWASP, PCI DSS, NIST, HIPAA).
2. **Given** a finding for `atlas/security/typescript/sql-injection` (CWE-89), **When** the compliance summary is inspected, **Then** it maps to PCI DSS 4.0 Requirement 6.2.4 and OWASP A03:2021 Injection.
3. **Given** a SARIF report output, **When** compliance metadata is present, **Then** each rule's `properties` includes a `compliance` array with framework references.

---

### User Story 3 — Developer Views Rule-Level Compliance Tags (Priority: P2)

A developer inspects a specific finding and wants to understand which compliance requirements it relates to. The finding metadata includes compliance tags that link to framework-specific requirements.

**Why this priority**: Rule-level metadata is the foundation that enables coverage reporting, but developers interact with it less frequently than auditors.

**Independent Test**: Load a rule YAML with compliance metadata and verify the loaded `Rule` struct contains the compliance mappings, and that findings produced by this rule carry the compliance metadata through to the report.

**Acceptance Scenarios**:

1. **Given** a security rule YAML with `metadata.compliance` entries, **When** the rule is loaded, **Then** `Rule.metadata["compliance"]` contains a structured array of framework mappings.
2. **Given** a finding produced by a rule with compliance metadata, **When** serialised to JSON, **Then** the finding includes `metadata.compliance` with all mapped frameworks and requirement IDs.

---

### User Story 4 — Team Tracks Multi-Framework Compliance in CI (Priority: P2)

A DevSecOps team runs `atlas compliance coverage --format json` in CI to track compliance coverage over time. They export the JSON to their compliance management system for trend analysis.

**Why this priority**: JSON output enables integration with external compliance tools, but requires the core coverage calculation (US1) to work first.

**Independent Test**: Run compliance coverage with `--format json`, parse the output, and verify the schema includes per-framework, per-category breakdowns with rule counts and finding counts.

**Acceptance Scenarios**:

1. **Given** `atlas compliance coverage owasp-top-10-2021 --format json`, **When** executed, **Then** valid JSON is produced with `framework`, `categories[]`, `total_rules`, `covered_categories`, and `coverage_percentage` fields.
2. **Given** multiple frameworks specified (`--framework owasp-top-10-2021,pci-dss-4.0`), **When** executed, **Then** each framework has its own section in the output.

---

### Edge Cases

- What happens when a rule maps to multiple OWASP categories? The rule is counted in all mapped categories, and findings appear under each relevant category. The coverage percentage reflects unique categories covered.
- What happens when no security rules are loaded (quality-only scan)? The compliance coverage report shows 0% coverage for all frameworks with a warning message.
- What happens when a new framework version is released (e.g., OWASP 2025)? Framework definitions are embedded in the Atlas binary. Updating requires an Atlas version upgrade. Future specs may support user-defined frameworks.
- What happens with secrets rules? Secrets rules map to compliance frameworks where applicable (e.g., hardcoded credentials → PCI DSS 6.2.4, NIST IA-5). They are included in compliance coverage reporting.

## Requirements *(mandatory)*

### Functional Requirements

**Compliance Metadata Schema**

- **FR-C01**: Each security rule YAML MUST support an optional `metadata.compliance` field containing an array of compliance framework mappings.
- **FR-C02**: Each compliance mapping MUST include: `framework` (string identifier), `requirement` (requirement ID), and `description` (human-readable label).
- **FR-C03**: All 27 existing security rules MUST be backfilled with compliance mappings for at least OWASP Top 10 2021. PCI DSS 4.0, NIST 800-53, and HIPAA mappings SHOULD be included where applicable.
- **FR-C04**: Secrets rules SHOULD include compliance mappings where applicable (e.g., hardcoded credentials → PCI DSS, NIST).

**Compliance Framework Definitions**

- **FR-C05**: Atlas MUST ship with embedded definitions for four compliance frameworks: OWASP Top 10 2021 (10 categories), PCI DSS 4.0 Requirement 6 (sub-requirements), NIST 800-53 (relevant controls), and HIPAA Security Rule (relevant safeguards).
- **FR-C06**: Each framework definition MUST include: `id`, `name`, `version`, `categories[]` with `id`, `title`, and `description`.
- **FR-C07**: Framework definitions MUST be stored as embedded YAML files in `rules/compliance/` directory.

**Coverage Reporting**

- **FR-C08**: A new `atlas compliance coverage <framework>` subcommand MUST compute and display compliance coverage for the specified framework.
- **FR-C09**: Coverage output MUST show: each framework category, the number of mapped rules, the number of scan findings, and a coverage status (Covered / No Coverage).
- **FR-C10**: Coverage percentage MUST be calculated as: `(categories with ≥1 mapped rule) / (total categories) × 100`.
- **FR-C11**: The `--format` flag MUST support `table` (default, human-readable) and `json` (machine-readable) output formats.

**Report Integration**

- **FR-C12**: JSON reports MUST include a `compliance_summary` section when compliance metadata is present, grouped by framework with per-category finding counts.
- **FR-C13**: SARIF reports MUST include compliance metadata in rule `properties.compliance` as an array of framework references.
- **FR-C14**: Compliance metadata in findings MUST be propagated from `Rule.metadata["compliance"]` to `Finding.metadata["compliance"]` at match time.

**Non-Regression**

- **FR-C15**: Adding compliance metadata to rule YAML files MUST NOT affect rule matching behaviour — the pattern engine is metadata-agnostic.
- **FR-C16**: All existing scan, gate, and report functionality MUST continue to work without modification.

### Key Entities

- **ComplianceFramework**: An embedded compliance standard definition. Key attributes: `id`, `name`, `version`, `categories[]`.
- **ComplianceCategory**: A single category within a framework (e.g., OWASP A01). Key attributes: `id`, `title`, `description`.
- **ComplianceMapping**: A link from a rule to a compliance requirement. Key attributes: `framework`, `requirement`, `description`.
- **ComplianceSummary**: An aggregated view of compliance coverage for a scan. Key attributes: `framework`, `categories[]`, `total_rules`, `covered_categories`, `coverage_percentage`.
- **ComplianceCoverage**: Per-category detail within a summary. Key attributes: `category_id`, `category_title`, `mapped_rules`, `finding_count`, `status`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-C01**: All 27 security rules have OWASP Top 10 2021 compliance mappings (100% backfill).
- **SC-C02**: `atlas compliance coverage owasp-top-10-2021` correctly reports coverage for all 10 OWASP categories, with coverage percentage matching manual calculation.
- **SC-C03**: JSON reports include a valid `compliance_summary` section when compliance-mapped findings are present.
- **SC-C04**: SARIF reports include `properties.compliance` on all rules with compliance metadata.
- **SC-C05**: Compliance metadata propagates from rule YAML → Rule struct → Finding → report output without data loss.
- **SC-C06**: Adding compliance metadata to rule YAML files causes zero test regressions on existing rule matching tests.
- **SC-C07**: `atlas compliance coverage` executes in < 2 seconds (no scanning required — reads loaded rule metadata only).
- **SC-C08**: At least 20 of 27 security rules have mappings to 2+ frameworks (OWASP + at least one of PCI DSS / NIST / HIPAA).

## Assumptions

- CWE-to-compliance-framework mappings are well-established and publicly documented (MITRE CWE → OWASP, NIST NVD → PCI DSS).
- The existing `Rule.metadata: BTreeMap<String, serde_json::Value>` field can store structured compliance arrays without schema changes.
- Compliance framework definitions are relatively stable (OWASP Top 10 updates every ~4 years).
- Auditors accept static analysis rule coverage as partial evidence of compliance controls (not sole evidence).

## Scope Boundaries

**In Scope**:
- Compliance metadata schema for rule YAML files
- Backfilling 27 security rules with OWASP Top 10 2021 mappings
- 4 embedded framework definitions (OWASP, PCI DSS, NIST, HIPAA)
- `atlas compliance coverage` CLI subcommand with table and JSON output
- `compliance_summary` in JSON reports
- Compliance properties in SARIF rule metadata
- Metadata propagation from Rule to Finding

**Out of Scope**:
- User-defined custom compliance frameworks
- Compliance-specific policy gating
- Compliance trend tracking (requires 010 Web Dashboard)
- Automated CWE-to-compliance mapping (manual curation)
- SOC 2, ISO 27001, CIS Benchmarks (future framework additions)
- Compliance coverage thresholds in CI gates

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `rules/compliance/owasp-top-10-2021.yaml` | OWASP framework definition |
| `rules/compliance/pci-dss-4.0.yaml` | PCI DSS framework definition |
| `rules/compliance/nist-800-53.yaml` | NIST framework definition |
| `rules/compliance/hipaa-security.yaml` | HIPAA framework definition |
| `crates/atlas-core/src/compliance.rs` | ComplianceFramework, ComplianceSummary types |
| `crates/atlas-cli/src/commands/compliance.rs` | `atlas compliance coverage` subcommand |

### Files to Modify

| File | Change |
|------|--------|
| 27 security rule YAML files | Add `metadata.compliance` entries |
| 6 secrets rule YAML files | Add `metadata.compliance` entries (where applicable) |
| `crates/atlas-report/src/json.rs` | Add `compliance_summary` to JSON reports |
| `crates/atlas-report/src/sarif.rs` | Add `properties.compliance` to SARIF rules |
| `crates/atlas-cli/src/main.rs` | Register `compliance` subcommand |

### Total Deliverables

| Type | Count |
|------|-------|
| Framework definition YAML files | 4 |
| New Rust source files | 2 |
| Modified rule YAML files | ~33 |
| Modified Rust source files | ~4 |

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `specs/002-code-quality-analysis/spec.md` | Quality rules metadata pattern |
| [OWASP Top 10 2021](https://owasp.org/Top10/) | Primary compliance framework |
| [PCI DSS 4.0](https://www.pcisecuritystandards.org/document_library/) | Payment card industry standard |
| [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) | Federal security controls |
| [CWE/CAPEC Mapping](https://cwe.mitre.org/data/definitions/699.html) | CWE to framework cross-references |
