## Why

Atlas-Local detects security vulnerabilities and code quality issues but cannot map findings to industry compliance frameworks. Security teams and auditors need to demonstrate that their static analysis tooling covers regulatory requirements such as OWASP Top 10 2021, PCI DSS 4.0, NIST 800-53, and HIPAA. Without compliance metadata on rules and a coverage reporting mechanism, teams must manually cross-reference findings against framework requirements — a tedious, error-prone process that impedes audit readiness.

## What Changes

- Define a compliance metadata schema (`metadata.compliance`) for security rule YAML files, containing an array of `{framework, requirement, description}` mappings
- Backfill all 27 existing security rules and applicable secrets rules (~33 YAML files total) with compliance mappings — at minimum OWASP Top 10 2021, with PCI DSS 4.0, NIST 800-53, and HIPAA where applicable
- Ship 4 embedded compliance framework definition YAML files (`rules/compliance/`) defining the categories and requirements for each supported framework
- Add an `atlas compliance coverage <framework>` CLI subcommand that computes and displays per-category coverage (mapped rules, finding counts, coverage percentage) in table or JSON format
- Include a `compliance_summary` section in JSON reports with per-framework, per-category finding breakdowns
- Add `properties.compliance` metadata to SARIF report rule entries
- Propagate compliance metadata from Rule → Finding → report output without data loss

## Capabilities

### New Capabilities

- `compliance-framework-mapping`: Compliance metadata on security rules, 4 embedded framework definitions (OWASP Top 10 2021, PCI DSS 4.0, NIST 800-53, HIPAA), `atlas compliance coverage` CLI subcommand with table/JSON output, and compliance summary integration in JSON and SARIF reports

### Modified Capabilities

_(none — existing scan, gate, rule-matching, and report functionality remain unchanged; compliance metadata is additive and the pattern engine is metadata-agnostic)_

## Impact

- **Rules** (`rules/builtin/`): ~33 security and secrets rule YAML files gain `metadata.compliance` entries; no pattern changes
- **Rules** (`rules/compliance/`): 4 new framework definition YAML files (OWASP, PCI DSS, NIST, HIPAA)
- **Core** (`atlas-core`): New `compliance.rs` module with `ComplianceFramework`, `ComplianceCategory`, `ComplianceMapping`, `ComplianceSummary`, and `ComplianceCoverage` types
- **CLI** (`atlas-cli`): New `compliance` subcommand registered in `main.rs`; new `commands/compliance.rs` with `coverage` subcommand supporting `--format {table|json}`
- **Report** (`atlas-report`): JSON report gains `compliance_summary` section; SARIF report gains `properties.compliance` on rule entries
- **Analysis** (`atlas-analysis`): `Finding.metadata["compliance"]` propagated from matched rule at match time (existing metadata plumbing — no structural changes)
- **Dependencies**: No new crate dependencies — framework definitions are embedded YAML parsed with existing `serde_yaml`
- **Backwards compatibility**: All changes are additive; rule matching behaviour is unaffected; reports without compliance-mapped findings omit compliance sections
