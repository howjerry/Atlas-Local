## Context

Atlas-Local has 27 security rules and 6 secrets rules across 5 languages. Each rule has a `metadata: BTreeMap<String, serde_json::Value>` field that flows from YAML → `Rule` → `RuleMatchMetadata` → `FindingBuilder` → `Finding` → reports. This metadata pipeline was established during code quality analysis (spec 002) and is proven to work end-to-end. The spec 002 quality rules use `metadata.quality_domain` — compliance mappings will use `metadata.compliance` following the same pattern.

The CLI uses clap v4 with a `Commands` enum in `main.rs`. Adding a subcommand is mechanical: new module in `commands/`, register variant in `Commands`, implement `execute()`.

Reports (JSON, SARIF, JSONL) already support optional top-level sections via `Option<T>` with `#[serde(skip_serializing_if = "Option::is_none")]`. The `diff_context` section added in spec 004 demonstrates this pattern.

## Goals / Non-Goals

**Goals:**

- Enrich all 27 security rules and applicable secrets rules with compliance framework mappings (OWASP Top 10 2021 mandatory; PCI DSS 4.0, NIST 800-53, HIPAA where applicable)
- Ship 4 embedded framework definitions so `atlas compliance coverage` can compute per-category coverage without network access
- Provide machine-readable (JSON) and human-readable (table) compliance coverage output for CI and audit workflows
- Include compliance summary in JSON reports and compliance properties in SARIF reports for downstream tool consumption

**Non-Goals:**

- User-defined custom compliance frameworks (future spec)
- Compliance-specific policy gating or thresholds
- Compliance trend tracking (requires spec 010 Web Dashboard)
- SOC 2, ISO 27001, CIS Benchmarks (future framework additions)
- Automated CWE-to-framework mapping — all mappings are manually curated

## Decisions

### D1: Store compliance mappings in rule YAML `metadata.compliance`, not in separate mapping files

**Choice**: Each rule YAML carries its own compliance mappings inline under `metadata.compliance`.

**Alternatives considered**:
- **Separate CWE-to-framework mapping file**: A single file mapping CWE IDs to framework categories. Would be DRY (many CWEs map to the same OWASP category), but adds indirection — you can't see a rule's compliance mappings by reading the rule file. Also fragile if a rule has CWE-specific nuances.
- **Dedicated `compliance_mappings` top-level field**: Adds a new field to the rule YAML schema. Unnecessary — `metadata` already supports arbitrary structured data and the plumbing is proven.

**Rationale**: Inline `metadata.compliance` is self-contained (one file = one rule = all its metadata), requires zero schema changes to the rule loader, and leverages the existing metadata pipeline. The slight duplication (e.g., multiple SQL injection rules all mapping to OWASP A03) is acceptable for ~33 rules.

### D2: Framework definitions as YAML files in `rules/compliance/`, loaded at runtime

**Choice**: 4 YAML files in `rules/compliance/` defining framework categories. Loaded by a `load_frameworks()` function in `atlas-core::compliance`.

**Alternatives considered**:
- **Hardcoded Rust constants**: Framework categories as `const` arrays. Faster to load but harder to maintain and impossible for users to inspect.
- **`include_str!` embedded at compile time**: Embeds YAML content in the binary. Eliminates runtime file I/O but prevents users from inspecting/overriding framework definitions. Also complicates testing.

**Rationale**: Runtime YAML loading follows the same pattern as `DeclarativeRuleLoader::load_from_dir()` for rules. Framework definitions are small (< 5 KB each) and loaded once per `atlas compliance coverage` invocation. Users can inspect the YAML files for audit transparency. The `compliance coverage` command will locate them relative to the rules directory (same resolution logic as builtin rules).

### D3: Compliance module lives in `atlas-core`, not a new crate

**Choice**: New `compliance.rs` module in `crates/atlas-core/src/`.

**Alternatives considered**:
- **New `atlas-compliance` crate**: Provides clean separation but adds workspace complexity for what is essentially 3 struct definitions and a YAML loader function. Premature for the current scope.

**Rationale**: `atlas-core` already hosts shared types (`GateResult`, `FindingStatus`), config, and engine orchestration. Compliance types (`ComplianceFramework`, `ComplianceSummary`) are shared between the CLI subcommand and the report module — `atlas-core` is the natural shared dependency. Can be extracted to a dedicated crate later if scope expands (e.g., user-defined frameworks).

### D4: CWE-based framework resolution for coverage computation

**Choice**: Each framework definition includes `cwe_mappings` per category. Coverage is computed by matching `Rule.cwe_id` against framework category CWE lists, supplemented by explicit `metadata.compliance` entries on rules.

**Alternatives considered**:
- **Only explicit `metadata.compliance` mappings**: Requires every rule to manually list every applicable framework+category. Tedious and error-prone for 27+ rules × 4 frameworks.
- **Only CWE-based auto-mapping**: Clean but loses specificity — some rules don't have CWE IDs, and CWE-to-OWASP mappings can be ambiguous.

**Rationale**: Dual approach — framework definitions carry CWE-to-category mappings for automatic resolution, while `metadata.compliance` allows per-rule overrides and additions. This means adding a new framework definition can immediately compute approximate coverage from existing CWE IDs, while explicit mappings provide precision. The `atlas compliance coverage` command resolves in order: explicit `metadata.compliance` (highest priority) → CWE-based auto-mapping (fallback).

### D5: `compliance_summary` in JSON report is computed from findings + loaded frameworks

**Choice**: The `compliance_summary` section is built at report generation time by cross-referencing scan findings against loaded framework definitions.

**Alternatives considered**:
- **Pre-compute during scan**: Would require passing framework definitions through the scan engine. Overcomplicates scan orchestration for what is a reporting concern.

**Rationale**: Compliance coverage is a view over scan results, not a scan-time operation. The report formatter already receives all findings — it can compute the summary by iterating findings, extracting `metadata.compliance`, and grouping by framework and category. This keeps the scan engine metadata-agnostic (per FR-C15).

### D6: `atlas compliance coverage` operates on loaded rules only (no scan required)

**Choice**: The coverage command loads rules and framework definitions, then computes which categories have mapped rules. It does NOT require a scan — it answers "what can we detect?" not "what did we find?".

**Alternatives considered**:
- **Require a prior scan result**: Coverage based on actual findings rather than rule mappings. Useful but conflates "detection capability" with "scan results" — and requires a scan artifact.

**Rationale**: Per the spec, coverage percentage = `(categories with ≥1 mapped rule) / (total categories) × 100`. This is rule-level metadata, not finding-level. The command should execute in < 2 seconds (SC-C07) — loading ~63 rules and 4 framework definitions is instantaneous. The JSON report's `compliance_summary` section provides the findings-based view.

## Risks / Trade-offs

**[Manual curation burden]** → All 27 security rules + applicable secrets rules need hand-crafted compliance mappings across up to 4 frameworks. Mitigation: CWE-based auto-mapping (D4) provides a starting point; explicit mappings only needed for overrides or rules without CWE IDs.

**[Framework version lock-in]** → Embedded framework definitions are snapshot-in-time (OWASP 2021, PCI DSS 4.0). When standards update, Atlas must ship a new version. Mitigation: Framework definitions are separate YAML files — updating is a file edit, not a code change. Future spec can add user-defined frameworks.

**[Incomplete coverage reporting]** → Atlas only covers vulnerabilities detectable by static analysis. OWASP A05 (Security Misconfiguration) or NIST AC-2 (Account Management) can't be detected by SAST. Coverage report may show low percentages for inherently undetectable categories. Mitigation: Coverage output should distinguish "No Coverage" (no rules exist) from categories where SAST is inherently limited. Documentation should clarify that SAST is one layer of a defence-in-depth strategy.

**[Metadata size increase]** → Adding compliance arrays to 33 YAML files increases rule loading time marginally. Mitigation: compliance metadata is small (< 500 bytes per rule). With ~63 rules, total metadata increase is < 16 KB — negligible.

## Open Questions

_(none — the spec is detailed and all technical decisions are resolved above)_
