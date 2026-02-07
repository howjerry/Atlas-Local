# Data Model: Atlas Local — Offline SAST Code Analysis Tool

**Feature Branch**: `001-atlas-local-sast`
**Date**: 2026-02-07

---

## Entity Relationship Overview

```text
┌──────────┐     1:N     ┌──────────┐     N:1     ┌──────────┐
│  Scan    │────────────▶│ Finding  │◀────────────│  Rule    │
└──────────┘             └──────────┘             └──────────┘
     │                        │                        │
     │ 1:1                    │                     N:1 │
     ▼                        │                        ▼
┌──────────┐                  │                  ┌──────────┐
│ Baseline │◀─ diff ──────────┘                  │ Rulepack │
└──────────┘                                     └──────────┘
     │
     │ 1:1                   ┌──────────┐
     └──────── policy ──────▶│  Policy  │
                             └──────────┘
┌──────────┐     1:1     ┌──────────┐
│  Scan    │────────────▶│  Audit   │
└──────────┘             │  Bundle  │
                         └──────────┘

┌──────────┐
│ License  │  (standalone, validated before scan)
└──────────┘
```

---

## Entities

### Finding

A detected issue in source code produced by rule evaluation against an AST.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `fingerprint` | `String` | SHA-256 hex of `rule_id + relative_path + normalized_snippet` | Unique within a scan. Stable across line drift. |
| `rule_id` | `String` | Identifier of the rule that produced this finding | Format: `atlas/{category}/{lang}/{name}` e.g. `atlas/security/typescript/sql-injection` |
| `severity` | `Severity` enum | Severity level | One of: `Critical`, `High`, `Medium`, `Low`, `Info` |
| `category` | `Category` enum | Finding category | One of: `Security`, `Quality`, `Secrets` |
| `cwe_id` | `Option<String>` | CWE identifier | Format: `CWE-{number}` e.g. `CWE-89`. Null for quality/secrets without CWE. |
| `file_path` | `String` | Relative path from scan root | Normalized with forward slashes, no leading `./` |
| `line_range` | `LineRange` | Start and end line/column | `{ start_line, start_col, end_line, end_col }` — 1-indexed |
| `snippet` | `String` | Source code snippet at finding location | Masked if `category == Secrets`. Max 10 lines. |
| `description` | `String` | Human-readable description of the issue | |
| `remediation` | `String` | Actionable guidance for fixing | |
| `analysis_level` | `AnalysisLevel` enum | Depth at which this finding was detected | One of: `L1`, `L2`, `L3` |
| `confidence` | `Confidence` enum | Detection confidence | One of: `High`, `Medium`, `Low` |
| `metadata` | `BTreeMap<String, Value>` | Extensible key-value metadata | Used for taint paths (L3), entropy scores (secrets), etc. |

**Validation Rules**:
- `fingerprint` must be a valid 64-char hex string.
- `line_range.start_line <= line_range.end_line`.
- If `start_line == end_line`, then `start_col <= end_col`.
- `snippet` must not contain unmasked secret values when `category == Secrets`.

**State Transitions** (in baseline context):
- `New` → finding not in baseline, counts against policy gates.
- `Baselined` → finding fingerprint exists in baseline, excluded from gate evaluation.
- `Resolved` → finding was in baseline but no longer detected (fixed).

---

### Rule

A detection pattern or logic unit that evaluates AST nodes to produce findings.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | `String` | Unique rule identifier | Format: `atlas/{category}/{lang}/{name}` |
| `name` | `String` | Human-readable rule name | |
| `description` | `String` | What the rule detects | |
| `severity` | `Severity` enum | Default severity | Can be overridden by policy |
| `category` | `Category` enum | Rule category | `Security`, `Quality`, `Secrets` |
| `language` | `Language` enum | Target language | `TypeScript`, `JavaScript`, `Java`, `Python`, `Go`, `CSharp` |
| `analysis_level` | `AnalysisLevel` enum | Required analysis depth | `L1`, `L2`, `L3` |
| `rule_type` | `RuleType` enum | Implementation type | `Declarative`, `Scripted`, `Compiled` |
| `pattern` | `Option<String>` | S-expression pattern for L1 declarative rules | Required when `rule_type == Declarative` |
| `script` | `Option<String>` | Rhai script path for scripted rules | Required when `rule_type == Scripted` |
| `plugin` | `Option<String>` | cdylib path for compiled rules | Required when `rule_type == Compiled` |
| `cwe_id` | `Option<String>` | Associated CWE | |
| `remediation` | `String` | Remediation guidance template | |
| `references` | `Vec<String>` | External reference URLs | OWASP, CWE links |
| `tags` | `Vec<String>` | Searchable tags | |
| `version` | `String` | Rule version (SemVer) | |

**Validation Rules**:
- Exactly one of `pattern`, `script`, `plugin` must be `Some`.
- `analysis_level` must match rule type: `L1` → Declarative allowed; `L2`/`L3` → Scripted or Compiled only.
- `language` must be a supported language enum variant.

---

### Rulepack

A signed, versioned bundle of rules for distribution.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | `String` | Rulepack identifier | e.g. `atlas-security-rules` |
| `version` | `String` | SemVer version | |
| `description` | `String` | Rulepack description | |
| `author` | `String` | Author/organization | |
| `created_at` | `String` | ISO 8601 creation timestamp | |
| `rules` | `Vec<Rule>` | Rules included in this pack | |
| `rule_count` | `u32` | Total number of rules | Must equal `rules.len()` |
| `signature` | `String` | Ed25519 signature (base64) over manifest SHA-256 | |
| `public_key` | `String` | Signing public key (base64) | Must match a trusted key |
| `checksum` | `String` | SHA-256 of the pack archive | |
| `min_engine_version` | `Option<String>` | Minimum Atlas engine version required | |

**Validation Rules**:
- `signature` must verify against `public_key` over the manifest content hash.
- `public_key` must be in the trusted keys store or match the built-in key.
- `rule_count == rules.len()`.
- All `rules[].id` must be unique within the pack.
- If `min_engine_version` is set, current engine version must satisfy it.

**State Transitions**:
- `Available` → pack file exists but not installed.
- `Installed` → rules extracted to local store, active for scans.
- `Archived` → previous version preserved for rollback.
- `Rejected` → signature verification failed, not installed.

---

### Policy

A YAML-defined set of gating thresholds for CI/CD integration.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `name` | `String` | Policy name | |
| `level` | `PolicyLevel` enum | Merge precedence level | `Organization`, `Team`, `Project`, `Local` |
| `fail_on` | `FailOnThresholds` | Severity thresholds for gate failure | |
| `warn_on` | `Option<WarnOnThresholds>` | Severity thresholds for warnings | |
| `category_overrides` | `Option<BTreeMap<Category, FailOnThresholds>>` | Per-category threshold overrides | |
| `baseline` | `Option<String>` | Path to baseline file | |
| `exclude_rules` | `Vec<String>` | Rule IDs to exclude from evaluation | |
| `include_rules` | `Vec<String>` | Rule IDs to exclusively include | |
| `schema_version` | `String` | Policy schema version | SemVer, e.g. `1.0.0` |

**FailOnThresholds**:
```rust
struct FailOnThresholds {
    critical: Option<u32>,  // Max allowed critical findings (default: 0)
    high: Option<u32>,      // Max allowed high findings (default: unlimited)
    medium: Option<u32>,    // Max allowed medium findings (default: unlimited)
    low: Option<u32>,       // Max allowed low findings (default: unlimited)
    info: Option<u32>,      // Max allowed info findings (default: unlimited)
    total: Option<u32>,     // Max allowed total findings (default: unlimited)
}
```

**Merge Rules** (specificity precedence: Local > Project > Team > Organization):
- For each threshold field, the most specific (lowest level) non-null value wins.
- `exclude_rules` and `include_rules` are unioned across all levels.
- `baseline` from the most specific level wins.

---

### Scan

A single execution of the analysis engine against a target directory.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | `String` | Deterministic scan ID | SHA-256 seed from target + engine version + config |
| `timestamp` | `Option<String>` | ISO 8601 scan start time | Omitted by default for determinism. Enabled via `--timestamp`. |
| `engine_version` | `String` | Atlas engine SemVer version | |
| `target_path` | `String` | Root directory that was scanned | Absolute path |
| `languages_detected` | `Vec<Language>` | Languages found in the target | |
| `files_scanned` | `u32` | Total files analyzed | |
| `files_skipped` | `u32` | Files skipped (unsupported, binary, parse error) | |
| `findings` | `Vec<Finding>` | All findings produced | Sorted: (file_path, start_line, start_col, rule_id) |
| `findings_count` | `FindingsSummary` | Count by severity | `{ critical, high, medium, low, info, total }` |
| `gate_result` | `GateResult` enum | Policy gate outcome | `Pass`, `Fail`, `Warn` |
| `gate_details` | `Option<GateDetails>` | Gate evaluation details | Which thresholds were breached |
| `policy_applied` | `Option<String>` | Policy file(s) used | |
| `baseline_applied` | `Option<String>` | Baseline file used | |
| `new_findings_count` | `Option<u32>` | Findings not in baseline | Only present if baseline used |
| `resolved_findings_count` | `Option<u32>` | Baseline findings no longer detected | Only present if baseline used |
| `stats` | `ScanStats` | Performance statistics | Cache hit rate, parse failures, timing breakdown |
| `rules_version` | `String` | Hash of all active rule versions | For cache invalidation |
| `config_hash` | `String` | Hash of scan configuration | For determinism verification |
| `schema_version` | `String` | Report schema version | `1.0.0` |

---

### Baseline

A snapshot of finding fingerprints for incremental adoption.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `scan_id` | `String` | ID of the scan that produced this baseline | |
| `created_at` | `String` | ISO 8601 creation timestamp | |
| `engine_version` | `String` | Engine version at creation | |
| `fingerprints` | `Vec<String>` | SHA-256 fingerprints of baselined findings | Sorted for determinism |
| `findings_count` | `u32` | Total baselined findings | Must equal `fingerprints.len()` |
| `metadata` | `BTreeMap<String, Value>` | Additional context | Target path, rules version, etc. |
| `schema_version` | `String` | Baseline schema version | `1.0.0` |

---

### License

An entitlement to use the tool.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `type` | `LicenseType` enum | License mode | `NodeLocked`, `Floating` |
| `license_id` | `String` | Unique license identifier | |
| `organization` | `String` | Licensed organization | |
| `expiry` | `String` | ISO 8601 expiration date | |
| `entitled_features` | `Vec<String>` | Features this license enables | e.g. `["scan", "l3_analysis", "audit"]` |
| `max_seats` | `Option<u32>` | Max concurrent users (floating only) | |
| `fingerprint` | `Option<String>` | Hardware fingerprint (node-locked only) | SHA-256 of MAC + hostname + OS |
| `server_url` | `Option<String>` | License server URL (floating only) | |
| `signature` | `String` | Ed25519 signature over license content | |
| `schema_version` | `String` | License format version | `1.0.0` |

**Validation Rules**:
- If `type == NodeLocked`: `fingerprint` must be `Some` and match current machine.
- If `type == Floating`: `server_url` must be `Some`.
- `expiry` must be in the future.
- `signature` must verify against the built-in Atlas public key.

---

### Audit Bundle

A tamper-evident archive for compliance review.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `scan_id` | `String` | ID of the associated scan | |
| `created_at` | `String` | ISO 8601 creation timestamp | |
| `engine_version` | `String` | Atlas engine version | |
| `report` | `Scan` | Full scan report (embedded) | |
| `rules_applied` | `Vec<RuleMetadata>` | Metadata of rules active during scan | Rule ID, version, analysis level |
| `policy` | `Option<Policy>` | Policy configuration used | |
| `config` | `BTreeMap<String, Value>` | Scan configuration snapshot | |
| `manifest` | `AuditManifest` | File checksums and metadata | |
| `signature` | `String` | Ed25519 signature over manifest | |
| `schema_version` | `String` | Audit bundle format version | `1.0.0` |

**AuditManifest**:
```rust
struct AuditManifest {
    files: BTreeMap<String, String>,  // filename -> SHA-256 checksum
    created_at: String,
    engine_version: String,
}
```

---

## Enums

```rust
enum Severity { Critical, High, Medium, Low, Info }
enum Category { Security, Quality, Secrets }
enum AnalysisLevel { L1, L2, L3 }
enum Confidence { High, Medium, Low }
enum Language { TypeScript, JavaScript, Java, Python, Go, CSharp }
enum RuleType { Declarative, Scripted, Compiled }
enum GateResult { Pass, Fail, Warn }
enum PolicyLevel { Organization, Team, Project, Local }
enum LicenseType { NodeLocked, Floating }
enum FindingStatus { New, Baselined, Resolved }
```

---

## Key Relationships

1. **Scan → Finding** (1:N): A scan produces zero or more findings.
2. **Rule → Finding** (1:N): Each finding is produced by exactly one rule.
3. **Rulepack → Rule** (1:N): Rules are distributed in rulepacks.
4. **Policy → Scan** (N:1): A policy is applied to a scan for gate evaluation.
5. **Baseline → Scan** (1:1): A baseline is created from a specific scan.
6. **Scan → Audit Bundle** (1:1): An audit bundle is generated for a specific scan.
7. **License** (standalone): Validated before any scan execution.
