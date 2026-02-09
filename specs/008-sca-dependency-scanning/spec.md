# Feature Specification: Atlas Local — SCA Dependency Scanning

**Feature Branch**: `008-sca-dependency-scanning`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, finding model, policy gating, report formats)

## Overview & Scope

Atlas-Local currently analyses source code for vulnerabilities but does not inspect third-party dependencies. Software Composition Analysis (SCA) is essential for identifying known vulnerabilities (CVEs) in libraries and frameworks that comprise a significant portion of modern applications. This specification adds dependency lockfile parsing, offline vulnerability database matching, and integration with the existing finding/gate/report pipeline.

**Purpose**: Enable development teams to detect known vulnerabilities in third-party dependencies by parsing lockfiles and matching against a local CVE database, without requiring network access during scans.

**Scope**: Lockfile parsing for 6 ecosystems, offline SQLite vulnerability database, `atlas sca update-db` command, and SCA findings integrated into existing reports and gates.

**Exclusions** (deferred to future specs):
- License compliance scanning (see 009 for SBOM which overlaps)
- Transitive dependency resolution (only direct lockfile entries)
- Source-level reachability analysis (whether vulnerable code paths are actually called)
- Private registry support (npm Enterprise, Artifactory, etc.)
- Automatic dependency upgrade suggestions
- Real-time advisory feed (NVD API integration)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Discovers Vulnerable Dependencies (Priority: P1)

A developer runs `atlas scan ./` on a Node.js project. Atlas detects `package-lock.json`, parses it, and reports that `lodash@4.17.20` has a known prototype pollution vulnerability (CVE-2021-23337). The finding includes the CVE ID, CVSS score, affected version range, and fixed version.

**Why this priority**: Identifying known CVEs in dependencies is the primary SCA use case. Without this, teams must use separate tools for dependency scanning.

**Independent Test**: Create a `package-lock.json` with a known vulnerable dependency, ensure the vulnerability database contains the corresponding CVE, scan, and verify the SCA finding is produced with correct metadata.

**Acceptance Scenarios**:

1. **Given** a `package-lock.json` containing `lodash@4.17.20` and a database entry for CVE-2021-23337 affecting `lodash < 4.17.21`, **When** scanned, **Then** a finding is produced with `category: "sca"`, `severity` derived from CVSS, `metadata.cve_id: "CVE-2021-23337"`, `metadata.package: "lodash"`, `metadata.installed_version: "4.17.20"`, `metadata.fixed_version: "4.17.21"`.
2. **Given** a `package-lock.json` containing `express@4.18.2` with no known vulnerabilities, **When** scanned, **Then** no SCA finding is produced for that package.
3. **Given** a project with no lockfile, **When** scanned, **Then** no SCA analysis is performed and a debug-level log indicates "No lockfile found; skipping SCA."

---

### User Story 2 — DevOps Engineer Updates the Vulnerability Database (Priority: P1)

A DevOps engineer downloads an updated vulnerability database bundle and applies it using `atlas sca update-db ./vuln-db-2026-02.bundle`. The bundle is cryptographically signed to prevent tampering. Future scans use the updated database.

**Why this priority**: The vulnerability database must be updatable without upgrading Atlas itself. Without offline updates, the database becomes stale immediately.

**Independent Test**: Download a signed database bundle, run `atlas sca update-db`, verify the database is updated, and confirm a newly added CVE is detected in subsequent scans.

**Acceptance Scenarios**:

1. **Given** a valid signed database bundle, **When** `atlas sca update-db ./bundle.db` is run, **Then** the local database is replaced and a success message shows the new advisory count and timestamp.
2. **Given** a tampered (invalid signature) bundle, **When** `atlas sca update-db ./tampered.db` is run, **Then** the update is rejected with an error: "Invalid database signature."
3. **Given** no database exists yet, **When** Atlas is first installed, **Then** a bundled baseline database is included in the binary.

---

### User Story 3 — CI Pipeline Gates on Critical CVEs (Priority: P1)

A CI pipeline runs `atlas scan ./` and the policy is configured with `category_overrides: { sca: { critical: 0, high: 0 } }`. The gate fails if any dependency has a Critical or High severity CVE.

**Why this priority**: CI gating is the primary enforcement mechanism for dependency security. Without it, CVE detection is informational only.

**Independent Test**: Configure a policy with SCA thresholds, scan a project with a Critical CVE dependency, and verify the gate fails.

**Acceptance Scenarios**:

1. **Given** a policy with `category_overrides: { sca: { critical: 0 } }` and a dependency with a Critical CVE, **When** scanned, **Then** the gate result is `FAIL`.
2. **Given** a policy with `category_overrides: { sca: { critical: 0 } }` and only Low severity CVEs, **When** scanned, **Then** the gate passes.

---

### User Story 4 — Multi-Language Project with Multiple Lockfiles (Priority: P2)

A polyglot project has `package-lock.json` (Node.js), `Cargo.lock` (Rust), and `requirements.txt` (Python). Atlas detects and parses all three, producing SCA findings for vulnerable dependencies across all ecosystems.

**Why this priority**: Real-world projects often use multiple languages. Multi-lockfile support is essential but builds on the single-lockfile foundation.

**Independent Test**: Create a project with 3 lockfiles, each with at least one known vulnerable dependency, and verify findings from all 3 ecosystems appear in the report.

**Acceptance Scenarios**:

1. **Given** a project with `package-lock.json`, `Cargo.lock`, and `requirements.txt`, **When** scanned, **Then** dependencies from all 3 lockfiles are analysed.
2. **Given** multiple lockfiles in subdirectories, **When** scanned, **Then** Atlas discovers lockfiles recursively within the scan target directory.

---

### Edge Cases

- What happens when a lockfile has malformed JSON/TOML? A warning is logged for the malformed lockfile and scanning continues with other lockfiles.
- What happens when the vulnerability database is empty or missing? A warning is logged: "Vulnerability database not found; SCA findings will be empty. Run `atlas sca update-db` to install."
- What happens with pre-release versions (e.g., `1.0.0-beta.1`)? Pre-release versions are compared using semver pre-release ordering rules.
- What happens when a CVE has no CVSS score? Severity defaults to `Medium` and a note is added to the finding.
- What happens when multiple CVEs affect the same package? Each CVE produces a separate finding. They share the same `package` and `installed_version` but have different `cve_id` values.

## Requirements *(mandatory)*

### Functional Requirements

**Lockfile Parsing**

- **FR-S01**: Atlas MUST parse `package-lock.json` (npm, v2/v3 format) to extract dependency names and exact versions.
- **FR-S02**: Atlas MUST parse `Cargo.lock` (Rust) to extract crate names and versions.
- **FR-S03**: Atlas MUST parse `pom.xml` and `gradle.lockfile` (Java/Kotlin Maven/Gradle) to extract artifact coordinates and versions.
- **FR-S04**: Atlas MUST parse `go.sum` (Go) to extract module paths and versions.
- **FR-S05**: Atlas MUST parse `requirements.txt` and `Pipfile.lock` (Python) to extract package names and pinned versions.
- **FR-S06**: Atlas MUST parse `packages.lock.json` (NuGet/.NET) to extract package names and versions.
- **FR-S07**: Lockfile discovery MUST be automatic — when a lockfile is found in the scan directory (recursively), SCA analysis is triggered without a separate command.

**Vulnerability Database**

- **FR-S08**: Atlas MUST ship with a bundled baseline vulnerability database embedded in the binary or distributed alongside it.
- **FR-S09**: The vulnerability database MUST be stored as a SQLite file (< 100 MB) at a configurable path (default: `~/.atlas/vuln.db`).
- **FR-S10**: `atlas sca update-db <path>` MUST replace the local database with the provided bundle after verifying its Ed25519 signature.
- **FR-S11**: Each database entry MUST contain: CVE ID, affected ecosystem, package name, affected version range, fixed version (if known), CVSS v3 score, severity, and description.

**Vulnerability Matching**

- **FR-S12**: For each parsed dependency, Atlas MUST query the database for CVEs matching the ecosystem + package name + version.
- **FR-S13**: Version matching MUST use semantic versioning range comparison (via the `semver` crate) for npm, Cargo, and NuGet. Maven and Go use their own version schemes.
- **FR-S14**: Each matched CVE MUST produce a Finding with `category: "sca"`.

**Finding Model**

- **FR-S15**: A new `Category::Sca` enum variant MUST be added to the Category enum.
- **FR-S16**: SCA findings MUST include metadata: `cve_id`, `cvss_score`, `package_name`, `ecosystem`, `installed_version`, `fixed_version`, `advisory_url`.
- **FR-S17**: SCA finding severity MUST be derived from CVSS v3 score: Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9).

**Gate & Policy Integration**

- **FR-S18**: SCA findings MUST participate in gate evaluation under `category_overrides.sca`.
- **FR-S19**: Default gate behaviour (no `category_overrides.sca`) MUST evaluate SCA findings against global `fail_on` thresholds.

### Key Entities

- **Dependency**: A parsed third-party package. Key attributes: `name`, `version`, `ecosystem`, `lockfile_path`.
- **Ecosystem**: The package manager ecosystem. Values: `npm`, `cargo`, `maven`, `go`, `pypi`, `nuget`.
- **Vulnerability**: A database entry for a known CVE. Key attributes: `cve_id`, `ecosystem`, `package_name`, `affected_versions`, `fixed_version`, `cvss_score`, `severity`, `description`.
- **VulnDatabase**: The local SQLite vulnerability database. Key attributes: `path`, `advisory_count`, `last_updated`.
- **ScaFinding**: A finding for a vulnerable dependency. Extends `Finding` with SCA-specific metadata.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-S01**: All 6 lockfile formats are parsed correctly, extracting 100% of direct dependencies and their exact versions from a curated test corpus of 10 lockfiles.
- **SC-S02**: Vulnerability matching correctly identifies known CVEs with 100% recall on a test corpus of 20 known-vulnerable dependencies (zero false negatives).
- **SC-S03**: False positive rate is < 5% (version range matching produces no spurious matches on a test corpus of 50 safe dependencies).
- **SC-S04**: `atlas sca update-db` correctly validates Ed25519 signatures and rejects tampered bundles.
- **SC-S05**: SCA scan of a project with 500 dependencies completes in < 3 seconds (lockfile parsing + database queries).
- **SC-S06**: The bundled baseline database contains at least 10,000 advisories covering npm, PyPI, Cargo, Maven, Go, and NuGet ecosystems.
- **SC-S07**: All existing SAST tests pass without modification (zero regression from `Category::Sca` addition).

## Assumptions

- Lockfile formats are stable and well-documented (npm v2/v3, Cargo.lock v3, go.sum, etc.).
- The `semver` crate handles npm and Cargo version range semantics correctly.
- An Ed25519 key pair will be generated for signing database bundles (using `ed25519-dalek`, already a dependency).
- CVE data is sourced from public feeds (NVD, OSV, GitHub Advisory Database) and curated into the SQLite format offline.

## Scope Boundaries

**In Scope**:
- 6 lockfile parsers (npm, Cargo, Maven/Gradle, Go, Python, NuGet)
- Offline SQLite vulnerability database
- Ed25519-signed database update mechanism
- `atlas sca update-db` CLI command
- Automatic lockfile discovery during scans
- SCA findings with CVE/CVSS metadata
- `Category::Sca` enum variant
- Gate integration (`category_overrides.sca`)
- JSON/SARIF/JSONL report integration for SCA findings

**Out of Scope**:
- License scanning
- Transitive dependency resolution
- Source-level reachability analysis
- Private registry support
- Auto-upgrade suggestions
- Real-time NVD/OSV API queries
- SBOM generation (see spec 009)

## Implementation Notes

### Crate Structure

A new `atlas-sca` crate in the workspace:

```
crates/atlas-sca/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Public API
│   ├── lockfile/       # Lockfile parsers
│   │   ├── mod.rs
│   │   ├── npm.rs
│   │   ├── cargo.rs
│   │   ├── maven.rs
│   │   ├── go.rs
│   │   ├── python.rs
│   │   └── nuget.rs
│   ├── database.rs     # SQLite vulnerability database
│   ├── matcher.rs      # Version range matching
│   └── update.rs       # Database update + signature verification
```

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-rules/src/lib.rs` | Add `Category::Sca` variant |
| `crates/atlas-core/src/engine.rs` | Integrate SCA after SAST in scan pipeline |
| `crates/atlas-cli/src/commands/scan.rs` | Lockfile discovery and SCA invocation |
| `crates/atlas-cli/src/commands/mod.rs` | Register `sca` subcommand group |
| `crates/atlas-policy/src/gate.rs` | Support `category_overrides.sca` |
| `crates/atlas-report/src/json.rs` | SCA findings in JSON output |
| `crates/atlas-report/src/sarif.rs` | SCA findings in SARIF output |
| `Cargo.toml` (workspace) | Add `atlas-sca` to workspace members |

### Category Enum Impact

Adding `Category::Sca` affects the same files listed in the plan's "Category Enum Changes" section. If spec 012 (`Category::Iac`) is developed concurrently, both variants should be added in a single PR to avoid repeated breaking changes.

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `specs/009-sbom-generation/spec.md` | Downstream consumer of SCA dependency data |
| [OSV Schema](https://ossf.github.io/osv-schema/) | Vulnerability data format reference |
| [NVD API](https://nvd.nist.gov/developers/vulnerabilities) | CVE data source |
| [GitHub Advisory Database](https://github.com/advisories) | CVE data source |
| [semver crate](https://docs.rs/semver/) | Version range matching |
| [rusqlite](https://docs.rs/rusqlite/) | SQLite database access |
