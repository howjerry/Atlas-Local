# Feature Specification: Atlas Local — SBOM Generation

**Feature Branch**: `009-sbom-generation`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 008-sca-dependency-scanning (lockfile parsers, dependency model, vulnerability database)

## Overview & Scope

Software Bill of Materials (SBOM) is increasingly required by regulations (US Executive Order 14028, EU Cyber Resilience Act) and procurement processes. Atlas-Local's SCA engine (spec 008) already parses lockfiles and identifies dependencies. This specification adds SBOM generation in CycloneDX v1.5 and SPDX v2.3 formats, reusing the parsed dependency data.

**Purpose**: Enable organisations to generate standards-compliant SBOMs from their projects' dependency lockfiles, satisfying regulatory requirements and supply chain transparency mandates.

**Scope**: CycloneDX JSON and SPDX JSON output formats. Reuses SCA dependency parsing — no lockfile re-parsing. Includes known vulnerabilities in the SBOM when the vulnerability database is available.

**Exclusions** (deferred to future specs):
- SBOM for source code components (only third-party dependencies)
- CycloneDX XML format (JSON only)
- SPDX tag-value format (JSON only)
- SBOM signing (CycloneDX supports it, but not in initial implementation)
- SBOM ingestion/comparison (consuming SBOMs from suppliers)
- VEX (Vulnerability Exploitability eXchange) document generation
- SBOM merge from multiple projects

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Generates CycloneDX SBOM (Priority: P1)

A developer runs `atlas sbom generate --format cyclonedx-json --output sbom.json` to produce a CycloneDX v1.5 SBOM for their project. The SBOM lists all dependencies parsed from lockfiles with package URLs (purl), versions, and optionally known vulnerabilities.

**Why this priority**: CycloneDX is the most widely adopted SBOM format, required by many enterprise procurement processes and government mandates.

**Independent Test**: Generate a CycloneDX SBOM for a project with `package-lock.json` and `requirements.txt`, validate the output against the CycloneDX v1.5 JSON schema, and verify all dependencies are listed with correct purl identifiers.

**Acceptance Scenarios**:

1. **Given** a project with `package-lock.json` containing 50 dependencies, **When** `atlas sbom generate --format cyclonedx-json --output sbom.json` is run, **Then** a valid CycloneDX v1.5 JSON file is produced with 50 components, each with `type: "library"`, `purl`, `name`, and `version`.
2. **Given** a vulnerability database with CVEs matching some dependencies, **When** the SBOM is generated, **Then** the `vulnerabilities` section includes matched CVEs with `id`, `source`, `ratings`, and `affects` referencing the vulnerable components.
3. **Given** `--output` is omitted, **When** the SBOM is generated, **Then** the output is written to stdout.

---

### User Story 2 — Compliance Team Generates SPDX SBOM (Priority: P1)

A compliance team needs an SPDX-formatted SBOM for regulatory submission. They run `atlas sbom generate --format spdx-json --output sbom.spdx.json` and receive an SPDX v2.3 document with package entries, relationships, and document creation information.

**Why this priority**: SPDX is the ISO/IEC 5962:2021 standard for SBOMs and is required by some government procurement processes alongside CycloneDX.

**Independent Test**: Generate an SPDX SBOM and validate it against the SPDX v2.3 JSON schema.

**Acceptance Scenarios**:

1. **Given** a project with dependencies, **When** `atlas sbom generate --format spdx-json` is run, **Then** a valid SPDX v2.3 JSON document is produced with `spdxVersion: "SPDX-2.3"`, `documentCreation` info, and `packages[]` for each dependency.
2. **Given** SPDX output, **When** inspected, **Then** each package has `SPDXID`, `name`, `versionInfo`, `externalRefs` with purl, and `downloadLocation`.

---

### User Story 3 — CI Pipeline Generates SBOM as Build Artifact (Priority: P2)

A CI pipeline generates an SBOM as a build artifact alongside the application binary. The SBOM is uploaded to an artifact registry for supply chain audit purposes.

**Why this priority**: CI integration is the primary production use case, but requires the generation engine (US1/US2) to work first.

**Independent Test**: Run SBOM generation in a CI script, verify the output file is created, and confirm it can be parsed by downstream SBOM tools.

**Acceptance Scenarios**:

1. **Given** a CI script running `atlas sbom generate --format cyclonedx-json --output dist/sbom.json`, **When** executed, **Then** the file is created at the specified path and is a valid CycloneDX document.
2. **Given** `--format` is not specified, **When** the command runs, **Then** the default format is `cyclonedx-json`.

---

### Edge Cases

- What happens when no lockfiles are found? The command produces an SBOM with zero components and a warning: "No lockfiles found; SBOM will contain no components."
- What happens when the vulnerability database is not installed? The SBOM is generated without the `vulnerabilities` section. A note is logged: "Vulnerability database not found; SBOM generated without vulnerability data."
- What happens with duplicate packages across lockfiles (e.g., `lodash` in npm and a wrapper in another ecosystem)? Each ecosystem's entry is listed separately with its ecosystem-specific purl.
- What happens with packages that have no purl mapping? The component is listed with `name` and `version` but `purl` is omitted. A warning is logged.

## Requirements *(mandatory)*

### Functional Requirements

**SBOM Command**

- **FR-B01**: Atlas MUST provide an `atlas sbom generate` subcommand for SBOM generation.
- **FR-B02**: The `--format` flag MUST support `cyclonedx-json` (default) and `spdx-json`.
- **FR-B03**: The `--output` flag MUST specify the output file path. If omitted, output MUST be written to stdout.
- **FR-B04**: The SBOM generator MUST reuse the lockfile parsers from the `atlas-sca` crate. No re-parsing of lockfiles is required.

**CycloneDX v1.5 Output**

- **FR-B05**: CycloneDX output MUST conform to the CycloneDX v1.5 JSON schema.
- **FR-B06**: Each dependency MUST be listed as a `component` with `type: "library"`, `name`, `version`, and `purl` (Package URL).
- **FR-B07**: The `metadata` section MUST include `tools` (Atlas tool info), `timestamp`, and `component` (the project being analysed).
- **FR-B08**: When a vulnerability database is available, matched CVEs MUST be included in the `vulnerabilities` section with `id`, `source`, `ratings[]`, and `affects[]`.
- **FR-B09**: The `dependencies` section SHOULD list top-level dependency relationships when lockfile data supports it.

**SPDX v2.3 Output**

- **FR-B10**: SPDX output MUST conform to the SPDX v2.3 JSON schema (`spdxVersion: "SPDX-2.3"`).
- **FR-B11**: Each dependency MUST be listed as a `package` with `SPDXID`, `name`, `versionInfo`, `downloadLocation`, and `externalRefs` containing the purl.
- **FR-B12**: The `documentCreation` section MUST include creator info (`Tool: Atlas`), creation date, and document namespace.
- **FR-B13**: Package `relationships` MUST include `DEPENDS_ON` relationships from the root package to each dependency.

**Package URL (purl)**

- **FR-B14**: Package URLs MUST follow the purl specification: `pkg:{ecosystem}/{name}@{version}`.
- **FR-B15**: Ecosystem mapping for purl MUST use: `npm`, `cargo`, `maven`, `golang`, `pypi`, `nuget`.

### Key Entities

- **SbomDocument**: The generated SBOM document. Key attributes: `format`, `metadata`, `components[]`, `vulnerabilities[]`.
- **SbomFormat**: The output format. Values: `CycloneDxJson`, `SpdxJson`.
- **SbomComponent**: A dependency entry in the SBOM. Key attributes: `name`, `version`, `purl`, `ecosystem`, `type`.
- **SbomVulnerability**: A known vulnerability entry (CycloneDX). Key attributes: `cve_id`, `source`, `ratings[]`, `affects[]`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-B01**: CycloneDX output validates against the CycloneDX v1.5 JSON schema with zero errors, tested on 5 projects of varying size.
- **SC-B02**: SPDX output validates against the SPDX v2.3 JSON schema with zero errors, tested on 5 projects.
- **SC-B03**: All dependencies from all parsed lockfiles appear in the SBOM (100% completeness).
- **SC-B04**: Package URLs are correctly formatted for all 6 ecosystems (npm, Cargo, Maven, Go, PyPI, NuGet).
- **SC-B05**: SBOM generation for a project with 500 dependencies completes in < 2 seconds (reusing parsed data).
- **SC-B06**: CycloneDX vulnerability section correctly matches CVEs from the local database to components.
- **SC-B07**: Generated SBOMs can be imported by at least 2 third-party SBOM tools (e.g., OWASP Dependency-Track, Anchore).

## Assumptions

- The SCA lockfile parsers (spec 008) are available and return `Vec<Dependency>` with accurate name, version, and ecosystem data.
- CycloneDX v1.5 and SPDX v2.3 JSON schemas are publicly available for validation.
- The purl specification is stable and covers all 6 target ecosystems.
- SBOM generation is a pure serialisation task (no network access, no lockfile parsing beyond what SCA already does).

## Scope Boundaries

**In Scope**:
- `atlas sbom generate` CLI subcommand
- CycloneDX v1.5 JSON output
- SPDX v2.3 JSON output
- Package URL (purl) generation for 6 ecosystems
- Vulnerability inclusion in CycloneDX (when database available)
- Dependency relationships in SPDX
- Stdout and file output options

**Out of Scope**:
- CycloneDX XML format
- SPDX tag-value format
- SBOM signing
- SBOM ingestion/comparison
- VEX document generation
- Source code component listing (only third-party dependencies)
- SBOM merge from multiple projects
- License field population (requires license scanning)

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `crates/atlas-sca/src/sbom.rs` | SBOM generation orchestration |
| `crates/atlas-sca/src/cyclonedx.rs` | CycloneDX v1.5 JSON serialisation |
| `crates/atlas-sca/src/spdx.rs` | SPDX v2.3 JSON serialisation |
| `crates/atlas-cli/src/commands/sbom.rs` | `atlas sbom generate` subcommand |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-cli/src/main.rs` | Register `sbom` subcommand group |

### Implementation Complexity

This is a low-complexity feature because:
1. All lockfile parsing is done by the SCA crate — SBOM just serialises the results
2. CycloneDX and SPDX are well-defined JSON schemas — serialisation is straightforward
3. No engine changes, no new analysis, no AST parsing
4. The main work is constructing the correct JSON structure with all required fields

## References

| Resource | Purpose |
|----------|---------|
| `specs/008-sca-dependency-scanning/spec.md` | Upstream dependency data source |
| [CycloneDX v1.5 Specification](https://cyclonedx.org/docs/1.5/) | CycloneDX schema reference |
| [SPDX v2.3 Specification](https://spdx.github.io/spdx-spec/v2.3/) | SPDX schema reference |
| [Package URL (purl) Specification](https://github.com/package-url/purl-spec) | purl format reference |
| [US Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/) | Regulatory context for SBOM requirements |
| [OWASP Dependency-Track](https://dependencytrack.org/) | SBOM consumer tool (validation target) |
