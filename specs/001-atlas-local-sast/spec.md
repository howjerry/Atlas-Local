# Feature Specification: Atlas Local — Offline SAST Code Analysis Tool

**Feature Branch**: `001-atlas-local-sast`
**Created**: 2026-02-07
**Status**: Draft
**Input**: User description: "Atlas Local — a commercial, closed-source, offline-first static application security testing (SAST) tool built in Rust. Provides security vulnerability detection, code quality analysis, secrets detection, and policy-based gating with deterministic machine-readable reports for enterprise CI/CD pipelines in restricted (air-gapped) environments."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a Basic Security Scan on a Project (Priority: P1)

A developer wants to scan their project source code for security vulnerabilities. They invoke `atlas scan ./src` from the command line and receive a structured report listing all findings with severity, location, description, and remediation guidance. The scan runs entirely offline with no network calls.

**Why this priority**: This is the core value proposition — without the ability to scan code and produce findings, nothing else matters. Every other feature builds on top of this capability.

**Independent Test**: Can be fully tested by running `atlas scan` on a sample project directory and verifying that findings are produced in the default Atlas Findings JSON format with correct schema, severity levels, and file locations.

**Acceptance Scenarios**:

1. **Given** a project directory containing TypeScript files with known insecure patterns (e.g., SQL string concatenation, dynamic code execution via `Function()` constructor, `innerHTML` assignment), **When** the user runs `atlas scan ./src`, **Then** the tool produces findings in Atlas Findings JSON v1.0.0 format with severity, CWE mapping, file path, line range, and remediation text for each detected issue.
2. **Given** the same project directory scanned twice without changes, **When** the user compares the two report files, **Then** the reports are byte-identical (deterministic output).
3. **Given** an air-gapped machine with no network access, **When** the user runs `atlas scan ./src`, **Then** the scan completes successfully without any network calls or DNS lookups.
4. **Given** a scan completes, **When** the user inspects the CLI exit code, **Then** exit code is `0` if all policy gates pass, `1` if any gate fails, `2` for engine errors, `3` for license issues, `4` for config errors.

---

### User Story 2 - Configure and Enforce Policy Gates in CI/CD (Priority: P1)

A security team lead defines a policy YAML file specifying thresholds (e.g., "fail if any Critical findings exist", "fail if more than 5 High findings") and integrates `atlas scan --policy org-policy.yaml` into the CI pipeline. The pipeline breaks when the policy gate fails.

**Why this priority**: Policy gating is the primary enterprise differentiator — it transforms scan results into actionable CI/CD decisions and enables governance at scale.

**Independent Test**: Can be fully tested by creating a policy YAML with `fail_on` thresholds, scanning a project with known findings, and verifying the correct exit code and gate result in the report.

**Acceptance Scenarios**:

1. **Given** a policy YAML with `fail_on: { critical: 0, high: 5 }`, **When** the scan produces 1 Critical finding, **Then** the exit code is `1` and the report includes `"gate_result": "FAIL"` with details on which threshold was breached.
2. **Given** multiple policy files at different levels (org, team, project), **When** all are provided, **Then** they merge with specificity precedence: local > project > team > org.
3. **Given** a policy YAML with `baseline: ./baseline.json`, **When** the scan runs, **Then** only new findings (not in the baseline) are counted against gate thresholds.

---

### User Story 3 - Multi-Format Report Output (Priority: P1)

A DevSecOps engineer needs scan results in multiple formats: Atlas Findings JSON for their internal dashboard, SARIF for GitHub/VS Code integration, and JSONL events for their SIEM pipeline. They run `atlas scan --format json,sarif,jsonl --output ./reports/`.

**Why this priority**: Integration with existing toolchains requires flexible output formats. Without this, adoption is blocked by format incompatibility.

**Independent Test**: Can be tested by running a scan with `--format json,sarif,jsonl` and validating each output file against its respective schema (Atlas Findings JSON v1.0.0, SARIF v2.1.0, Atlas Events JSONL).

**Acceptance Scenarios**:

1. **Given** a scan with `--format sarif`, **When** the report is generated, **Then** it conforms to SARIF v2.1.0 schema and can be loaded in VS Code SARIF Viewer without errors.
2. **Given** a scan with `--format jsonl`, **When** the report is generated, **Then** each line is a valid JSON object with `event_type`, `timestamp`, `correlation_id`, and event-specific fields.
3. **Given** secrets are detected during the scan, **When** any report format is generated, **Then** all secret values are masked (only first 4 and last 4 characters shown) in every output format.

---

### User Story 4 - Manage and Update Rulepacks (Priority: P2)

A security engineer updates the organization's detection rules by installing a new signed rulepack. They run `atlas rulepack install ./security-rules-v2.pack` and the tool verifies the ed25519 signature, extracts the rules, and makes them available for subsequent scans. They can also rollback to a previous version if needed.

**Why this priority**: Rulepacks are the mechanism for distributing and updating detection logic. Without them, the tool cannot evolve its detection capabilities, but a hardcoded initial ruleset can serve as MVP.

**Independent Test**: Can be tested by creating a signed rulepack, installing it, running a scan that triggers a new rule, then rolling back and verifying the rule no longer triggers.

**Acceptance Scenarios**:

1. **Given** a valid signed rulepack file, **When** the user runs `atlas rulepack install ./rules.pack`, **Then** the tool verifies the ed25519 signature, extracts rules to the local store, and reports the number of rules added/updated.
2. **Given** a rulepack with a tampered signature, **When** the user attempts to install it, **Then** the tool rejects the rulepack with a clear error message about signature verification failure.
3. **Given** a rulepack has been installed, **When** the user runs `atlas rulepack rollback security-rules`, **Then** the previous version is restored and the rolled-back version is archived.
4. **Given** a rulepack contains both declarative (YAML + tree-sitter S-expression) and programmatic (rhai script) rules, **When** installed, **Then** both rule types are available and functional during scans.

---

### User Story 5 - Baseline Management for Incremental Adoption (Priority: P2)

A team adopting Atlas on a legacy codebase wants to establish a baseline of existing findings so that CI only fails on new issues. They run `atlas baseline create --output baseline.json` to snapshot current findings, then reference the baseline in subsequent scans.

**Why this priority**: Without baseline management, legacy codebases with many existing findings would always fail policy gates, making adoption impractical. This feature enables gradual remediation.

**Independent Test**: Can be tested by scanning a project, creating a baseline, adding a new vulnerability, re-scanning with the baseline, and verifying only the new finding is reported as a gate violation.

**Acceptance Scenarios**:

1. **Given** a project with 50 existing findings, **When** the user runs `atlas baseline create`, **Then** a baseline file is generated containing fingerprints of all 50 findings.
2. **Given** a baseline exists and a new vulnerability is introduced, **When** the user runs `atlas scan --baseline baseline.json`, **Then** the report shows the new finding as "new" and existing findings as "baselined", and only new findings count against policy gates.
3. **Given** a finding in the baseline is fixed, **When** a scan runs with the baseline, **Then** the fixed finding is reported as "resolved" in the diff summary.

---

### User Story 6 - Multi-Language Project Scanning (Priority: P2)

A developer working on a polyglot project (e.g., TypeScript frontend, Java backend, Python scripts) wants to scan the entire repository with a single command. Atlas automatically detects languages, loads appropriate tree-sitter grammars, and applies language-specific rules.

**Why this priority**: Real-world projects are multi-language. Supporting only a single language would severely limit the tool's value. However, individual language adapters can be delivered incrementally.

**Independent Test**: Can be tested by creating a project with files in multiple supported languages, running a scan, and verifying findings are produced for each language with appropriate language-specific rules applied.

**Acceptance Scenarios**:

1. **Given** a repository containing TypeScript, Java, and Python files, **When** `atlas scan .` is run, **Then** the tool detects all three languages, loads the corresponding tree-sitter grammars, and produces findings for each language.
2. **Given** an unsupported file type (e.g., `.rs` if Rust is not yet a supported target language), **When** encountered during scan, **Then** the file is skipped with an INFO-level log message and the scan continues without error.
3. **Given** the `--lang` flag is specified (e.g., `--lang typescript,java`), **When** the scan runs, **Then** only the specified languages are analyzed, other files are skipped.

---

### User Story 7 - Secrets Detection with Masking (Priority: P3)

A security auditor wants to detect hardcoded secrets (API keys, passwords, tokens) in the codebase. Atlas detects secrets using regex patterns, entropy analysis, and contextual analysis, and masks all secret values in reports to prevent accidental exposure.

**Why this priority**: Secrets detection is a valuable addition but builds on the same scanning infrastructure. It can be implemented as a specialized rule category after the core scanning engine is stable.

**Independent Test**: Can be tested by planting known secret patterns in test files, running a scan, and verifying secrets are detected and properly masked in all output formats.

**Acceptance Scenarios**:

1. **Given** a file containing a hardcoded AWS access key (`AKIA...`), **When** scanned, **Then** a finding is produced with `category: "secrets"` and the secret value is masked (showing only `AKIA****...****WXYZ`).
2. **Given** a file containing a high-entropy random string assigned to a variable named `api_key`, **When** scanned, **Then** the entropy + context analysis flags it as a potential secret.
3. **Given** a `.env.example` file or a file matching exclusion patterns, **When** scanned, **Then** it is skipped unless explicitly included via configuration.

---

### User Story 8 - Licensing and Audit Bundle Generation (Priority: P3)

An enterprise compliance officer needs to verify the tool's license status and generate an audit bundle for regulatory review. They run `atlas license status` to check validity and `atlas audit bundle --scan-id <id>` to produce a signed, tamper-evident archive of scan results, configuration, and metadata.

**Why this priority**: Licensing and audit capabilities are essential for enterprise sales and compliance but can be layered on after the core scanning and reporting capabilities are solid.

**Independent Test**: Can be tested by activating a license, verifying status output, running a scan, generating an audit bundle, and verifying the bundle's signature and contents.

**Acceptance Scenarios**:

1. **Given** a valid node-locked license file, **When** `atlas license status` is run, **Then** the output shows license type, expiry date, entitled features, and hardware fingerprint match status.
2. **Given** an expired or invalid license, **When** any scan command is run, **Then** the tool exits with code `3` and a descriptive error message.
3. **Given** a completed scan, **When** `atlas audit bundle --scan-id <id>` is run, **Then** a signed archive is produced containing the scan report, applied rules, policy configuration, engine version, and a manifest with checksums.

---

### Edge Cases

- What happens when a scan target directory does not exist or is empty? The tool should exit with code `4` (config error) and a descriptive message.
- How does the system handle files with mixed encodings (UTF-8 with embedded binary)? Non-UTF-8 files should be skipped with a warning unless they match a supported binary format.
- What happens when a tree-sitter grammar fails to parse a syntactically invalid file? The tool should log a warning, skip the file, and continue scanning remaining files.
- What happens when the cache database is corrupted? The tool should detect corruption, log a warning, delete the corrupted cache, and proceed without caching for the current run.
- How does the system handle symbolic links in the scan target? Symlinks should be followed by default with cycle detection; a `--no-follow-symlinks` flag disables this.
- What happens when a rulepack contains a rule ID that conflicts with an existing rule? The newer rule replaces the older one, and the event is logged as a WARNING.
- How does the tool handle scans of repositories with millions of files? The tool should respect `.gitignore` and `.atlasignore` patterns, and use rayon-based parallelism to process files concurrently across available CPU cores.
- What happens when the floating license server is unreachable in floating-license mode? The tool should fail with exit code `3` and suggest checking network connectivity or switching to a node-locked license.

## Requirements *(mandatory)*

### Functional Requirements

**Core Scanning Engine**

- **FR-001**: System MUST parse source files using tree-sitter to produce typed AST nodes for pattern matching and semantic analysis.
- **FR-002**: System MUST support three analysis depth levels: L1 (pattern matching via tree-sitter S-expression queries), L2 (intra-procedural data flow within a single function/method), and L3 (inter-procedural taint analysis across function boundaries with configurable call-depth limit).
- **FR-003**: System MUST implement a Language Adapter trait that encapsulates language-specific parsing, scoping, import resolution, and type inference stubs for each supported language.
- **FR-004**: System MUST support Tier 1 languages (TypeScript, JavaScript, Java) with full L1-L3 analysis coverage at launch.
- **FR-005**: System MUST support Tier 2 languages (Python, Go) with L1-L2 coverage at launch, with L3 as a roadmap item.
- **FR-006**: System MUST support Tier 3 languages (C#) with L1 coverage at launch.

**Detection Categories**

- **FR-007**: System MUST detect security vulnerabilities including but not limited to: injection flaws (SQL, command, code), XSS, path traversal, insecure deserialization, broken authentication patterns, sensitive data exposure, and SSRF.
- **FR-008**: System MUST detect code quality issues including but not limited to: unsafe type coercion, unused variables in security-critical paths, error handling anti-patterns, and resource leak patterns.
- **FR-009**: System MUST detect hardcoded secrets using a combination of regex patterns, Shannon entropy analysis, and contextual variable-name heuristics.
- **FR-010**: System MUST mask all detected secret values in every output format, showing only the first 4 and last 4 characters.

**Finding Model**

- **FR-011**: Each finding MUST include: unique fingerprint (v1 scheme: SHA-256 of `rule_id + relative_path + normalized_snippet`), rule ID, severity (Critical/High/Medium/Low/Info), category (security/quality/secrets), CWE ID (where applicable), file path, line range (start/end), code snippet, description, and remediation guidance.
- **FR-012**: Finding fingerprints MUST remain stable when lines are inserted or deleted above the finding location (content-based, not line-based).
- **FR-013**: System MUST produce deterministic output — identical inputs and configuration MUST produce byte-identical reports.

**Rules System**

- **FR-014**: System MUST support declarative rules defined in YAML with tree-sitter S-expression patterns for L1 matching.
- **FR-015**: System MUST support programmatic rules written in rhai scripting language for complex detection logic requiring L2/L3 analysis.
- **FR-016**: System MUST support compiled Rust plugin rules (cdylib) for performance-critical detections with a stable ABI contract.
- **FR-017**: System MUST package rules into signed rulepacks using ed25519 signatures with versioning and rollback capability.
- **FR-018**: System MUST verify rulepack signatures before installation and reject tampered packs.

**Policy & Gating**

- **FR-019**: System MUST support Policy-as-Code defined in YAML with `fail_on` severity thresholds, category-specific overrides, and baseline references.
- **FR-020**: System MUST merge multiple policy files with specificity precedence: local > project > team > organization.
- **FR-021**: System MUST produce a `gate_result` (PASS/FAIL/WARN) in every report based on policy evaluation.
- **FR-022**: System MUST support baseline files for incremental adoption, counting only new findings (not in baseline) against gate thresholds.

**Reporting**

- **FR-023**: System MUST output reports in Atlas Findings JSON v1.0.0 format as the default.
- **FR-024**: System MUST support SARIF v2.1.0 output format compatible with GitHub Code Scanning and VS Code SARIF Viewer.
- **FR-025**: System MUST support Atlas Events JSONL format for streaming ingestion into SIEM/log aggregation systems.
- **FR-026**: System MUST support writing reports to files (`--output`) or stdout, and support multiple simultaneous formats.

**CLI Interface**

- **FR-027**: System MUST provide a CLI interface using clap v4 with subcommands: `scan`, `rulepack` (install/list/rollback), `baseline` (create/diff), `license` (activate/status/deactivate), `audit` (bundle), and `config` (show/validate).
- **FR-028**: System MUST use defined exit codes: `0` (pass), `1` (gate fail), `2` (engine error), `3` (license invalid), `4` (config error).
- **FR-029**: System MUST provide human-readable progress indication (via indicatif) with `--quiet` and `--verbose` flags.

**Performance & Caching**

- **FR-030**: System MUST use rayon for parallel file processing across available CPU cores.
- **FR-031**: System MUST implement a file-level result cache using SQLite + bincode with LRU eviction, keyed on content hash, invalidated when rules or configuration change.
- **FR-032**: System MUST provide `--jobs N` flag to control parallelism and `--no-cache` flag to bypass caching.

**Licensing**

- **FR-033**: System MUST support node-locked licensing (hardware fingerprint: MAC + hostname + OS hash) and floating licensing (mTLS + JSON-RPC to a license server).
- **FR-034**: System MUST enforce license validation before scan execution and exit with code `3` on failure.

**Audit & Governance**

- **FR-035**: System MUST generate tamper-evident audit bundles containing scan report, applied rules, policy configuration, engine version, and a signed manifest.
- **FR-036**: System MUST emit structured tracing events for all significant operations using the `tracing` crate.

**Architecture**

- **FR-037**: System MUST be built as a single statically-linked binary (modular monolith) using Rust 2024 edition, stable toolchain, with no runtime network dependencies for core scanning functionality.

### Key Entities

- **Finding**: A detected issue in source code. Key attributes: fingerprint, rule_id, severity, category, CWE, file_path, line_range, snippet, description, remediation. Each finding belongs to a scan and is produced by a rule.
- **Rule**: A detection pattern or logic unit. Key attributes: id, name, severity, category, language, analysis_level (L1/L2/L3), pattern (S-expression or rhai script or cdylib reference). Rules belong to rulepacks.
- **Rulepack**: A signed, versioned bundle of rules. Key attributes: id, version, signature, rules list, metadata. Rulepacks are installed into the local rule store.
- **Policy**: A YAML-defined set of gating thresholds. Key attributes: fail_on (severity thresholds), category overrides, baseline reference, merge level (org/team/project/local).
- **Scan**: A single execution of the analysis engine against a target. Key attributes: id, timestamp, target_path, languages_detected, findings_count, gate_result, duration, engine_version.
- **Baseline**: A snapshot of finding fingerprints used for incremental adoption. Key attributes: scan_id, timestamp, fingerprints list, metadata.
- **License**: An entitlement to use the tool. Key attributes: type (node-locked/floating), expiry, entitled_features, hardware_fingerprint (for node-locked), server_url (for floating).
- **Audit Bundle**: A tamper-evident archive for compliance. Key attributes: scan_id, report, rules_applied, policy, engine_version, manifest_checksums, signature.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The tool detects at least 95% of OWASP Top 10 vulnerability patterns in supported Tier 1 languages when tested against the OWASP Benchmark or equivalent test suites.
- **SC-002**: A full L1 scan of a 100,000-line TypeScript project completes in under 30 seconds on a 4-core machine (excluding first-run cache population).
- **SC-003**: Identical scan inputs produce byte-identical report outputs 100% of the time (determinism guarantee).
- **SC-004**: All report outputs validate against their respective schemas (Atlas Findings JSON v1.0.0, SARIF v2.1.0, JSONL per-line JSON validity) with zero validation errors.
- **SC-005**: The tool operates fully offline with zero network calls during scan, report generation, and policy evaluation (verified via network tracing).
- **SC-006**: False positive rate is below 15% for L1 rules and below 10% for L2/L3 rules when tested against curated benchmark projects.
- **SC-007**: Cached re-scans (no file changes) complete in under 2 seconds regardless of project size.
- **SC-008**: The single binary size is under 50 MB for the primary target platform (Linux x86_64).
- **SC-009**: Memory usage stays below 2 GB when scanning a 1-million-line codebase at L2 depth.
- **SC-010**: All detected secrets are masked in every output format with zero instances of unmasked secret values in reports.
- **SC-011**: Rulepack signature verification correctly rejects 100% of tampered packages in testing.
- **SC-012**: The tool handles projects with 10,000+ files without crashes, hangs, or degraded output quality.

## Assumptions

- The target deployment environment has Rust stable toolchain available for building from source, or pre-built binaries are distributed for supported platforms (Linux x86_64, macOS ARM64/x86_64, Windows x86_64).
- Tree-sitter grammars for all Tier 1 languages are available and can be statically linked into the binary.
- The ed25519 signing key for rulepacks is managed externally (key management is out of scope for the tool itself).
- Floating license server infrastructure is provided separately; only the client-side protocol is in scope.
- The hardware fingerprint algorithm for node-locked licenses is deterministic across reboots on the same machine.

## Scope Boundaries

**In Scope**:
- CLI tool for offline SAST scanning with L1/L2/L3 analysis depths
- Multi-language support via tree-sitter (TypeScript, JavaScript, Java, Python, Go, C# at varying tiers)
- Declarative, programmatic (rhai), and compiled (cdylib) rule types
- Signed rulepack distribution and management
- Policy-as-Code with YAML-based gating
- Baseline management for incremental adoption
- SARIF, JSON, JSONL report formats
- Node-locked and floating license enforcement
- Audit bundle generation
- SQLite-based result caching

**Out of Scope**:
- LSP server for IDE integration (tower-lsp) — deferred to a future release; core CLI must be stable first
- Web UI or dashboard (integrations consume reports via JSON/SARIF)
- SaaS/cloud deployment (this is an offline-first tool)
- Source code management or version control integration (beyond `.gitignore` respect)
- Automated code remediation or fix application
- License server implementation (only client protocol is in scope)
- Custom tree-sitter grammar authoring tools
- Training or machine learning-based detection
