<!--
  Sync Impact Report
  ==================
  Version change: N/A (initial) -> 1.0.0
  Modified principles: N/A (initial creation)
  Added sections:
    - 9 Core Principles (I through IX)
    - Commercial Compliance (hard constraints)
    - Engineering Standards (quality gates, testing, error handling)
    - Governance (amendment procedure, versioning, compliance)
  Removed sections: N/A
  Templates requiring updates:
    - .specify/templates/plan-template.md — ✅ no update needed
      (Constitution Check section already generic; gates derived at
       fill-time from this constitution)
    - .specify/templates/spec-template.md — ✅ no update needed
      (template is feature-agnostic; constitution constraints apply
       at spec-fill-time)
    - .specify/templates/tasks-template.md — ✅ no update needed
      (task phases are generic; constitution-driven tasks added at
       fill-time)
    - .specify/templates/checklist-template.md — ✅ no update needed
    - .specify/templates/agent-file-template.md — ✅ no update needed
  Follow-up TODOs: none
-->

# Atlas Local Constitution

## Core Principles

### I. Code Never Leaves

All analysis MUST execute entirely on the engineer's local
workstation. No source code, AST fragments, findings containing
raw source, or any derivative that could reconstruct source code
SHALL be transmitted outside the machine boundary — not to cloud
services, not to telemetry endpoints, not to license servers.

Rationale: This is the foundational trust promise to customers in
defence, finance, healthcare, and government sectors where code
exfiltration is a regulatory and contractual impossibility.

### II. Complete Offline Self-Sufficiency

Every core capability (scanning, policy evaluation, reporting,
rule loading, caching, fingerprinting) MUST operate with zero
degradation in a fully air-gapped environment. Features that
require network access (e.g., floating license checkout) MUST
degrade gracefully and MUST NOT block local analysis.

Rationale: The product targets environments where internet access
is permanently unavailable — not temporarily offline. Design for
permanent air-gap as the baseline, not the exception.

### III. Vendor Independence

The product MUST NOT depend on, bind to, reference, or require
any external enterprise product, service, SDK, model, or CLI.
All interoperability MUST be achieved through open standards
(SARIF, JSON Schema, LSP, ed25519, mTLS). No vendor-specific
protocols, formats, or authentication flows are permitted.

Rationale: Customers in regulated industries cannot accept supply-
chain dependencies on third-party vendors for a security tool.
Vendor lock-in is a disqualifying procurement risk.

### IV. Machine-Readable First

All output formats MUST be designed for automated consumption as
the primary use case. Human-readable formats (terminal summaries,
HTML, PDF) are secondary and MUST NOT introduce information that
is absent from the machine-readable equivalents. Every report
MUST include a `schema_version` field and conform to a published
JSON Schema.

Rationale: The core differentiator is enabling enterprise AI code
agents, automated remediation pipelines, and governance platforms
to consume scan results without human mediation.

### V. Auditable Governance

Every policy change, rule update, exception grant, suppression,
and configuration modification MUST produce a traceable,
timestamped audit record. Audit bundles MUST NOT contain source
code plaintext unless explicitly configured by the enterprise.
All rule packs and updates MUST be cryptographically signed and
verified before loading.

Rationale: SOC 2, ISO 27001, and financial regulatory frameworks
require verifiable evidence chains. The product must produce
audit artifacts that satisfy external auditors without exposing
proprietary source code.

### VI. Modular Monolith / Single Binary

The product MUST compile to a single statically-linked binary
with zero external runtime dependencies. Internal architecture
MUST use explicit module boundaries (Rust crate workspace) but
MUST NOT introduce inter-process communication, microservices,
or sidecar processes for core functionality.

Rationale: Deployment to air-gapped, locked-down workstations
demands a single artifact with no dependency resolution at
install time. Operational simplicity is a hard requirement.

### VII. Deterministic & Reproducible Output

Given identical inputs (source files, rule pack version, engine
version, analysis configuration), the product MUST produce
byte-identical output (including finding order). Timestamps in
reports MUST be optional and disabled by default for
reproducibility. Random identifiers (UUIDs) MUST use
deterministic seeding when reproducibility mode is enabled.

Rationale: Reproducibility is required for audit verification,
regression testing, and baseline diffing. Non-deterministic
output undermines trust in automated gating decisions.

### VIII. Phased Analysis Depth

Analysis capabilities MUST be explicitly bounded into three
levels — L1 (Pattern), L2 (Intra-procedural), L3 (Inter-
procedural with bounded call-chain depth). Each rule MUST
declare its required analysis level. The engine MUST gracefully
degrade (not fail) when a rule's required level exceeds the
configured or available depth for a given language.

Rationale: Taint analysis engineering effort spans 10-50x
between L1 and full L3. Explicit levelling prevents scope creep,
enables phased delivery, and sets honest expectations with
customers about per-language analysis depth.

### IX. Rust-Only Core on Stable Toolchain

All production code MUST be written in Rust using the stable
toolchain (2024 edition). Nightly-only features are prohibited.
Third-party crates MUST be from the established ecosystem (see
Technology Stack in PRD). The scripting extension layer (rhai)
and tree-sitter grammars are the only sanctioned non-Rust
execution environments within the binary.

Rationale: Rust provides memory safety, deterministic resource
management, and zero-cost abstractions critical for a compiler-
frontend-class analysis engine. Stable-only policy ensures
reproducible builds across the CI matrix (3 OS x multi-arch).

## Commercial Compliance

The following constraints are **non-negotiable** and override any
conflicting technical decision:

- **No External AI/LLM Dependency**: The product MUST NOT
  integrate, call, require, or optionally support any external
  AI model, AI coding tool, LLM service, or agent platform.
  All analysis intelligence is rule-based and deterministic.

- **No Telemetry / Phone-Home**: The product MUST NOT transmit
  any data to any external endpoint. Crash reports, usage
  analytics, and update checks are all opt-in and require
  explicit enterprise configuration pointing to an internal
  endpoint.

- **Closed-Source Distribution**: The product is distributed as
  compiled binaries only. Source code, intermediate
  representations, and build artifacts MUST NOT be included in
  customer-facing packages.

- **License Enforcement Without Network**: Node-locked licensing
  MUST work entirely offline. Floating licensing requires only
  an internal (customer-operated) license server.

- **Cross-Platform Parity**: All core features MUST be available
  on Windows 10+ (x64), macOS 12+ (x64 + ARM64), and Linux
  (x64, glibc 2.31+). Platform-specific degradation MUST be
  documented and MUST NOT affect core scanning/reporting.

## Engineering Standards

### Testing Discipline

- Every rule MUST have positive and negative test cases.
- Fingerprint stability MUST be verified by four test categories:
  line-drift, unrelated-edit, rename-refactor, cross-version.
- Integration tests MUST cover end-to-end: scan -> report ->
  exit code.
- Benchmark tests (criterion) MUST run on reference repos
  (Small/Medium/Large) and MUST NOT regress beyond defined SLA.
- Cross-platform CI MUST build and run basic scans on all three
  target OS families.

### Error Handling

- Library crates MUST use `thiserror` for typed errors.
- Application/CLI code MUST use `anyhow` for error propagation.
- All errors MUST be structured (machine-parseable via
  `--output-format json`).
- Parse failures MUST NOT abort the scan; degraded analysis MUST
  continue on parseable subtrees.

### Versioning & Compatibility

- All external formats (JSON Schema, JSONL Schema, Policy
  Schema, Baseline Format, License Format) MUST carry a
  `schema_version` field following SemVer.
- Minor versions MUST be additive-only (backward compatible).
- Major version changes MUST provide a migration tool and a
  minimum 6-month deprecation period.
- Cache format is internal and carries no compatibility promise;
  it MUST self-invalidate on engine version change.
- Fingerprint algorithm changes MUST provide old-to-new mapping
  tooling.

### Logging & Observability

- Structured JSON logging via `tracing` crate is mandatory.
- Scan statistics (cache hit rate, parse failures, timing
  breakdown) MUST be included in every report's `stats` block.
- `atlas diag` MUST output engine version, rule pack version,
  license status, environment info, and cache statistics.

## Governance

This constitution is the authoritative source of non-negotiable
project constraints. It supersedes all other documentation when
conflicts arise.

### Amendment Procedure

1. Proposed amendments MUST be documented with rationale.
2. Amendments MUST be reviewed by at least the project lead.
3. Each amendment MUST include a migration plan for any
   downstream artifacts (specs, plans, tasks) affected.
4. Version MUST be incremented per the versioning policy below.

### Constitution Versioning

- **MAJOR**: Removal or incompatible redefinition of a principle.
- **MINOR**: Addition of a new principle or material expansion.
- **PATCH**: Wording clarification, typo fix, non-semantic edits.

### Compliance Review

- Every spec (`spec.md`) MUST reference this constitution and
  verify alignment before approval.
- Every plan (`plan.md`) MUST pass a Constitution Check gate
  before Phase 0 research begins.
- Every task list (`tasks.md`) MUST trace back to a principle
  for any compliance-related task.
- Pull requests MUST NOT merge if they introduce a violation of
  any principle defined herein.

**Version**: 1.0.0 | **Ratified**: 2026-02-07 | **Last Amended**: 2026-02-07
