# Tasks: Atlas Local — Offline SAST Code Analysis Tool

**Input**: Design documents from `/specs/001-atlas-local-sast/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Cargo workspace initialization and project skeleton

- [x] T001 Create Cargo workspace root with `[workspace]` and `[workspace.dependencies]` in `Cargo.toml`
- [x] T002 Create all 11 crate directories and their `Cargo.toml` files under `crates/` (atlas-cli, atlas-core, atlas-lang, atlas-rules, atlas-analysis, atlas-policy, atlas-report, atlas-license, atlas-audit, atlas-cache) — 10 library crates + 1 binary crate
- [x] T003 [P] Configure shared dependencies in workspace root `Cargo.toml`: serde, serde_json, thiserror, anyhow, tracing, sha2, BTreeMap re-exports
- [x] T004 [P] Add `.gitignore`, `.atlasignore` example, `rust-toolchain.toml` (stable), and `rustfmt.toml` at repository root
- [x] T005 [P] Create `tests/fixtures/typescript-vulnerable/` directory with sample TypeScript files containing known insecure patterns (SQL concatenation, `Function()` constructor, `innerHTML` assignment, eval usage) for acceptance testing

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core types, traits, and infrastructure that ALL user stories depend on

**CRITICAL**: No user story work can begin until this phase is complete

- [x] T006 Define shared enum types (Severity, Category, AnalysisLevel, Confidence, Language, RuleType, GateResult, PolicyLevel, LicenseType, FindingStatus) in `crates/atlas-core/src/lib.rs` with Serialize/Deserialize/Ord derives
- [x] T007 Implement Finding struct with all fields from data-model.md in `crates/atlas-analysis/src/finding.rs`, including content-based fingerprint computation (SHA-256 of rule_id + relative_path + normalized_snippet)
- [x] T008 [P] Implement LineRange struct with validation (start <= end) in `crates/atlas-analysis/src/finding.rs`
- [x] T009 Implement Rule struct with all fields from data-model.md in `crates/atlas-rules/src/lib.rs`, including validation (exactly one of pattern/script/plugin must be Some)
- [x] T010 [P] Implement LanguageAdapter trait in `crates/atlas-lang/src/adapter.rs` with methods: `language() -> Language`, `extensions() -> &[&str]`, `parse(source: &[u8]) -> Result<Tree>`, `configure_parser(parser: &mut Parser)`
- [x] T011 Implement TypeScript/JavaScript language adapter in `crates/atlas-lang/src/typescript.rs` using tree-sitter-typescript and tree-sitter-javascript grammars
- [x] T012 [P] Implement file discovery (directory walker) in `crates/atlas-core/src/scanner.rs` with .gitignore/.atlasignore respect, language detection by extension, symlink following with cycle detection, and binary file skipping
- [x] T013 [P] Implement configuration loading and merging (.atlas.yaml) in `crates/atlas-core/src/config.rs` with CLI > project > home > defaults precedence, using serde_yaml
- [x] T014 Implement L1 pattern matching engine in `crates/atlas-analysis/src/l1_pattern.rs` using tree-sitter Query and QueryCursor with S-expression pattern evaluation and capture extraction
- [x] T015 Implement declarative rule loader (YAML + S-expression) in `crates/atlas-rules/src/declarative.rs` that parses rule YAML files and creates tree-sitter Query objects for L1 evaluation
- [x] T016 Implement scan pipeline orchestrator in `crates/atlas-core/src/engine.rs` with phases: discover -> parse -> analyze L1 -> collect findings -> sort deterministically -> produce report
- [x] T017 [P] Implement structured tracing setup with JSON output via tracing crate in `crates/atlas-core/src/lib.rs`, configurable via --verbose/--quiet flags
- [x] T018 [P] Implement exit code enum and process exit logic (0=pass, 1=gate-fail, 2=engine-error, 3=license, 4=config) in `crates/atlas-cli/src/lib.rs`
- [x] T019 Create initial set of L1 declarative rules for TypeScript: sql-injection (CWE-89), xss-innerhtml (CWE-79), code-injection-eval (CWE-94), code-injection-function-constructor (CWE-94), path-traversal (CWE-22) as YAML files in `rules/builtin/typescript/`

**Checkpoint**: Foundation ready — core types, TypeScript parsing, L1 pattern matching, file discovery, and scan pipeline are functional

---

## Phase 3: User Story 1 — Run a Basic Security Scan on a Project (Priority: P1) MVP

**Goal**: Developer runs `atlas scan ./src` and receives Atlas Findings JSON v1.0.0 report with security findings, deterministic output, fully offline, with correct exit codes.

**Independent Test**: Run `atlas scan` on `tests/fixtures/typescript-vulnerable/`, verify findings JSON matches schema, run twice and compare for byte-identity, verify exit code.

### Implementation for User Story 1

- [x] T020 [US1] Implement Atlas Findings JSON v1.0.0 formatter in `crates/atlas-report/src/json.rs` per `contracts/atlas-findings-v1.schema.json`, including ScanMetadata, FindingsSummary, GateResult, ScanStats sections
- [x] T021 [US1] Implement Scan struct with deterministic ID generation (SHA-256 of target_path + engine_version + config_hash + rules_version) in `crates/atlas-core/src/engine.rs`
- [x] T022 [US1] Implement deterministic output guarantee: BTreeMap for all maps, sorted findings by (file_path, start_line, start_col, rule_id), optional timestamps (disabled by default), deterministic UUID seeding in `crates/atlas-report/src/json.rs`
- [x] T023 [US1] Implement `scan` CLI subcommand in `crates/atlas-cli/src/commands/scan.rs` using clap v4 with args: target path (positional), --format, --output, --policy, --baseline, --lang, --jobs, --no-cache, --verbose, --quiet, --timestamp
- [x] T024 [US1] Implement rayon-based parallel file processing in `crates/atlas-core/src/scanner.rs` with ThreadPoolBuilder for --jobs N support
- [x] T025 [US1] Implement main.rs entry point in `crates/atlas-cli/src/main.rs` wiring clap CLI to engine, connecting scan command to pipeline orchestrator, handling exit codes
- [x] T026 [US1] Implement progress indication with indicatif in `crates/atlas-cli/src/commands/scan.rs` (progress bar for file processing, respecting --quiet flag)
- [x] T027 [US1] Implement config subcommand (show/validate) in `crates/atlas-cli/src/commands/config.rs` for .atlas.yaml inspection
- [x] T028 [US1] Implement edge case handling: missing/empty target dir (exit 4), non-UTF-8 files (skip with warning), parse failures (log warning, continue), .gitignore/.atlasignore respect in `crates/atlas-core/src/scanner.rs`
- [x] T029 [US1] Wire end-to-end: `atlas scan ./src` -> discover files -> parse TypeScript -> run L1 rules -> produce Atlas JSON report -> stdout/file -> exit code. Validate against `tests/fixtures/typescript-vulnerable/`

**Checkpoint**: User Story 1 complete — `atlas scan` produces deterministic Atlas JSON reports for TypeScript projects with correct exit codes

---

## Phase 4: User Story 2 — Configure and Enforce Policy Gates in CI/CD (Priority: P1)

**Goal**: Security team defines policy YAML with severity thresholds, applies to scan, pipeline breaks on gate failure.

**Independent Test**: Create policy YAML with `fail_on: { critical: 0 }`, scan fixture with known critical finding, verify exit code 1 and `gate_result: FAIL` in report.

### Implementation for User Story 2

- [x] T030 [US2] Implement Policy struct with all fields from data-model.md in `crates/atlas-policy/src/policy.rs`, including FailOnThresholds, WarnOnThresholds, deserialization from YAML
- [x] T031 [US2] Implement policy YAML loading and validation against `contracts/policy-v1.schema.json` in `crates/atlas-policy/src/policy.rs`
- [x] T032 [US2] Implement multi-policy merge with specificity precedence (local > project > team > org) in `crates/atlas-policy/src/policy.rs`: most specific non-null threshold wins, exclude/include rules unioned
- [x] T033 [US2] Implement gate evaluation engine in `crates/atlas-policy/src/gate.rs`: compare findings counts against thresholds, produce GateResult (PASS/FAIL/WARN) with GateDetails showing which thresholds were breached
- [x] T034 [US2] Implement category-specific threshold overrides in `crates/atlas-policy/src/gate.rs` (security/quality/secrets can have different fail_on limits)
- [x] T035 [US2] Wire --policy flag in scan command to policy loading and gate evaluation in `crates/atlas-cli/src/commands/scan.rs`, include gate_result in report output
- [x] T036 [US2] Add default policy (fail on any Critical) applied when no --policy flag is provided, in `crates/atlas-policy/src/policy.rs`

**Checkpoint**: User Story 2 complete — policy-based gating with YAML config, merge precedence, and correct exit codes

---

## Phase 5: User Story 3 — Multi-Format Report Output (Priority: P1)

**Goal**: DevSecOps engineer gets scan results in Atlas JSON, SARIF v2.1.0, and JSONL formats simultaneously.

**Independent Test**: Run scan with `--format json,sarif,jsonl --output ./reports/`, validate each file against respective schema.

### Implementation for User Story 3

- [x] T037 [P] [US3] Implement SARIF v2.1.0 formatter in `crates/atlas-report/src/sarif.rs` with Rust structs mirroring OASIS schema: SarifReport, Run, Result, ReportingDescriptor, PhysicalLocation, mapping Atlas Finding to SARIF result, Rule to reportingDescriptor, Severity to level, CWE to relationships
- [x] T038 [P] [US3] Implement Atlas Events JSONL formatter in `crates/atlas-report/src/jsonl.rs` per `contracts/atlas-events-jsonl-v1.schema.json` with event types: scan_started, file_analyzed, finding_detected, gate_evaluated, scan_completed
- [x] T039 [US3] Implement report dispatcher in `crates/atlas-report/src/lib.rs` supporting multiple simultaneous formats (--format json,sarif,jsonl), output to files (--output dir) or stdout, with format auto-detection from extension
- [x] T040 [US3] Implement secret value masking in `crates/atlas-report/src/masking.rs`: mask function (first 4 + last 4 chars, `****` between), apply at serialization boundary to all output formats for findings with category=secrets
- [x] T041 [US3] Wire --format and --output flags in scan command to report dispatcher in `crates/atlas-cli/src/commands/scan.rs`

**Checkpoint**: User Story 3 complete — all three output formats work, secrets are masked, multi-format simultaneous output works

---

## Phase 6: User Story 4 — Manage and Update Rulepacks (Priority: P2)

**Goal**: Security engineer installs signed rulepacks, verifies signatures, manages versions with rollback.

**Independent Test**: Create a signed rulepack with test rules, install it, verify new rules are active, rollback, verify old rules restored.

### Implementation for User Story 4

- [x] T042 [US4] Implement Rulepack struct with all fields from data-model.md in `crates/atlas-rules/src/rulepack.rs`, including manifest deserialization per `contracts/rulepack-manifest-v1.schema.json`
- [x] T043 [US4] Implement ed25519 signature verification using ed25519-dalek in `crates/atlas-rules/src/rulepack.rs`: compute SHA-256 of manifest.json, verify_strict() against public key, reject tampered packs
- [x] T044 [US4] Implement rulepack install pipeline in `crates/atlas-rules/src/rulepack.rs`: extract .pack archive -> verify signature -> validate manifest -> extract rule files to local store (~/.atlas/rulepacks/) -> report count of rules added/updated
- [x] T045 [US4] Implement rulepack rollback in `crates/atlas-rules/src/rulepack.rs`: archive current version, restore previous version from archive, log rollback event
- [x] T046 [US4] Implement rulepack list (show installed packs with versions) in `crates/atlas-rules/src/rulepack.rs`
- [x] T047 [US4] Implement rhai scripting engine integration in `crates/atlas-rules/src/scripted.rs`: create sandboxed rhai Engine, register custom API (node.type(), node.text(), node.children(), scope.variables(), finding.emit()), compile rule scripts, evaluate against AST nodes
- [x] T048 [US4] Implement compiled rule (cdylib) plugin loading via stable ABI in `crates/atlas-rules/src/compiled.rs`: load shared library, call rule evaluation function with defined ABI contract
- [x] T049 [US4] Implement rule conflict resolution (newer rule replaces older, log WARNING) in `crates/atlas-rules/src/rulepack.rs`
- [x] T050 [US4] Implement `rulepack` CLI subcommand (install/list/rollback) in `crates/atlas-cli/src/commands/rulepack.rs` using clap v4
- [x] T051 [US4] Create a test rulepack build script in `tools/build-rulepack.sh` that generates a signed .pack file from a rules directory for testing purposes

**Checkpoint**: User Story 4 complete — signed rulepacks can be installed, verified, listed, and rolled back; rhai scripted rules are functional

---

## Phase 7: User Story 5 — Baseline Management for Incremental Adoption (Priority: P2)

**Goal**: Team establishes baseline of existing findings, CI only fails on new issues, resolved findings tracked.

**Independent Test**: Scan fixture, create baseline, add new vuln file, re-scan with baseline, verify only new finding counts against gate.

### Implementation for User Story 5

- [x] T052 [US5] Implement Baseline struct with all fields from data-model.md in `crates/atlas-policy/src/baseline.rs` per `contracts/baseline-v1.schema.json`
- [x] T053 [US5] Implement baseline creation in `crates/atlas-policy/src/baseline.rs`: collect all finding fingerprints from a scan, sort for determinism, write baseline JSON file
- [x] T054 [US5] Implement baseline diffing in `crates/atlas-policy/src/baseline.rs`: compare current findings against baseline fingerprints, classify each finding as New/Baselined/Resolved
- [x] T055 [US5] Integrate baseline with gate evaluation in `crates/atlas-policy/src/gate.rs`: when baseline provided, only count New findings against policy thresholds, include baseline_diff in report
- [x] T056 [US5] Implement `baseline` CLI subcommand (create/diff) in `crates/atlas-cli/src/commands/baseline.rs` using clap v4
- [x] T057 [US5] Wire --baseline flag in scan command to baseline loading and diff computation in `crates/atlas-cli/src/commands/scan.rs`

**Checkpoint**: User Story 5 complete — baseline create/diff works, gate evaluation respects baseline, resolved findings tracked

---

## Phase 8: User Story 6 — Multi-Language Project Scanning (Priority: P2)

**Goal**: Polyglot project scanned with single command, auto-detecting languages, applying language-specific rules.

**Independent Test**: Create `tests/fixtures/polyglot/` with TS+Java+Python files, run `atlas scan .`, verify findings for each language.

### Implementation for User Story 6

- [ ] T058 [P] [US6] Implement Java language adapter in `crates/atlas-lang/src/java.rs` using tree-sitter-java grammar (Tier 1: L1-L3)
- [ ] T059 [P] [US6] Implement Python language adapter in `crates/atlas-lang/src/python.rs` using tree-sitter-python grammar (Tier 2: L1-L2)
- [ ] T060 [P] [US6] Implement Go language adapter in `crates/atlas-lang/src/go.rs` using tree-sitter-go grammar (Tier 2: L1-L2)
- [ ] T061 [P] [US6] Implement C# language adapter in `crates/atlas-lang/src/csharp.rs` using tree-sitter-c-sharp grammar (Tier 3: L1)
- [ ] T062 [US6] Implement language auto-detection by file extension in `crates/atlas-lang/src/adapter.rs` with registry of all adapters, skipping unsupported files with INFO log
- [ ] T063 [US6] Wire --lang flag for language filtering in `crates/atlas-cli/src/commands/scan.rs` (only analyze specified languages)
- [ ] T064 [P] [US6] Create initial L1 declarative rules for Java: sql-injection, xss-jsp, insecure-deserialization, path-traversal as YAML in `rules/builtin/java/`
- [ ] T065 [P] [US6] Create initial L1 declarative rules for Python: sql-injection, command-injection, eval-usage, unsafe-deserialization as YAML in `rules/builtin/python/`
- [ ] T066 [US6] Create `tests/fixtures/polyglot/` with TypeScript, Java, and Python files containing known vulnerabilities for multi-language acceptance testing

**Checkpoint**: User Story 6 complete — multi-language scanning works for all 6 languages, auto-detection and --lang filtering functional

---

## Phase 9: User Story 7 — Secrets Detection with Masking (Priority: P3)

**Goal**: Detect hardcoded secrets via regex + entropy + context analysis, mask in all reports.

**Independent Test**: Plant known secrets (AWS key, API token, high-entropy string) in test files, scan, verify detection and masking.

### Implementation for User Story 7

- [ ] T067 [US7] Implement regex-based secret detection patterns in `crates/atlas-rules/src/declarative.rs`: AWS access keys (AKIA...), GitHub tokens (ghp_/gho_/ghs_), GCP keys, generic API key patterns, JWT tokens, connection strings with passwords
- [ ] T068 [US7] Implement Shannon entropy calculator in `crates/atlas-analysis/src/finding.rs`: compute bits-per-char entropy on candidate strings, flag strings >20 chars with entropy >4.5 bits/char
- [ ] T069 [US7] Implement contextual variable-name heuristics in `crates/atlas-analysis/src/finding.rs`: check if high-entropy string is assigned to variable matching suspicious names (api_key, secret, token, password, credential, auth)
- [ ] T070 [US7] Create secrets detection rules as L1 declarative rules in `rules/builtin/secrets/` for all supported languages
- [ ] T071 [US7] Implement .env.example and exclusion pattern skipping for secrets scanning in `crates/atlas-core/src/scanner.rs`
- [ ] T072 [US7] Create test fixture files with planted secrets in `tests/fixtures/secrets/` (AWS key, GitHub token, high-entropy api_key variable, .env.example)

**Checkpoint**: User Story 7 complete — secrets detected via regex + entropy + context, masked in all output formats

---

## Phase 10: User Story 8 — Licensing and Audit Bundle Generation (Priority: P3)

**Goal**: Enterprise license enforcement (node-locked/floating) and tamper-evident audit bundle generation.

**Independent Test**: Create test license file, verify status output, run scan, generate audit bundle, verify bundle signature and contents.

### Implementation for User Story 8

- [ ] T073 [US8] Implement License struct with all fields from data-model.md in `crates/atlas-license/src/validator.rs`, including deserialization and signature verification
- [ ] T074 [US8] Implement hardware fingerprint generation in `crates/atlas-license/src/node_locked.rs`: SHA-256 of sorted MAC addresses + hostname + OS identifier, deterministic across reboots
- [ ] T075 [US8] Implement node-locked license validation pipeline in `crates/atlas-license/src/node_locked.rs`: load license file -> verify ed25519 signature -> check expiry -> match hardware fingerprint -> check entitled features
- [ ] T076 [US8] Implement floating license client stub in `crates/atlas-license/src/floating.rs`: mTLS + JSON-RPC protocol for checkout/checkin/heartbeat, fail with exit code 3 if server unreachable
- [ ] T077 [US8] Integrate license validation before scan execution in `crates/atlas-core/src/engine.rs`: validate license -> proceed or exit code 3
- [ ] T078 [US8] Implement AuditBundle struct with all fields from data-model.md in `crates/atlas-audit/src/bundle.rs`, including AuditManifest with file checksums
- [ ] T079 [US8] Implement audit bundle generation in `crates/atlas-audit/src/bundle.rs`: collect scan report + rules applied + policy config + engine version -> compute manifest checksums -> sign manifest with ed25519 -> write signed archive
- [ ] T080 [US8] Implement `license` CLI subcommand (activate/status/deactivate) in `crates/atlas-cli/src/commands/license.rs`
- [ ] T081 [US8] Implement `audit` CLI subcommand (bundle) in `crates/atlas-cli/src/commands/audit.rs` with --scan-id and --output flags
- [ ] T082 [US8] Implement `diag` CLI subcommand in `crates/atlas-cli/src/commands/diag.rs` outputting engine version, rulepack version, license status, environment info, cache statistics

**Checkpoint**: User Story 8 complete — licensing enforcement works (node-locked and floating stub), audit bundles are generated with signatures

---

## Phase 11: Polish & Cross-Cutting Concerns

**Purpose**: Performance optimization, caching, L2/L3 analysis, and robustness improvements across all stories

- [ ] T083 [P] Implement SQLite-based result cache in `crates/atlas-cache/src/cache.rs`: cache key = SHA-256(file_content + rule_version_hash + config_hash), cache value = bincode-serialized Vec<Finding>, LRU eviction, self-invalidation on engine/rule version change
- [ ] T084 [P] Implement cache corruption detection and recovery in `crates/atlas-cache/src/cache.rs`: detect SQLITE_CORRUPT, log warning, delete cache file, proceed without cache
- [ ] T085 Integrate cache with scan pipeline in `crates/atlas-core/src/scanner.rs`: check cache before parsing, store results after analysis, respect --no-cache flag
- [ ] T086 [P] Implement L2 intra-procedural data flow analysis in `crates/atlas-analysis/src/l2_intraprocedural.rs`: build scope graph per function, track variable definitions and uses, identify data flow paths within function boundaries
- [ ] T087 [P] Implement L3 inter-procedural taint analysis in `crates/atlas-analysis/src/l3_interprocedural.rs`: build cross-file call graph, track taint sources/sinks across function boundaries with configurable call-depth limit
- [ ] T088 Integrate L2/L3 analysis phases into scan pipeline in `crates/atlas-core/src/engine.rs`: after L1, run L2 on files needing deeper analysis, then L3 for cross-file taint tracking
- [ ] T089 [P] Implement FindingsSummary computation (count by severity) and ScanStats (duration, cache hit rate, parse failures, timing breakdown) in `crates/atlas-core/src/engine.rs`
- [ ] T090 [P] Implement schema_version field in all output formats (Atlas JSON, SARIF, JSONL, Policy, Baseline, Audit Bundle) to satisfy Constitution IV
- [ ] T091 [P] Add edge case handling: max file size limit (skip files exceeding config), files with >1MB size warning, graceful degradation when analysis level exceeds language adapter capability
- [ ] T092 Run quickstart.md validation: verify all CLI commands documented in quickstart.md work as expected end-to-end
- [ ] T093 Verify determinism guarantee: run scan twice on same fixture, assert byte-identical output (SC-003)
- [ ] T094 Verify offline operation: run scan with network blocked, assert zero network calls (SC-005)
- [ ] T095 [P] Create positive and negative test case files for each TypeScript builtin rule in `rules/builtin/typescript/tests/`: each rule gets a `pass/` dir (code that should NOT trigger) and `fail/` dir (code that MUST trigger), per Constitution Testing Discipline
- [ ] T096 [P] Create positive and negative test case files for each Java builtin rule in `rules/builtin/java/tests/` and each Python builtin rule in `rules/builtin/python/tests/`, per Constitution Testing Discipline
- [ ] T097 [P] Create positive and negative test case files for each secrets detection rule in `rules/builtin/secrets/tests/`, per Constitution Testing Discipline
- [ ] T098 [P] Implement fingerprint stability test suite in `tests/integration/fingerprint_stability.rs` covering 4 categories: line-drift (insert lines above finding), unrelated-edit (change code elsewhere in file), rename-refactor (rename file), cross-version (verify fingerprint across engine versions), per Constitution Testing Discipline
- [ ] T099 [P] Create criterion benchmark suite in `tests/benchmarks/` with reference repos: small (~1K LOC), medium (~50K LOC), large (~500K LOC). Benchmarks MUST measure L1 scan time and MUST NOT regress beyond defined SLA (SC-002: 100K LOC < 30s), per Constitution Testing Discipline
- [ ] T100 [P] Configure cross-platform CI pipeline in `.github/workflows/ci.yml`: lint (clippy), format check (rustfmt), unit tests, integration tests on Linux x64 + macOS ARM64 + Windows x64; build release binary on all 3 platforms, per Constitution Testing Discipline (cross-platform CI MUST build and run basic scans on all three target OS families)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — **BLOCKS all user stories**
- **User Story 1 (Phase 3)**: Depends on Foundational — core MVP
- **User Story 2 (Phase 4)**: Depends on Foundational — can parallel with US1 but benefits from US1's report infrastructure
- **User Story 3 (Phase 5)**: Depends on Foundational + US1's JSON formatter as reference — can start after T020
- **User Story 4 (Phase 6)**: Depends on Foundational — independent from US1-3
- **User Story 5 (Phase 7)**: Depends on Foundational + US2's gate evaluation (T033) — builds on policy engine
- **User Story 6 (Phase 8)**: Depends on Foundational — language adapters are independent
- **User Story 7 (Phase 9)**: Depends on Foundational + US3's masking (T040) — builds on masking infrastructure
- **User Story 8 (Phase 10)**: Depends on Foundational — independent from other stories
- **Polish (Phase 11)**: Depends on all desired user stories being complete

### User Story Dependencies

- **US1 (P1)**: After Foundational -> no other story dependencies
- **US2 (P1)**: After Foundational -> independently testable, benefits from US1's report format
- **US3 (P1)**: After Foundational -> independently testable, needs masking for secrets
- **US4 (P2)**: After Foundational -> independently testable
- **US5 (P2)**: After Foundational -> needs gate evaluation from US2 (T033)
- **US6 (P2)**: After Foundational -> independently testable
- **US7 (P3)**: After Foundational -> needs masking from US3 (T040)
- **US8 (P3)**: After Foundational -> independently testable

### Within Each User Story

- Core structs/models before services/logic
- Services/engines before CLI wiring
- CLI wiring before end-to-end validation
- Story complete before moving to next priority

### Parallel Opportunities

- **Phase 1**: T003, T004, T005 can all run in parallel
- **Phase 2**: T008, T010, T012, T013, T017, T018 can run in parallel (different crates/files)
- **Phase 3+**: After Foundational, US1/US2/US4/US6/US8 can all start in parallel (no cross-story dependencies)
- **Phase 5**: T037 (SARIF) and T038 (JSONL) can run in parallel
- **Phase 8**: T058-T061 (language adapters) can all run in parallel; T064-T065 (rules) can run in parallel
- **Phase 11**: T083, T084, T086, T087, T089, T090, T091 can run in parallel

---

## Parallel Example: User Story 6

```bash
# Launch all language adapters in parallel (different files, no deps):
T058: "Implement Java adapter in crates/atlas-lang/src/java.rs"
T059: "Implement Python adapter in crates/atlas-lang/src/python.rs"
T060: "Implement Go adapter in crates/atlas-lang/src/go.rs"
T061: "Implement C# adapter in crates/atlas-lang/src/csharp.rs"

# Then launch rules in parallel:
T064: "Create Java L1 rules in rules/builtin/java/"
T065: "Create Python L1 rules in rules/builtin/python/"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T005)
2. Complete Phase 2: Foundational (T006-T019) — **CRITICAL: blocks everything**
3. Complete Phase 3: User Story 1 (T020-T029)
4. **STOP and VALIDATE**: `atlas scan tests/fixtures/typescript-vulnerable/` produces correct Atlas JSON
5. Deploy/demo: single-language TypeScript SAST scanner with L1 rules

### P1 Complete (Stories 1-3)

6. Complete Phase 4: User Story 2 (T030-T036) — policy gating
7. Complete Phase 5: User Story 3 (T037-T041) — multi-format output
8. **VALIDATE**: Full P1 feature set — scan + policy + multi-format

### P2 Expansion (Stories 4-6)

9. Stories 4, 5, 6 can proceed in parallel or sequentially
10. Each adds independent value: rulepacks, baselines, multi-language

### P3 Enterprise (Stories 7-8)

11. Secrets detection + licensing/audit for enterprise readiness

### Final Polish

12. Phase 11: Caching, L2/L3 analysis, edge cases, performance validation

---

## Notes

- [P] tasks = different files, no dependencies — safe to parallelize
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Total task count: 100
- All file paths are relative to repository root
- Constitution compliance is embedded in task design (no network calls, deterministic output, single binary, etc.)
