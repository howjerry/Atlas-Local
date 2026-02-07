# Research: Atlas Local — Offline SAST Code Analysis Tool

**Feature Branch**: `001-atlas-local-sast`
**Date**: 2026-02-07
**Status**: Complete

---

## R1: Tree-sitter Rust Integration for Multi-Language AST Parsing

**Decision**: Use `tree-sitter` crate (latest stable) with statically-linked grammar crates per language.

**Rationale**:
- Tree-sitter provides incremental, error-tolerant parsing with a unified C API and first-class Rust bindings.
- The query system uses S-expression patterns with captures (`@name`), predicates (`#match?`, `#eq?`), and wildcards — directly supporting our L1 declarative rule format.
- `QueryCursor::matches()` returns pattern matches against a syntax tree, enabling rule evaluation by iterating captures.
- Grammars are available as separate crates: `tree-sitter-typescript`, `tree-sitter-javascript`, `tree-sitter-java`, `tree-sitter-python`, `tree-sitter-go`, `tree-sitter-c-sharp`.
- All grammars compile to static C libraries that link into the final binary — no runtime dependencies (Constitution II: offline self-sufficiency).

**Alternatives Considered**:
- **syn/quote (Rust-only AST)**: Only supports Rust. Not applicable for multi-language.
- **ANTLR4**: JVM-based runtime. Violates Constitution IX (Rust-only core).
- **Semgrep's approach (custom OCaml parser)**: Different language, not embeddable in Rust. Violates Constitution IX.
- **ast-grep**: Built on tree-sitter but is a separate CLI tool, not a library. We need library-level control for L2/L3 analysis.

**Key Implementation Notes**:
- Use `Parser::set_language()` to switch grammars per file.
- Use `Query::new(language, s_expression)` for L1 pattern rules.
- For L2/L3, walk the tree manually via `TreeCursor` and build scope/data-flow graphs from AST nodes.
- Tree-sitter is error-tolerant: partially-parsed files produce `ERROR` nodes that can be skipped (spec edge case: "parse failures MUST NOT abort the scan").

---

## R2: Cargo Workspace Architecture for Modular Monolith

**Decision**: Use a Cargo workspace with 10 library crates + 1 binary crate, all compiling to a single binary.

**Rationale**:
- Cargo workspaces provide: unified dependency resolution (shared `Cargo.lock`), shared build artifacts (single `target/` directory), and per-crate `cargo test` isolation.
- Crate boundaries enforce explicit module APIs via `pub` visibility — stronger than `mod` boundaries alone.
- All crates share the same `Cargo.lock`, preventing version drift (Constitution VI: single binary).
- The workspace root `Cargo.toml` defines shared dependency versions via `[workspace.dependencies]`.
- Since Cargo 1.90 (Sept 2025), workspace publishing is stable, but we don't publish crates — this is closed-source (Constitution: closed-source distribution).

**Alternatives Considered**:
- **Single crate with modules**: Simpler but loses enforced API boundaries. With 10+ domains (engine, rules, analysis, policy, reporting, licensing, audit, cache, languages), single crate becomes unmanageable.
- **Microservices/IPC**: Explicitly forbidden by Constitution VI.
- **Dynamic linking**: Violates Constitution VI (single statically-linked binary).

**Workspace Layout**:
```
[workspace]
members = [
  "crates/atlas-cli",
  "crates/atlas-core",
  "crates/atlas-lang",
  "crates/atlas-rules",
  "crates/atlas-analysis",
  "crates/atlas-policy",
  "crates/atlas-report",
  "crates/atlas-license",
  "crates/atlas-audit",
  "crates/atlas-cache",
]
```

---

## R3: SARIF v2.1.0 Output Compliance

**Decision**: Implement SARIF v2.1.0 output using `serde` serialization against the OASIS schema.

**Rationale**:
- SARIF v2.1.0 is the OASIS standard (published 2020, errata 2023) for static analysis results interchange.
- GitHub Code Scanning and VS Code SARIF Viewer both consume SARIF v2.1.0.
- The schema is publicly available at `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`.
- We define Rust structs mirroring the SARIF schema and derive `Serialize` — no external SARIF library needed (avoids unnecessary dependencies).

**Key SARIF Mappings**:
| Atlas Concept | SARIF Element |
|---|---|
| Finding | `result` |
| Rule | `reportingDescriptor` in `tool.driver.rules` |
| Severity | `result.level` (error/warning/note/none) |
| File + line range | `result.locations[].physicalLocation` |
| CWE | `reportingDescriptor.relationships[].target.id` |
| Remediation | `result.fixes[]` or `reportingDescriptor.helpUri` |
| Fingerprint | `result.fingerprints` |
| Scan metadata | `run.invocations[]` |

**Alternatives Considered**:
- **sarif-rs crate**: Exists but immature, low adoption. Rolling our own with serde is simpler and avoids an external dependency.
- **Protobuf/FlatBuffers**: Not an open standard for SAST results. Violates Constitution III (vendor independence).

---

## R4: Ed25519 Rulepack Signing with ed25519-dalek

**Decision**: Use `ed25519-dalek` crate (v2.x) for rulepack signing and verification.

**Rationale**:
- `ed25519-dalek` is the de-facto Rust ed25519 implementation. No unsafe code. Constant-time signing. Automatic key zeroing.
- Supports `verify_strict()` to reject weak keys — important for rulepack integrity (Constitution V: auditable governance).
- Key management is out of scope per spec assumptions — we only implement the verification side in the product; signing is done by the rulepack build pipeline.
- Batch verification available for future optimization if multiple rulepacks are verified simultaneously.

**Rulepack Format**:
- Rulepack = tarball (`.pack`) containing: `manifest.json` (metadata, version, rule list), rule files (YAML + rhai), and a detached `manifest.sig` (ed25519 signature over the manifest SHA-256 hash).
- Verification: compute SHA-256 of `manifest.json`, verify signature using the embedded public key or a configured trusted key.

**Alternatives Considered**:
- **ring**: Lower-level, more complex API. ed25519-dalek is simpler for our use case.
- **RSA signatures**: Larger key/signature sizes with no benefit for our use case. ed25519 is faster and simpler.
- **GPG/PGP**: Requires external tooling. Violates Constitution VI (single binary, no external dependencies).

---

## R5: Rhai Scripting for Programmatic Rules

**Decision**: Use `rhai` crate for L2/L3 programmatic rule scripting.

**Rationale**:
- Rhai is designed for embedding in Rust. JavaScript+Rust-like syntax. Sand-boxed execution with resource limits (stack depth, operation count, data size).
- Tight Rust integration: expose AST node types, scope information, and data-flow results as Rhai types via custom API registration.
- No unsafe code. Compile-once-run-many via AST caching.
- Sandboxing protects against malicious rule scripts (important for third-party rulepacks): stack overflow protection, runaway script limits, data size limits.
- Can register custom functions and types from Rust — we expose `AstNode`, `Scope`, `DataFlowGraph` etc.

**Script API Surface** (exposed to rule authors):
- `node.type()` — AST node type string
- `node.text()` — source text of the node
- `node.children()` — child nodes
- `node.parent()` — parent node
- `scope.variables()` — variables in scope
- `dataflow.taint_sources(node)` — L2/L3 taint sources reaching a node
- `finding.emit(severity, message, cwe)` — produce a finding

**Alternatives Considered**:
- **Lua (rlua/mlua)**: Mature but Lua syntax is less Rust-like. Rhai integrates more naturally.
- **WASM plugins**: Higher complexity, slower startup. Overkill for rule scripts.
- **Python (PyO3)**: Requires Python runtime. Violates Constitution VI (single binary).
- **Starlark**: Google's dialect. Less ecosystem support than rhai in Rust.

---

## R6: Parallelism Strategy with Rayon

**Decision**: Use `rayon` for CPU-bound parallel file processing. Use `--jobs N` to control thread pool size.

**Rationale**:
- Rayon provides work-stealing parallelism with minimal API surface: `.par_iter()` on file lists.
- File-level parallelism is the natural unit: each file is independently parsed and analyzed (L1/L2). L3 requires cross-file data, but the analysis graph can be built in parallel and resolved serially.
- The `ThreadPoolBuilder::new().num_threads(n).build_global()` controls parallelism via `--jobs N`.
- Overhead is negligible for file processing since each file involves parsing (milliseconds) — well above rayon's overhead threshold.

**Pipeline Architecture**:
1. **Discover**: Walk target directory, respect `.gitignore`/`.atlasignore`, filter by language — serial (fast, I/O bound).
2. **Parse + Analyze L1**: `par_iter()` over files — parallel. Each file: detect language → load grammar → parse → run L1 pattern rules → cache result.
3. **Analyze L2**: `par_iter()` over files with findings needing L2 — parallel. Build intra-procedural data flow per function.
4. **Analyze L3**: Build cross-file call graph — parallel graph construction, serial resolution. Run taint analysis with bounded call depth.
5. **Report**: Collect findings, sort deterministically, apply policy, format output — serial (must be deterministic).

**Alternatives Considered**:
- **tokio (async runtime)**: Designed for I/O-bound workloads. AST parsing is CPU-bound. Rayon is the better fit.
- **Manual threads**: Unnecessary complexity when rayon handles work-stealing.
- **crossbeam**: Lower-level than rayon. Rayon's `par_iter` is sufficient.

---

## R7: Deterministic Output Strategy

**Decision**: Enforce determinism through content-based fingerprints, sorted output, optional timestamps, and deterministic seeding.

**Rationale**:
- Constitution VII requires byte-identical output for identical inputs.
- Findings are sorted by: (file_path, start_line, start_col, rule_id) — a total order.
- Fingerprint v1: SHA-256 of `rule_id + relative_path + normalized_snippet` — content-based, stable across line insertions above the finding.
- Timestamps in reports are **disabled by default** (reproducibility mode). Enabled via `--timestamp` flag.
- UUIDs (scan ID, correlation ID) use deterministic seeding from: `SHA-256(target_path + engine_version + config_hash + rule_versions)`.
- `HashMap` iteration is non-deterministic in Rust — all collections that appear in output must use `BTreeMap` or be sorted before serialization.

**Alternatives Considered**:
- **Line-based fingerprints**: Fragile — inserting a blank line above a finding changes the fingerprint. Content-based is more robust.
- **Always include timestamps**: Breaks determinism. Optional timestamps are the compromise.

---

## R8: Caching Strategy with SQLite + Bincode

**Decision**: Use `rusqlite` for cache storage with `bincode` serialization of cached analysis results.

**Rationale**:
- SQLite is a single-file database, zero-config, works offline, and is battle-tested for embedded use.
- Cache key: `SHA-256(file_content) + rule_version_hash + config_hash`.
- Cache value: `bincode`-serialized `Vec<Finding>` for the file.
- LRU eviction: maintain a `last_accessed` timestamp column; evict oldest entries when cache exceeds configured size.
- Self-invalidation: store `engine_version` + `rulepack_version_hash` in cache metadata. On version mismatch, drop all entries.
- Corruption detection: wrap SQLite operations in a transaction. On `SQLITE_CORRUPT`, log warning, delete cache file, proceed without caching (spec edge case).

**Alternatives Considered**:
- **sled**: Rust-native embedded DB. Less mature than SQLite, no SQL query capability for diagnostics.
- **RocksDB**: Overkill for our use case. Larger binary size.
- **File-per-entry cache**: Doesn't scale to 10K+ files. No atomic invalidation.

---

## R9: Licensing Architecture

**Decision**: Two licensing modes — node-locked (offline) and floating (requires internal license server).

**Node-Locked**:
- Hardware fingerprint = SHA-256 of (sorted MAC addresses + hostname + OS identifier).
- License file = JSON with fields: `type`, `fingerprint`, `expiry`, `entitled_features`, `signature`.
- Signature verified with a hardcoded public key (ed25519).
- Deterministic across reboots on the same machine (assumption in spec).

**Floating**:
- Client connects to customer-operated license server via mTLS + JSON-RPC.
- Checkout: acquire seat. Checkin: release seat. Heartbeat: keep alive.
- If server unreachable: fail with exit code 3 (spec edge case).
- Network access is ONLY for license checkout — never for core scanning (Constitution I, II).

**Alternatives Considered**:
- **Dongle-based licensing**: Hardware dependency. Not practical for CI/CD runners.
- **Online activation**: Violates Constitution II (offline self-sufficiency).

---

## R10: Secret Masking Strategy

**Decision**: Mask all secret values in every output format, showing first 4 + last 4 characters with `****` in between.

**Implementation**:
- Masking is applied in `atlas-report` crate, at the serialization boundary — ensures all formats are covered.
- The `Finding` struct stores the raw match internally (for fingerprinting) but the `snippet` field exposed in reports goes through the masking pipeline.
- Masking function: if value length > 8, show `first4****last4`. If ≤ 8, show `****` (fully masked).
- Regex-based detection: curated patterns for AWS keys (`AKIA...`), GCP keys, GitHub tokens, JWTs, generic API keys, passwords in connection strings.
- Entropy-based detection: Shannon entropy > 4.5 bits/char on strings > 20 chars assigned to suspicious variable names (`api_key`, `secret`, `token`, `password`, etc.).

**Alternatives Considered**:
- **No masking (rely on user caution)**: Violates FR-010 and SC-010. Secrets in reports are a data leak risk.
- **Full redaction (show nothing)**: Loses context for remediation. First/last 4 chars aid identification.
