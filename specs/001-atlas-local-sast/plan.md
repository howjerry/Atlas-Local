# Implementation Plan: Atlas Local — Offline SAST Code Analysis Tool

**Branch**: `001-atlas-local-sast` | **Date**: 2026-02-07 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-atlas-local-sast/spec.md`

## Summary

Build a commercial, closed-source, offline-first static application security testing (SAST) CLI tool in Rust. The tool uses tree-sitter for multi-language AST parsing, supports three analysis depth levels (L1 pattern matching, L2 intra-procedural, L3 inter-procedural taint analysis), and produces deterministic machine-readable reports (Atlas JSON, SARIF v2.1.0, JSONL). It ships as a single statically-linked binary with signed rulepack distribution, policy-as-code gating, baseline management, node-locked/floating licensing, and audit bundle generation — all designed for air-gapped enterprise CI/CD environments.

## Technical Context

**Language/Version**: Rust 2024 edition, stable toolchain only (no nightly features)
**Primary Dependencies**: tree-sitter (AST parsing), clap v4 (CLI), rayon (parallelism), rhai (scripting rules), tracing (structured logging), indicatif (progress), ed25519-dalek (rulepack signing), rusqlite (cache), bincode (cache serialization), serde/serde_json/serde_yaml (serialization), thiserror (library errors), anyhow (CLI errors), criterion (benchmarks)
**Storage**: SQLite (file-level result cache with LRU eviction), filesystem (rulepacks, baselines, reports, audit bundles, license files)
**Testing**: `cargo test` (unit + integration), criterion (benchmarks), cross-platform CI (Linux x64, macOS x64+ARM64, Windows x64)
**Target Platform**: Linux x64 (glibc 2.31+), macOS 12+ (x64 + ARM64), Windows 10+ (x64) — single statically-linked binary per platform
**Project Type**: Single binary (modular monolith via Cargo workspace with internal crates)
**Performance Goals**: L1 scan of 100K LOC TypeScript < 30s on 4-core; cached re-scan < 2s; binary < 50MB; memory < 2GB for 1M LOC at L2
**Constraints**: Zero network calls for core scanning, deterministic byte-identical output, no external AI/LLM, no telemetry, offline-first as baseline
**Scale/Scope**: 1M+ LOC codebases, 10K+ files, 6 languages (3 tiers), signed rulepacks, enterprise licensing

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| # | Principle | Status | Evidence |
|---|-----------|--------|----------|
| I | Code Never Leaves | PASS | All analysis runs locally. No network calls in core scanning path. No source code transmitted. |
| II | Complete Offline Self-Sufficiency | PASS | Core scanning, policy evaluation, reporting, rule loading, caching all work air-gapped. Floating license degrades gracefully. |
| III | Vendor Independence | PASS | Uses open standards only: SARIF, JSON Schema, LSP, ed25519, mTLS. No vendor SDKs. |
| IV | Machine-Readable First | PASS | Atlas JSON v1.0.0 as default output. All formats have `schema_version`. SARIF/JSONL as secondary. |
| V | Auditable Governance | PASS | Signed rulepacks, audit bundles with checksums, structured tracing for all operations. |
| VI | Modular Monolith / Single Binary | PASS | Cargo workspace compiles to single statically-linked binary. No IPC/microservices. |
| VII | Deterministic & Reproducible Output | PASS | Content-based fingerprints, deterministic finding order, optional timestamps, deterministic UUID seeding. |
| VIII | Phased Analysis Depth | PASS | Explicit L1/L2/L3 levels. Rules declare required level. Engine degrades gracefully. |
| IX | Rust-Only Core on Stable Toolchain | PASS | Rust 2024 edition, stable only. Rhai + tree-sitter are sanctioned non-Rust environments. |
| — | No External AI/LLM | PASS | All analysis is rule-based and deterministic. No AI models. |
| — | No Telemetry | PASS | No phone-home. Crash reports/analytics are opt-in to internal endpoints only. |
| — | Cross-Platform Parity | PASS | Targets Linux, macOS (x64+ARM64), Windows. Platform degradation documented. |

**GATE RESULT: PASS** — No violations. Proceed to Phase 0.

## Project Structure

### Documentation (this feature)

```text
specs/001-atlas-local-sast/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── atlas-findings-v1.schema.json
│   ├── atlas-events-jsonl-v1.schema.json
│   ├── policy-v1.schema.json
│   ├── rulepack-manifest-v1.schema.json
│   └── baseline-v1.schema.json
└── tasks.md             # Phase 2 output (/speckit.tasks command)
```

### Source Code (repository root)

```text
Cargo.toml                    # Workspace root
crates/
├── atlas-cli/                # Binary crate — CLI entry point (clap v4)
│   └── src/
│       ├── main.rs
│       └── commands/         # scan, rulepack, baseline, license, audit, config
├── atlas-core/               # Library crate — scanning engine orchestration
│   └── src/
│       ├── engine.rs         # Scan pipeline: discover → parse → analyze → report
│       ├── scanner.rs        # File discovery, parallelism (rayon), caching
│       └── config.rs         # Configuration loading & merging
├── atlas-lang/               # Library crate — language adapters & tree-sitter
│   └── src/
│       ├── adapter.rs        # LanguageAdapter trait
│       ├── typescript.rs     # Tier 1: TypeScript/JavaScript adapter
│       ├── java.rs           # Tier 1: Java adapter
│       ├── python.rs         # Tier 2: Python adapter
│       ├── go.rs             # Tier 2: Go adapter
│       └── csharp.rs         # Tier 3: C# adapter
├── atlas-rules/              # Library crate — rule system
│   └── src/
│       ├── declarative.rs    # YAML + S-expression rule evaluation
│       ├── scripted.rs       # Rhai scripting engine integration
│       ├── compiled.rs       # cdylib plugin ABI
│       └── rulepack.rs       # Rulepack install/verify/rollback
├── atlas-analysis/           # Library crate — analysis depth levels
│   └── src/
│       ├── l1_pattern.rs     # L1: tree-sitter S-expression pattern matching
│       ├── l2_intraprocedural.rs  # L2: intra-procedural data flow
│       ├── l3_interprocedural.rs  # L3: inter-procedural taint analysis
│       └── finding.rs        # Finding model, fingerprinting, deduplication
├── atlas-policy/             # Library crate — policy evaluation & gating
│   └── src/
│       ├── policy.rs         # Policy loading, merging, evaluation
│       ├── baseline.rs       # Baseline creation, diffing
│       └── gate.rs           # Gate result computation (PASS/FAIL/WARN)
├── atlas-report/             # Library crate — output formatters
│   └── src/
│       ├── json.rs           # Atlas Findings JSON v1.0.0
│       ├── sarif.rs          # SARIF v2.1.0
│       ├── jsonl.rs          # Atlas Events JSONL
│       └── masking.rs        # Secret value masking
├── atlas-license/            # Library crate — licensing
│   └── src/
│       ├── node_locked.rs    # Hardware fingerprint licensing
│       ├── floating.rs       # mTLS + JSON-RPC floating licensing
│       └── validator.rs      # License validation pipeline
├── atlas-audit/              # Library crate — audit bundle generation
│   └── src/
│       └── bundle.rs         # Tamper-evident archive creation
└── atlas-cache/              # Library crate — result caching
    └── src/
        └── cache.rs          # SQLite + bincode, LRU eviction, content-hash keying

tests/
├── integration/              # End-to-end: scan → report → exit code
├── fixtures/                 # Test projects with known vulnerabilities
│   ├── typescript-vulnerable/
│   ├── java-vulnerable/
│   └── polyglot/
└── benchmarks/               # criterion benchmarks on reference repos
    ├── small/                # ~1K LOC
    ├── medium/               # ~50K LOC
    └── large/                # ~500K LOC
```

**Structure Decision**: Cargo workspace with 10 internal library crates + 1 binary crate. This follows the modular monolith principle (Constitution VI) — explicit module boundaries via crate-level isolation, but compiles to a single binary. Each crate has a focused responsibility aligned with the functional requirement groups in the spec.

## Complexity Tracking

> No Constitution Check violations — no entries needed.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| (none)    | —          | —                                   |
