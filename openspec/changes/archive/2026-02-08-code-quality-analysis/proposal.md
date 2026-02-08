## Why

Atlas-Local currently detects only security vulnerabilities and secrets (33 rules). Development teams using SAST tools expect code quality coverage — empty catch blocks, debug print residuals, type-safety gaps — alongside security findings in a single tool. Without quality rules, teams must maintain a separate linter pipeline for basic code hygiene. Adding 36 L1 declarative quality rules makes Atlas-Local a more complete static analysis solution with zero engine code changes.

## What Changes

- **36 new YAML quality rules** across 5 languages (TS 10, Java 7, Python 7, Go 6, C# 6) covering 6 quality domains: error-handling, debug-residual, type-safety, best-practices, performance, maintainability
- **72 new test fixtures** (fail + pass per rule) validating detection accuracy
- **Quality metadata** via explicit `metadata.quality_domain` in each rule YAML, plumbed through to findings
- **Independent quality gating** leveraging the existing `category_overrides.quality` policy mechanism
- **SARIF level mapping**: quality findings use `warning`/`note` (not `error`) to differentiate from security
- **Test count assertion updates** in `declarative.rs` for all 5 languages (the only Rust file modified)

## Capabilities

### New Capabilities
- `quality-rules`: 36 declarative YAML quality rules with tree-sitter patterns, test fixtures, and quality-domain metadata across TypeScript, Java, Python, Go, and C#

### Modified Capabilities
_(none — the existing engine, policy gate, and report formats already support quality category without requirement changes)_

## Impact

- **Rules directory**: 108 new files under `rules/builtin/{language}/` (36 YAML + 72 fixtures)
- **Test assertions**: 1 file modified (`crates/atlas-rules/src/declarative.rs`) — bump per-language rule counts
- **Engine / Policy / Report crates**: No code changes — L1 engine is category-agnostic, gate already handles `category_overrides.quality`, report formats already emit `category` field
- **Performance**: ~30% more rules to evaluate; target < 40s for 100K-line polyglot project (vs 30s baseline)
- **Dependencies**: None — all rules use existing tree-sitter grammars already in the workspace
