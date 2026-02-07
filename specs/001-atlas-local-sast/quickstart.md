# Quickstart: Atlas Local — Development Setup

**Feature Branch**: `001-atlas-local-sast`
**Date**: 2026-02-07

---

## Prerequisites

- **Rust toolchain**: stable (2024 edition) — install via [rustup](https://rustup.rs/)
- **C compiler**: required for tree-sitter grammar compilation (gcc/clang/MSVC)
- **Git**: for source checkout

```bash
# Verify Rust installation
rustup show
# Expected: stable-{arch} (default)

# Ensure 2024 edition support
rustc --version
# Expected: rustc 1.85+ (2024 edition support)
```

---

## Project Setup

```bash
# Clone and enter
cd /path/to/atlas-local

# Build the entire workspace
cargo build

# Run all tests
cargo test --workspace

# Build release binary
cargo build --release
# Binary at: target/release/atlas
```

---

## Workspace Layout

```
Cargo.toml                    # Workspace root
crates/
├── atlas-cli/                # Binary: CLI entry point
├── atlas-core/               # Library: scan engine orchestration
├── atlas-lang/               # Library: language adapters (tree-sitter)
├── atlas-rules/              # Library: rule system (declarative/rhai/cdylib)
├── atlas-analysis/           # Library: L1/L2/L3 analysis
├── atlas-policy/             # Library: policy evaluation & gating
├── atlas-report/             # Library: output formatters (JSON/SARIF/JSONL)
├── atlas-license/            # Library: licensing (node-locked/floating)
├── atlas-audit/              # Library: audit bundle generation
└── atlas-cache/              # Library: SQLite result caching
```

---

## First Scan

```bash
# Scan a project directory (default: Atlas JSON output)
atlas scan ./path/to/project

# Scan with specific output format
atlas scan --format sarif ./path/to/project

# Scan with multiple formats, write to directory
atlas scan --format json,sarif,jsonl --output ./reports/ ./path/to/project

# Scan specific languages only
atlas scan --lang typescript,java ./path/to/project

# Scan with policy enforcement
atlas scan --policy ./org-policy.yaml ./path/to/project

# Scan with baseline (incremental adoption)
atlas scan --baseline ./baseline.json ./path/to/project

# Control parallelism
atlas scan --jobs 4 ./path/to/project

# Disable caching
atlas scan --no-cache ./path/to/project

# Verbose output
atlas scan --verbose ./path/to/project

# Quiet mode (machine-readable only)
atlas scan --quiet ./path/to/project
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, all policy gates pass |
| `1` | Scan completed, one or more policy gates failed |
| `2` | Engine error (scan could not complete) |
| `3` | License validation failed |
| `4` | Configuration error (invalid config, missing target, etc.) |

---

## Rulepack Management

```bash
# Install a signed rulepack
atlas rulepack install ./security-rules-v2.pack

# List installed rulepacks
atlas rulepack list

# Rollback a rulepack to previous version
atlas rulepack rollback security-rules
```

---

## Baseline Management

```bash
# Create a baseline from current scan
atlas baseline create --output baseline.json ./path/to/project

# Show diff between current scan and baseline
atlas baseline diff --baseline baseline.json ./path/to/project
```

---

## License Management

```bash
# Activate a node-locked license
atlas license activate ./license.key

# Check license status
atlas license status

# Deactivate license
atlas license deactivate
```

---

## Audit

```bash
# Generate audit bundle for a scan
atlas audit bundle --scan-id <scan-id> --output ./audit/
```

---

## Configuration

```bash
# Show current configuration
atlas config show

# Validate configuration
atlas config validate

# Diagnostics (engine info, cache stats, license status)
atlas diag
```

---

## Development Workflow

```bash
# Build and test a specific crate
cargo test -p atlas-core
cargo test -p atlas-lang

# Run clippy (lint)
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all

# Run benchmarks
cargo bench -p atlas-cli

# Build for specific target
cargo build --release --target x86_64-unknown-linux-gnu
```

---

## Configuration File

Atlas looks for configuration in order:
1. CLI flags (highest priority)
2. `.atlas.yaml` in scan target directory
3. `.atlas.yaml` in user home directory
4. Built-in defaults

```yaml
# .atlas.yaml example
scan:
  languages: [typescript, javascript, java, python, go, csharp]
  exclude_patterns:
    - "node_modules/**"
    - "vendor/**"
    - "dist/**"
    - "*.min.js"
  follow_symlinks: true
  max_file_size_kb: 1024

analysis:
  max_depth: L2          # L1, L2, or L3
  l3_call_depth: 5       # Max call chain depth for L3

cache:
  enabled: true
  max_size_mb: 500
  path: ~/.atlas/cache/

reporting:
  default_format: json
  timestamp: false        # Disabled for determinism

rulepacks:
  trusted_keys:
    - "base64-encoded-ed25519-public-key"
  store_path: ~/.atlas/rulepacks/
```
