# Atlas Local

A high-performance, offline-first static analysis security testing (SAST) tool built in Rust. Atlas scans source code for security vulnerabilities, secret leaks, and code quality issues using tree-sitter AST parsing with declarative YAML rules.

## Features

- **Multi-language support** -- TypeScript, JavaScript, Java, Python, Go, C#
- **63 built-in rules** -- 27 security, 6 secrets detection, 30 code quality
- **Declarative rules** -- YAML + tree-sitter S-expression patterns (L1)
- **Policy gating** -- Fail/warn thresholds by severity and category
- **Multi-format reports** -- JSON (Atlas Findings v1.0.0), SARIF v2.1.0, JSONL
- **Baseline management** -- Incremental adoption without alert fatigue
- **Result caching** -- SQLite-backed, skip unchanged files
- **Rulepack signing** -- Ed25519-signed rule distribution
- **Parallel scanning** -- Rayon-based multi-threaded file processing
- **Offline-first** -- No network calls required; runs entirely on-device

## Quick Start

### Build

```bash
cargo build --release
```

### Scan a project

```bash
# JSON output to stdout
./target/release/atlas scan ~/Projects/MyApp

# Multiple formats to organised directory
./target/release/atlas scan ~/Projects/MyApp --format json,sarif --output reports/
# -> reports/MyApp/20260208-220854/atlas-report.json
# -> reports/MyApp/20260208-220854/atlas-report.sarif

# Single file output
./target/release/atlas scan ~/Projects/MyApp --format json --output result.json

# Filter by language
./target/release/atlas scan ~/Projects/MyApp --lang typescript,python

# With custom policy
./target/release/atlas scan ~/Projects/MyApp --policy policy.yaml
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, all policy gates passed |
| 1 | One or more policy gates failed |
| 2 | Engine error |
| 3 | License validation failed |
| 4 | Configuration error |

## CLI Reference

```
atlas <COMMAND>

Commands:
  scan       Scan a project for security vulnerabilities
  config     Show/validate Atlas configuration
  rulepack   Manage signed rulepacks (install, list, rollback)
  baseline   Manage baselines for incremental adoption (create, diff)
  license    Manage Atlas licenses (activate, status, deactivate)
  audit      Generate signed audit bundles for compliance
  diag       Display diagnostic information
```

### `atlas scan`

```
atlas scan <TARGET> [OPTIONS]

Options:
  --format <FORMAT>      Output format(s): json, sarif, jsonl (comma-separated) [default: json]
  -o, --output <PATH>    Output directory or file path
  --policy <FILE>        Policy file for gate evaluation
  --baseline <FILE>      Baseline file for incremental adoption
  --lang <LANGUAGES>     Languages to scan (comma-separated)
  -j, --jobs <N>         Number of parallel jobs
  --no-cache             Disable result caching
  -v, --verbose          Enable verbose output
  -q, --quiet            Suppress all non-essential output
  --timestamp            Include timestamps in output
```

**Output path behaviour:**

| `--output` value | Behaviour |
|------------------|-----------|
| _(omitted)_ | stdout |
| `reports/` (directory) | `reports/{project}/{timestamp}/atlas-report.{ext}` |
| `result.json` (file) | Write directly to that file |

## Built-in Rules

| Language | Security | Quality | Total |
|----------|----------|---------|-------|
| TypeScript | 5 | 10 | 15 |
| Java | 4 | 7 | 11 |
| Python | 4 | 7 | 11 |
| Go | 3 | 6 | 9 |
| C# | 5 | 6 | 11 |
| Secrets | 6 | -- | 6 |
| **Total** | **27** | **36** | **63** |

### Security rules

SQL injection, command injection, path traversal, insecure deserialization, XSS, eval usage, hardcoded credentials, weak cryptography, and more.

### Quality rules

Empty catch blocks, TODO comments, console/debug logging residuals, type assertion abuse, bare exception handling, unused imports, magic numbers, and more.

### Secrets detection

API keys, private keys, AWS credentials, GitHub tokens, JWT secrets, generic high-entropy strings.

## Configuration

### `.atlas.yaml`

Place in your project root or home directory:

```yaml
scan:
  languages: [typescript, javascript, java, python, go, csharp]
  exclude_patterns:
    - "node_modules/**"
    - "vendor/**"
    - "dist/**"
  max_file_size_kb: 1024

cache:
  enabled: true
  max_size_mb: 500

reporting:
  default_format: json
```

### `.atlasignore`

Follows `.gitignore` syntax to exclude files from scanning:

```gitignore
tests/fixtures/
target/
dist/
vendor/
node_modules/
*.min.js
```

### Policy file

Define gate thresholds to fail or warn on findings:

```yaml
schema_version: "1.0.0"
name: my-project-policy
fail_on:
  critical: 0
  high: 5
warn_on:
  medium: 10
suppressions:
  - fingerprint: "abc123..."
    reason: "Accepted risk"
    expires: "2026-12-31"
```

## Project Structure

```
Atlas-Local/
├── crates/
│   ├── atlas-cli/          # CLI entry point (binary)
│   ├── atlas-core/         # Scan engine orchestration
│   ├── atlas-lang/         # Tree-sitter language adapters
│   ├── atlas-rules/        # Rule loading & rulepack management
│   ├── atlas-analysis/     # Finding model (L1/L2/L3)
│   ├── atlas-policy/       # Policy gating & baseline
│   ├── atlas-report/       # JSON, SARIF, JSONL formatters
│   ├── atlas-license/      # Node-locked license validation
│   ├── atlas-audit/        # Audit bundle generation
│   └── atlas-cache/        # SQLite result cache
├── rules/
│   └── builtin/            # 63 YAML rule definitions
│       ├── typescript/
│       ├── java/
│       ├── python/
│       ├── go/
│       ├── csharp/
│       └── secrets/
├── tests/
│   └── fixtures/           # Vulnerable code samples for testing
└── specs/                  # Feature specifications
```

## Development

### Prerequisites

- Rust stable toolchain (2024 edition, 1.85+)
- C compiler (for tree-sitter grammar compilation)

### Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo test --workspace         # Run all tests
cargo clippy --workspace       # Lint
cargo fmt --all                # Format
cargo bench                    # Benchmarks
```

### Writing rules

Rules are YAML files with tree-sitter S-expression patterns:

```yaml
id: atlas/security/typescript/sql-injection
name: SQL Injection via String Concatenation
severity: critical
category: security
language: TypeScript
cwe_id: CWE-89
pattern: |
  (call_expression
    function: (member_expression
      property: (property_identifier) @method
      (#match? @method "^(query|execute)$"))
    arguments: (arguments
      (template_string) @sql_template))
  @match
remediation: >
  Use parameterized queries instead of string concatenation.
```

Place in `rules/builtin/{language}/{rule-name}.yaml` with test fixtures at `rules/builtin/{language}/tests/{rule-name}/fail.{ext}` and `pass.{ext}`.

## License

Proprietary. See LICENSE for details.
