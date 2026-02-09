## Why

Atlas-Local currently performs full-project scans on every invocation. In large codebases (10,000+ files), this means developers wait minutes for results even when they've only changed a handful of files. CI pipelines waste compute scanning unchanged code on every PR. Diff-aware scanning limits analysis to files and lines modified since a given git reference, reducing scan time proportionally to the change size and enabling PR-level gating that only flags newly introduced issues.

## What Changes

- Add `--diff <git-ref>` CLI flag to restrict scanning to files changed relative to any git reference (branch, tag, commit SHA, `HEAD`, `HEAD~N`)
- Compute changed files via `git diff --name-only --diff-filter=ACM` and changed line ranges via `@@` hunk header parsing
- Pre-filter discovered files in the scan engine so only changed files are parsed and analyzed
- Attribute each finding with `diff_status`: `new` (on a changed line) or `context` (on an unchanged line in a changed file)
- Add `--diff-gate-mode {all|new-only}` flag to control whether gate evaluation counts all findings in changed files or only newly introduced ones
- Include `diff_context` summary section in JSON reports and `diff_status` per finding in JSON, SARIF, and JSONL outputs
- Gracefully handle non-git directories (warning + full scan fallback) and missing `git` binary (hard error)

## Capabilities

### New Capabilities

- `diff-aware-scanning`: Git diff computation, changed-file filtering, changed-line attribution, diff-aware gate evaluation, and diff context in reports

### Modified Capabilities

_(none — existing scan, gate, and report capabilities retain current behavior; diff-aware fields are additive and optional)_

## Impact

- **CLI** (`atlas-cli`): New `--diff` and `--diff-gate-mode` flags on the `scan` command
- **Core** (`atlas-core`): New `diff.rs` module for git diff computation; `engine.rs` modified to pre-filter files when diff context is present; `ScanOptions` gains `diff_context` field
- **Analysis** (`atlas-analysis`): `Finding` struct gains `diff_status: Option<DiffStatus>` field; L1 engine checks finding line ranges against hunk ranges
- **Policy** (`atlas-policy`): `gate.rs` filters findings by `diff_status` in `new-only` mode
- **Report** (`atlas-report`): JSON report gains `diff_context` section; SARIF gains `diff_status` in result properties; JSONL includes `diff_status` per line
- **Dependencies**: No new crate dependencies — uses `std::process::Command` to invoke `git` CLI
- **Backwards compatibility**: All changes are additive; existing full-scan behavior is unchanged; new report fields are optional
