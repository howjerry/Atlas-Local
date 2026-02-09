## 1. Core diff types and git integration

- [x] 1.1 Create `crates/atlas-core/src/diff.rs` with `DiffStatus` enum (`New`, `Context`), `HunkRange` struct (`start_line: u32`, `line_count: u32`), `ChangedFile` struct (`path`, `change_type`, `hunks: Vec<HunkRange>`), and `DiffContext` struct (`git_ref`, `changed_files: Vec<ChangedFile>`, `is_fallback: bool`)
- [x] 1.2 Implement `compute_diff(target: &Path, git_ref: &str) -> Result<DiffContext>` using `std::process::Command` to invoke `git diff --name-only --diff-filter=ACMR <ref>` for changed file list
- [x] 1.3 Implement hunk parsing: run single `git diff -U0 <ref>` invocation, parse `@@` hunk headers to extract `HunkRange` per file, group by file path into `ChangedFile.hunks`
- [x] 1.4 Implement `HunkRange::overlaps(line_range: &LineRange) -> bool` for finding attribution (any line overlap = true)
- [x] 1.5 Handle edge cases in `compute_diff`: non-git directory detection (return `DiffContext` with `is_fallback: true`), missing `git` binary (return error), invalid git reference (return error with "Invalid git reference: <ref>"), renamed files (scan at new path)
- [x] 1.6 Add `pub mod diff;` to `crates/atlas-core/src/lib.rs` and re-export `DiffStatus`, `DiffContext`, `HunkRange`, `ChangedFile`
- [x] 1.7 Unit tests for `compute_diff`: valid ref, invalid ref, non-git dir fallback, deleted files excluded, renamed files included, single-line hunk, multi-hunk file, empty diff (clean tree)

## 2. Finding model changes

- [x] 2.1 Add `diff_status: Option<DiffStatus>` field to `Finding` struct in `crates/atlas-analysis/src/finding.rs` with `#[serde(skip_serializing_if = "Option::is_none")]` and default `None`
- [x] 2.2 Add `diff_status` setter to `FindingBuilder` (default `None`, not included in fingerprint computation)
- [x] 2.3 Unit tests: verify `diff_status` is `None` by default, serialises when `Some`, omitted when `None`, does not affect fingerprint

## 3. Scan engine integration

- [x] 3.1 Add `diff_context: Option<DiffContext>` field to `ScanOptions` in `crates/atlas-core/src/engine.rs`
- [x] 3.2 In `scan_with_options()`, after `discover_files()`, if `diff_context` is `Some` and not fallback: filter `discovery.files` to retain only files whose relative path matches a `ChangedFile` path; log "No changed files to scan" and return early if filtered list is empty
- [x] 3.3 In `scan_with_options()`, when `diff_context` is active and diff exceeds 80% of discovered files, log suggestion: "Consider running a full scan for comprehensive coverage"
- [x] 3.4 In `process_file()`, after L1 evaluation produces findings, if `diff_context` is present: look up `ChangedFile` for the current file, call `HunkRange::overlaps()` to set each finding's `diff_status` to `New` or `Context`
- [x] 3.5 Pass `diff_context` reference into `process_file()` (add parameter to method signature)
- [x] 3.6 Integration tests: diff-aware scan with 3 changed files in a 10-file project produces findings only in changed files; findings on changed lines get `New`, findings on unchanged lines get `Context`

## 4. CLI flags

- [x] 4.1 Add `--diff <git-ref>` optional argument to `ScanArgs` in `crates/atlas-cli/src/commands/scan.rs`
- [x] 4.2 Add `--diff-gate-mode` optional argument to `ScanArgs` with values `all` (default) and `new-only` (use `clap::ValueEnum`)
- [x] 4.3 In `execute()`, when `--diff` is provided: call `compute_diff(target, git_ref)`, handle non-git fallback (log warning, set `is_fallback`), handle missing git error (return error), handle invalid ref error (return error); set `diff_context` on `ScanOptions`
- [x] 4.4 In `execute()`, after scan and before gate evaluation: if `diff_gate_mode == NewOnly` and `diff_context` is active, filter `findings_for_gate` to only `diff_status == New`

## 5. Report integration

- [x] 5.1 Add `DiffContextReport` struct to `crates/atlas-report/src/json.rs` with fields `git_ref: String`, `changed_files_count: u32`, `total_new_findings: u32`, `total_context_findings: u32`
- [x] 5.2 Add `diff_context: Option<DiffContextReport>` field to `AtlasReport` with `#[serde(skip_serializing_if = "Option::is_none")]`
- [x] 5.3 Add `diff_context` to `ReportOptions` so the CLI can pass diff metadata to report generation; populate `DiffContextReport` from scan results when `--diff` was used
- [x] 5.4 Verify `Finding.diff_status` serialises correctly in JSON output (already handled by the `Option` serde attribute from task 2.1)
- [x] 5.5 In `crates/atlas-report/src/sarif.rs`, add `diff_status: Option<String>` to `SarifResultProperties` with `#[serde(skip_serializing_if = "Option::is_none")]`; populate from `Finding.diff_status` during SARIF generation
- [x] 5.6 In `crates/atlas-report/src/jsonl.rs`, include `diff_status` field in per-finding JSON lines when present
- [x] 5.7 Unit tests: JSON report includes `diff_context` section when diff is active, omits when not; SARIF results include `diff_status` in properties; JSONL lines include `diff_status`

## 6. End-to-end tests

- [x] 6.1 E2E test: create git repo with 100 files, modify 3 to introduce vulnerabilities, run `atlas scan --diff HEAD`, verify only 3 files scanned, findings have correct `diff_status`
- [x] 6.2 E2E test: clean working tree with `--diff HEAD` produces 0 files scanned and gate passes
- [x] 6.3 E2E test: `--diff-gate-mode new-only` with context findings exceeding threshold still passes gate
- [x] 6.4 E2E test: `--diff-gate-mode all` (default) counts both new and context findings against gate
- [x] 6.5 E2E test: non-git directory with `--diff HEAD` logs warning and produces full scan results
- [x] 6.6 E2E test: delete-only diff produces 0 files scanned and gate passes
- [x] 6.7 E2E test: JSON and SARIF reports include `diff_context` and per-finding `diff_status`
- [x] 6.8 Verify all existing scan tests pass without modification (zero regression)
