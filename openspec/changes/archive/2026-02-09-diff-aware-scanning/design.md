## Context

Atlas-Local scans entire project directories on every invocation. The scan pipeline is:
`discover_files() → parallel process_file() → sort findings → gate evaluation → reports`.
There is no mechanism to restrict scanning to a subset of files based on version control state.

The existing baseline system (fingerprint-based diff against a stored baseline file) is orthogonal — it compares findings across runs, not files across git commits. Diff-aware scanning operates at a different level: filtering *which files* enter the pipeline and attributing *which lines* a finding sits on relative to a git diff.

Key integration points in the current codebase:
- `ScanOptions` controls engine behaviour (file size, parallelism, caching)
- `discover_files()` returns all source files matching language and ignore rules
- `Finding` has `line_range: LineRange` (1-indexed start/end line+col)
- `evaluate_gate()` accepts `&[impl GateFinding]` — the caller pre-filters the finding set
- `ReportOptions` carries optional metadata injected into report output
- `generate_reports()` takes `ScanResult` + `ReportOptions` and produces all formats

## Goals / Non-Goals

**Goals:**

- Scan only git-changed files when `--diff <ref>` is provided, achieving scan time proportional to change size
- Attribute each finding as `new` (on a changed line) or `context` (on an unchanged line in a changed file)
- Support `--diff-gate-mode new-only` to gate only on newly introduced findings in CI
- Include diff context metadata in JSON, SARIF, and JSONL reports
- Zero regression on existing full-scan behaviour — all new fields/paths are additive and optional

**Non-Goals:**

- `git2` / libgit2 native integration (using `git` CLI subprocess instead)
- Cross-file impact analysis (changed file A affecting findings in file B)
- Incremental AST caching between scans
- Non-git VCS support (Mercurial, SVN)
- Pre-commit hook orchestration

## Decisions

### D1: Git CLI subprocess over `git2` crate

**Choice**: Use `std::process::Command` to invoke `git diff` rather than the `git2` Rust crate.

**Rationale**: `git2` requires building `libgit2` (C library), adding cross-platform compilation complexity and ~4 MB binary size increase. The two git commands needed (`git diff --name-only` and `git diff -U0`) produce well-defined text output that is trivial to parse. The `git` CLI is universally available in development and CI environments where diff-aware scanning is relevant.

**Alternatives considered**: `git2` crate would avoid subprocess overhead and give structured data, but the build complexity cost exceeds the benefit for two simple commands.

### D2: Diff module placement in `atlas-core`

**Choice**: Create `crates/atlas-core/src/diff.rs` containing `DiffContext`, `ChangedFile`, `HunkRange`, and the `compute_diff()` function.

**Rationale**: The diff context feeds directly into `ScanEngine::scan_with_options()` and the file discovery filter, both in `atlas-core`. Placing it in `atlas-core` avoids a cross-crate dependency cycle. The module has no dependencies beyond `std::process::Command` and `std::path::Path`.

### D3: File filtering after discovery (not during)

**Choice**: Run `discover_files()` as-is, then filter the resulting file list against `DiffContext.changed_files` before entering the parallel scan loop.

**Rationale**: `discover_files()` handles `.gitignore`, `.atlasignore`, language detection, and binary exclusion. These filters must still apply to diff-changed files. Post-filtering is a single `retain()` call on the discovered file vec, keeping discovery logic unchanged and the diff integration minimal.

**Trade-off**: For very large codebases, discovery still walks the full tree even in diff mode. This is acceptable because discovery is I/O-bound and fast (the expensive step is AST parsing, which is skipped for non-changed files). If discovery becomes a bottleneck in the future, it can be optimised independently.

### D4: Line attribution via hunk overlap check

**Choice**: After a finding is produced by L1 evaluation, check whether its `line_range` overlaps any `HunkRange` in the corresponding `ChangedFile`. If overlap → `New`; if no overlap → `Context`.

**Rationale**: This post-evaluation check is the simplest integration point. It doesn't require modifying the L1 pattern engine or tree-sitter evaluation logic. The overlap check is O(hunks) per finding, with hunks typically numbering < 20 per file.

**Implementation detail**: The overlap check will be: `finding.line_range.start_line <= hunk.start_line + hunk.line_count - 1 && finding.line_range.end_line >= hunk.start_line`. This handles multi-line findings that partially overlap a hunk (conservative: mark as `New` if any line overlaps).

### D5: `diff_status` as `Option<DiffStatus>` on Finding

**Choice**: Add `diff_status: Option<DiffStatus>` to the `Finding` struct, where `DiffStatus` is an enum with variants `New` and `Context`. The field is `None` for non-diff scans.

**Rationale**: Using `Option` preserves backwards compatibility — existing non-diff scan paths produce `None`, serialised reports omit the field via `#[serde(skip_serializing_if = "Option::is_none")]`. The `DiffStatus` enum is defined in `atlas-core::diff` alongside the other diff types, and re-exported for use in `atlas-analysis`.

**Alternative considered**: Putting `diff_status` in the `metadata` BTreeMap. Rejected because diff status is a first-class attribute that affects gate evaluation, not arbitrary metadata.

### D6: Gate filtering in CLI, not in gate engine

**Choice**: The `--diff-gate-mode` filtering happens in `scan.rs` before calling `evaluate_gate()`, not inside the gate engine itself.

**Rationale**: The gate engine is a pure function `(findings, thresholds) → result`. Adding diff-awareness would couple it to the diff concept. Instead, `scan.rs` already filters findings for baseline mode using the same pattern — we extend that pattern with an additional diff-status filter. This keeps the gate engine unchanged and testable in isolation.

### D7: Hunk parsing from `git diff -U0`

**Choice**: Use `git diff -U0 <ref> -- <file>` to get zero-context unified diff, then parse `@@ -old,count +new,count @@` hunk headers to extract changed line ranges on the new side.

**Rationale**: `-U0` produces the smallest possible diff output (no surrounding context lines), making hunk header parsing unambiguous. The `+new_start,count` portion of each `@@` header directly gives us the changed line ranges in the current file version.

**Optimisation**: Run a single `git diff -U0 <ref>` (without `-- <file>`) to get all hunks for all changed files in one subprocess call, then parse and group by file path. This avoids N subprocess calls for N changed files.

### D8: Non-git fallback and missing-git error

**Choice**: If `--diff` is specified and the directory is not a git repository, log a warning and fall back to a full scan. If `git` is not installed, return a hard error.

**Rationale**: A non-git directory is a configuration mismatch (developer runs the command in the wrong directory) — a full scan is a reasonable fallback that doesn't lose safety. A missing `git` binary, however, means the feature cannot function at all, so a clear error is better than a silent fallback.

## Risks / Trade-offs

- **[Risk] Subprocess overhead for large diffs** — `git diff` on a repository with 100,000+ commits is fast for diffing HEAD vs a recent branch, but could be slow for diffing against a very old ref. → *Mitigation*: The spec requires < 5 seconds for diff computation; test with large repos. The `git diff` command itself is highly optimised.

- **[Risk] Hunk parsing edge cases** — Renamed files, binary files, merge commits, and files with no newline at EOF can produce unusual diff output. → *Mitigation*: Use `--diff-filter=ACM` to exclude deletes/binary; parse only `@@` headers (not content); test against edge-case fixtures.

- **[Risk] Finding attribution accuracy on multi-line findings** — A finding spanning lines 10-15 where only line 12 changed will be marked as `New`. This is conservative (may over-count new findings). → *Mitigation*: Document this behaviour as intentional. For gate purposes, conservative attribution is safer than missing new issues.

- **[Trade-off] Discovery still walks full tree** — In diff mode, file discovery traverses the entire project before filtering. This adds ~100ms for 10,000-file projects but keeps the architecture simple. Acceptable for the initial implementation; can optimise later if needed.

- **[Trade-off] No incremental AST caching** — Each diff-aware scan still parses changed files from scratch. Combining diff-aware scanning with an AST cache (spec deferred) would further reduce scan time, but the two features are independent.
