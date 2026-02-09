# Feature Specification: Atlas Local — Diff-Aware Scanning

**Feature Branch**: `004-diff-aware-scanning`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, finding model, gate evaluation)

## Overview & Scope

Atlas-Local currently performs full-project scans on every invocation. In large codebases, this is wasteful during iterative development and CI/CD pull request checks where only a subset of files has changed. This specification adds diff-aware scanning that limits analysis to files and lines modified since a given git reference, dramatically reducing scan time and focusing results on newly introduced issues.

**Purpose**: Enable developers and CI pipelines to scan only changed code, reducing scan time proportionally to the change size and surfacing only newly introduced findings.

**Scope**: Git diff integration, changed-file filtering, changed-line attribution, and diff-aware gate evaluation. Requires `git` CLI availability.

**Exclusions** (deferred to future specs):
- Baseline file comparison (separate mechanism already exists)
- Cross-file impact analysis ("file A changed, what findings in file B are affected?")
- Non-git VCS support (Mercurial, SVN)
- Incremental caching of AST parse results between scans
- Pre-commit hook integration (can use `--diff HEAD` manually)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Scans Only Changed Files Before Commit (Priority: P1)

A developer has modified 3 files in a 5,000-file project. They run `atlas scan ./src --diff HEAD` to check only the files they changed. The scan completes in seconds instead of minutes and shows only findings in the modified files.

**Why this priority**: This is the primary use case — fast feedback on local changes. Without this, developers must wait for full scans or skip scanning entirely.

**Independent Test**: Create a git repository with 100 files, modify 3 files to introduce known vulnerabilities, run `atlas scan --diff HEAD`, and verify only the 3 modified files are scanned and findings appear only in those files.

**Acceptance Scenarios**:

1. **Given** a git repository where 3 files have unstaged changes, **When** `atlas scan ./src --diff HEAD` is run, **Then** only the 3 changed files are scanned and the scan duration is proportional to 3 files, not the full project.
2. **Given** a clean working tree with no changes, **When** `atlas scan --diff HEAD` is run, **Then** 0 files are scanned and the result is "No changed files to scan."
3. **Given** a changed file that introduces a SQL injection vulnerability, **When** diff-aware scan runs, **Then** the finding is produced with `diff_status: "new"`.

---

### User Story 2 — CI Pipeline Gates Only on New Findings (Priority: P1)

A CI pipeline runs `atlas scan --diff origin/main --diff-gate-mode new-only` on every pull request. The gate evaluates only findings in newly added or modified lines, ignoring pre-existing issues in the base branch. This prevents false gate failures caused by legacy code.

**Why this priority**: PR-level gating on new findings only is the most common CI use case for diff-aware scanning. Without `new-only` mode, existing issues would block unrelated PRs.

**Independent Test**: Create a branch with one new vulnerability and one pre-existing vulnerability in the diff context. Run with `--diff-gate-mode new-only` and verify only the new finding counts against the gate.

**Acceptance Scenarios**:

1. **Given** a PR branch with 1 new critical finding in added lines and 3 pre-existing findings in unchanged context, **When** `atlas scan --diff origin/main --diff-gate-mode new-only` runs, **Then** only the 1 new finding counts against the gate.
2. **Given** `--diff-gate-mode all` (default), **When** a diff-aware scan runs, **Then** all findings in changed files count against the gate (both new and contextual).
3. **Given** a PR that only deletes code, **When** diff-aware scan runs, **Then** 0 files are scanned (deleted files are excluded) and the gate passes.

---

### User Story 3 — Developer Compares Against a Specific Commit (Priority: P2)

A developer wants to see what new issues were introduced since the last release tag. They run `atlas scan --diff v2.1.0` to compare against an arbitrary git reference (tag, commit SHA, or branch).

**Why this priority**: Flexible git reference support extends the feature beyond just `HEAD` and `origin/main`, but the core diff mechanism must work first.

**Independent Test**: Create a tag, make changes after the tag, and run `atlas scan --diff <tag>`. Verify only files changed since the tag are scanned.

**Acceptance Scenarios**:

1. **Given** a git tag `v2.1.0` and changes made after it, **When** `atlas scan --diff v2.1.0` runs, **Then** only files modified since that tag are scanned.
2. **Given** a commit SHA as the diff reference, **When** `atlas scan --diff abc123` runs, **Then** the diff is computed against that specific commit.
3. **Given** an invalid git reference, **When** `atlas scan --diff nonexistent` runs, **Then** an error message is displayed: "Invalid git reference: nonexistent" and the scan aborts.

---

### User Story 4 — Non-Git Directory Falls Back to Full Scan (Priority: P2)

A developer runs `atlas scan --diff HEAD` on a directory that is not a git repository. Instead of failing, Atlas logs a warning and falls back to a full scan.

**Why this priority**: Graceful degradation ensures the tool works in all environments, but this is a defensive edge case rather than a primary workflow.

**Independent Test**: Run `atlas scan --diff HEAD` in a non-git directory and verify the warning message and full scan behaviour.

**Acceptance Scenarios**:

1. **Given** a directory that is not inside a git repository, **When** `atlas scan --diff HEAD` runs, **Then** a warning is logged ("Not a git repository; falling back to full scan") and a full scan is performed.
2. **Given** a git repository where `git` is not installed, **When** `atlas scan --diff HEAD` runs, **Then** an error is returned: "git command not found; --diff requires git."

---

### Edge Cases

- What happens when a file is renamed? Renamed files (detected via `--diff-filter=R`) are treated as the new path. If content changed, the new path is scanned.
- What happens when a binary file appears in the diff? Binary files are excluded from scanning (same as full scans).
- What happens with merge commits? The diff is computed between the merge base and HEAD, not the merge commit's parents. This matches `git diff <ref>...HEAD` semantics.
- What happens when the diff is very large (e.g., 500+ files)? All changed files are scanned. If the diff exceeds 80% of total files, a suggestion is logged: "Consider running a full scan for comprehensive coverage."
- What happens when a file is modified but only whitespace/comments changed? The file is still scanned (diff granularity is file-level for scan inclusion). Line attribution may mark findings as `context` if they are on unchanged lines.

## Requirements *(mandatory)*

### Functional Requirements

**Diff Computation**

- **FR-D01**: The `--diff <git-ref>` flag MUST accept any valid git reference (branch name, tag, commit SHA, `HEAD`, `HEAD~N`).
- **FR-D02**: Changed files MUST be computed using `git diff --name-only --diff-filter=ACM <ref>` to get added, copied, and modified files relative to the git ref.
- **FR-D03**: Deleted files (`D` filter) MUST be excluded from the scan file list.
- **FR-D04**: Renamed files (`R` filter) MUST be scanned at their new path if content changed.
- **FR-D05**: Changed line ranges MUST be extracted by parsing `@@` hunk headers from `git diff -U0 <ref>`.

**Diff-Aware Engine Integration**

- **FR-D06**: When `--diff` is specified, the scan engine MUST filter the file list to include only changed files before parsing/analysis.
- **FR-D07**: Each Finding produced during a diff-aware scan MUST include a `diff_status` field with value `"new"` (finding is on a changed line) or `"context"` (finding is on an unchanged line in a changed file).
- **FR-D08**: If `--diff` is specified and the directory is not a git repository, the engine MUST log a warning and fall back to a full scan.
- **FR-D09**: If the `git` command is not available, the engine MUST return an error and not fall back to full scan.

**Diff-Aware Gate Evaluation**

- **FR-D10**: A `--diff-gate-mode` flag MUST be supported with values `all` (default) and `new-only`.
- **FR-D11**: In `new-only` mode, gate evaluation MUST count only findings where `diff_status == "new"`.
- **FR-D12**: In `all` mode (default), gate evaluation MUST count all findings in changed files regardless of `diff_status`.

**Reporting**

- **FR-D13**: JSON reports MUST include a `diff_context` section when `--diff` is used, containing: `git_ref`, `changed_files_count`, `total_new_findings`, `total_context_findings`.
- **FR-D14**: Each finding in the report MUST include `diff_status` when produced by a diff-aware scan.
- **FR-D15**: SARIF reports MUST include `diff_status` in finding `properties`.

**Performance**

- **FR-D16**: Diff computation (git commands) MUST complete in < 5 seconds for repositories with up to 100,000 commits.
- **FR-D17**: The scan time for a diff-aware scan MUST scale linearly with the number of changed files, not total project files.

### Key Entities

- **DiffContext**: The overall diff state for a scan. Key attributes: `git_ref`, `changed_files`, `is_fallback`.
- **ChangedFile**: A file modified in the diff. Key attributes: `path`, `change_type` (Added/Modified/Copied/Renamed), `hunks`.
- **HunkRange**: A contiguous range of changed lines in a file. Key attributes: `start_line`, `line_count`.
- **FindingDiffStatus**: The relationship of a finding to the diff. Values: `New` (on a changed line), `Context` (on an unchanged line in a changed file).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-D01**: `atlas scan --diff HEAD` on a 10,000-file project with 5 changed files completes in < 5 seconds (excluding AST parse time for unchanged files).
- **SC-D02**: Findings in diff-aware mode correctly attribute `diff_status: "new"` for findings on changed lines and `diff_status: "context"` for findings on unchanged lines, with 100% accuracy against a manually verified test corpus.
- **SC-D03**: `--diff-gate-mode new-only` correctly excludes `context` findings from gate counting — a policy breach with `all` mode does not breach with `new-only` mode when only context findings exceed the threshold.
- **SC-D04**: Non-git fallback produces identical results to a full scan without `--diff`.
- **SC-D05**: All existing full-scan tests pass without modification (zero regression).
- **SC-D06**: Diff computation handles repositories with 100,000+ commits without timeout (< 5 seconds for diff calculation).
- **SC-D07**: JSON and SARIF reports include `diff_context` and per-finding `diff_status` when `--diff` is used.

## Assumptions

- `git` CLI is available on the system PATH in environments where `--diff` is used.
- Git repositories use standard diff formats (unified diff with `@@` hunk markers).
- The performance benefit is proportional to the ratio of changed files to total files.
- Line-level attribution (new vs context) is accurate for single-branch linear histories. Merge-heavy histories may have edge cases.

## Scope Boundaries

**In Scope**:
- `--diff <git-ref>` CLI flag for diff-aware scanning
- Git diff computation using `git` CLI subprocess
- Changed file filtering in the scan engine
- Changed line range parsing from `@@` hunk headers
- `diff_status` attribution on findings (new/context)
- `--diff-gate-mode` flag (all/new-only)
- `diff_context` section in JSON reports
- `diff_status` in SARIF finding properties
- Non-git fallback with warning
- Error handling for missing `git` command

**Out of Scope**:
- `git2` native library integration (using CLI subprocess instead)
- Cross-file impact analysis
- Incremental AST caching between scans
- Non-git VCS support
- Pre-commit hook orchestration
- Diff-aware baseline comparison (separate mechanisms)

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `crates/atlas-core/src/diff.rs` | DiffContext, ChangedFile, HunkRange, git CLI invocation |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-cli/src/commands/scan.rs` | Add `--diff` and `--diff-gate-mode` flags |
| `crates/atlas-core/src/engine.rs` | Integrate diff file filtering before scan loop |
| `crates/atlas-analysis/src/finding.rs` | Add `diff_status` field to Finding |
| `crates/atlas-policy/src/gate.rs` | Filter by diff_status in new-only mode |
| `crates/atlas-report/src/json.rs` | Add `diff_context` section, `diff_status` per finding |
| `crates/atlas-report/src/sarif.rs` | Add `diff_status` to finding properties |

### Technical Decision: git CLI vs git2 Crate

Using `std::process::Command` to invoke `git` CLI rather than the `git2` crate because:
1. `git2` requires `libgit2` native compilation, which adds build complexity
2. `git diff` output parsing is straightforward and well-tested
3. The `git` CLI is universally available in development and CI environments
4. Performance is equivalent for the operations needed (diff, name-only listing)

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| [git-diff documentation](https://git-scm.com/docs/git-diff) | Git diff output format reference |
| [Unified diff format](https://www.gnu.org/software/diffutils/manual/html_node/Unified-Format.html) | Hunk header parsing specification |
