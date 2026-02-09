# Data Model: Diff-Aware Scanning

**Feature**: 004-diff-aware-scanning
**Created**: 2026-02-08
**Purpose**: Define the diff context data model, finding diff status attribution, and report schema extensions.

## 1. DiffContext

Represents the overall diff state for a scan invocation.

### Rust Type

```rust
/// Context for a diff-aware scan, computed from git diff output.
pub struct DiffContext {
    /// The git reference used for comparison (e.g., "HEAD", "origin/main", "v2.1.0").
    pub git_ref: String,
    /// List of files with changes relative to the git reference.
    pub changed_files: Vec<ChangedFile>,
    /// Whether this is a fallback (non-git directory detected).
    pub is_fallback: bool,
}
```

### JSON Serialisation (in report `diff_context` section)

```json
{
  "diff_context": {
    "git_ref": "origin/main",
    "changed_files_count": 5,
    "total_new_findings": 3,
    "total_context_findings": 7,
    "is_fallback": false
  }
}
```

## 2. ChangedFile

Represents a single file that has changes in the diff.

### Rust Type

```rust
/// A file modified relative to the diff reference.
pub struct ChangedFile {
    /// Path relative to the repository root.
    pub path: String,
    /// The type of change.
    pub change_type: ChangeType,
    /// Ranges of changed lines within the file.
    pub hunks: Vec<HunkRange>,
}

/// Type of change detected by git diff.
pub enum ChangeType {
    Added,      // New file (A)
    Modified,   // Existing file modified (M)
    Copied,     // File copied with changes (C)
    Renamed,    // File renamed (R) — path is the new name
}
```

### Git Command Mapping

| ChangeType | `--diff-filter` | Description |
|-----------|-----------------|-------------|
| `Added` | `A` | File is new in the working tree |
| `Modified` | `M` | File exists in both sides, content changed |
| `Copied` | `C` | File was copied from another file |
| `Renamed` | `R` | File was renamed (may include content changes) |
| *(excluded)* | `D` | File was deleted — not scanned |

### Example Git Commands

```bash
# Step 1: Get list of changed files (Added, Copied, Modified, Renamed)
git diff --name-only --diff-filter=ACMR origin/main

# Step 2: Get changed line ranges (unified diff with zero context)
git diff -U0 origin/main -- path/to/file.ts

# Step 3: Parse hunk headers from output
# @@ -15,3 +17,5 @@  → HunkRange { start_line: 17, line_count: 5 }
```

## 3. HunkRange

Represents a contiguous block of changed lines within a file.

### Rust Type

```rust
/// A range of changed lines in a file, parsed from a git diff hunk header.
pub struct HunkRange {
    /// The starting line number in the new version of the file (1-based).
    pub start_line: usize,
    /// The number of lines in this hunk. A value of 0 means the hunk is a deletion-only hunk.
    pub line_count: usize,
}
```

### Hunk Header Parsing

Git unified diff hunk headers follow the format:

```
@@ -<old_start>,<old_count> +<new_start>,<new_count> @@ [optional context]
```

Only the `+<new_start>,<new_count>` portion is relevant for determining which lines are "new":

| Hunk Header | Parsed HunkRange |
|-------------|-----------------|
| `@@ -10,3 +12,5 @@` | `{ start_line: 12, line_count: 5 }` → lines 12–16 |
| `@@ -1 +1,2 @@` | `{ start_line: 1, line_count: 2 }` → lines 1–2 |
| `@@ -5,0 +6,3 @@` | `{ start_line: 6, line_count: 3 }` → lines 6–8 |
| `@@ -5,3 +5,0 @@` | `{ start_line: 5, line_count: 0 }` → deletion only (no new lines) |

### Regex for Parsing

```rust
// Regex to extract new-side start and count from hunk headers
let hunk_re = Regex::new(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@").unwrap();
// Group 1: new_start, Group 2: new_count (defaults to 1 if omitted)
```

## 4. FindingDiffStatus

Describes whether a finding is on a changed line or an unchanged line within a changed file.

### Rust Type

```rust
/// The relationship of a finding to the diff context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDiffStatus {
    /// Finding is on a line that was added or modified in the diff.
    New,
    /// Finding is on an unchanged line within a changed file.
    Context,
}
```

### Attribution Logic

```rust
fn attribute_diff_status(
    finding_line: usize,
    hunks: &[HunkRange],
) -> FindingDiffStatus {
    for hunk in hunks {
        let end_line = hunk.start_line + hunk.line_count;
        if finding_line >= hunk.start_line && finding_line < end_line {
            return FindingDiffStatus::New;
        }
    }
    FindingDiffStatus::Context
}
```

### Finding Model Extension

The `Finding` struct gains an optional `diff_status` field:

```rust
pub struct Finding {
    // ... existing fields ...

    /// Present only during diff-aware scans.
    /// `None` for full scans, `Some(New)` or `Some(Context)` for diff scans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_status: Option<FindingDiffStatus>,
}
```

## 5. Gate Evaluation with Diff Mode

### DiffGateMode

```rust
/// Controls how findings are counted against the gate in diff-aware scans.
#[derive(Debug, Clone, ValueEnum)]
pub enum DiffGateMode {
    /// Count all findings in changed files (default).
    All,
    /// Count only findings on changed lines (diff_status == New).
    NewOnly,
}
```

### Gate Filtering Logic

```rust
fn filter_findings_for_gate(
    findings: &[Finding],
    diff_gate_mode: DiffGateMode,
) -> Vec<&Finding> {
    match diff_gate_mode {
        DiffGateMode::All => findings.iter().collect(),
        DiffGateMode::NewOnly => findings
            .iter()
            .filter(|f| f.diff_status == Some(FindingDiffStatus::New))
            .collect(),
    }
}
```

## 6. CLI Flag Definitions

```
atlas scan [OPTIONS] <PATH>

Diff-aware scanning:
    --diff <GIT_REF>            Compare against a git reference (branch, tag, SHA)
    --diff-gate-mode <MODE>     Gate evaluation mode for diff scans [default: all]
                                [possible values: all, new-only]
```

### Flag Interactions

| `--diff` | `--diff-gate-mode` | Behaviour |
|----------|-------------------|-----------|
| Not set | N/A (ignored) | Full scan, all findings gated |
| `HEAD` | `all` (default) | Scan changed files, gate all findings in them |
| `origin/main` | `new-only` | Scan changed files, gate only findings on changed lines |

## 7. Report Examples

### JSON Report with Diff Context

```json
{
  "scan_metadata": {
    "project_root": "/home/user/project",
    "scanned_files": 5,
    "total_project_files": 5000,
    "scan_mode": "diff",
    "timestamp": "2026-02-08T12:00:00Z"
  },
  "diff_context": {
    "git_ref": "origin/main",
    "changed_files_count": 5,
    "total_new_findings": 3,
    "total_context_findings": 7,
    "is_fallback": false
  },
  "findings": [
    {
      "fingerprint": "abc123...",
      "rule_id": "atlas/security/typescript/sql-injection",
      "severity": "critical",
      "category": "security",
      "file_path": "src/api/users.ts",
      "line_range": { "start_line": 42, "end_line": 42 },
      "diff_status": "new",
      "description": "SQL injection via string concatenation"
    },
    {
      "fingerprint": "def456...",
      "rule_id": "atlas/quality/typescript/console-log",
      "severity": "low",
      "category": "quality",
      "file_path": "src/api/users.ts",
      "line_range": { "start_line": 10, "end_line": 10 },
      "diff_status": "context",
      "description": "console.log residual"
    }
  ],
  "gate_result": {
    "result": "FAIL",
    "mode": "new-only",
    "breached_thresholds": [
      {
        "severity": "critical",
        "threshold": 0,
        "actual": 1,
        "note": "Only new findings counted (diff-gate-mode: new-only)"
      }
    ]
  }
}
```

### SARIF Finding with Diff Status

```json
{
  "ruleId": "atlas/security/typescript/sql-injection",
  "level": "error",
  "message": { "text": "SQL injection via string concatenation" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/api/users.ts" },
      "region": { "startLine": 42 }
    }
  }],
  "properties": {
    "diff_status": "new",
    "category": "security"
  }
}
```

## 8. Diff Pipeline Flow

```
CLI (--diff origin/main)
  │
  ▼
DiffContext::from_git_ref("origin/main")
  │  ├─ git diff --name-only --diff-filter=ACMR origin/main
  │  └─ git diff -U0 origin/main -- <files>  (parse @@ hunks)
  │
  ▼
engine.scan(files: changed_files_only)
  │  ├─ Parse AST for each changed file
  │  └─ Run L1 pattern matching (unchanged)
  │
  ▼
Findings ← attribute_diff_status(finding.line, file.hunks)
  │  ├─ New: finding line ∈ hunk range
  │  └─ Context: finding line ∉ any hunk range
  │
  ▼
Gate evaluation (filtered by diff_gate_mode)
  │  ├─ All: count all findings
  │  └─ NewOnly: count only New findings
  │
  ▼
Report (includes diff_context + per-finding diff_status)
```
