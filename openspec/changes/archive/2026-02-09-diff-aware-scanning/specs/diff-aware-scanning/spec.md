## ADDED Requirements

### Requirement: Diff reference flag
The `scan` command SHALL accept a `--diff <git-ref>` flag that restricts scanning to files changed relative to the specified git reference. The git reference MUST accept branch names, tags, commit SHAs, `HEAD`, and relative references (`HEAD~N`).

#### Scenario: Scan with HEAD reference
- **WHEN** `atlas scan ./src --diff HEAD` is run in a git repository with 3 files having unstaged changes
- **THEN** only the 3 changed files are scanned and findings appear only in those files

#### Scenario: Scan with branch reference
- **WHEN** `atlas scan --diff origin/main` is run on a feature branch
- **THEN** only files changed between `origin/main` and HEAD are scanned

#### Scenario: Scan with tag reference
- **WHEN** `atlas scan --diff v2.1.0` is run after changes made since the tag
- **THEN** only files modified since that tag are scanned

#### Scenario: Scan with commit SHA reference
- **WHEN** `atlas scan --diff abc123` is run with a valid commit SHA
- **THEN** the diff is computed against that specific commit

#### Scenario: Invalid git reference
- **WHEN** `atlas scan --diff nonexistent` is run with an invalid git reference
- **THEN** an error message is displayed: "Invalid git reference: nonexistent" and the scan aborts

### Requirement: Changed file computation
The system SHALL compute changed files using `git diff --name-only --diff-filter=ACM <ref>` to identify added, copied, and modified files. Deleted files SHALL be excluded from the scan file list. Renamed files SHALL be scanned at their new path if content changed.

#### Scenario: Deleted files excluded
- **WHEN** a file has been deleted since the diff reference
- **THEN** the deleted file is not included in the scan file list

#### Scenario: Renamed files scanned at new path
- **WHEN** a file has been renamed and its content changed since the diff reference
- **THEN** the file is scanned at its new path

#### Scenario: Added files included
- **WHEN** a new file has been added since the diff reference
- **THEN** the new file is included in the scan and all findings are attributed as `new`

### Requirement: Changed line range extraction
The system SHALL extract changed line ranges by parsing `@@` hunk headers from `git diff -U0 <ref>`. A single `git diff -U0 <ref>` invocation SHALL be used to retrieve hunks for all changed files (not one subprocess per file).

#### Scenario: Hunk headers parsed correctly
- **WHEN** a file has changes at lines 10-15 and 30-35
- **THEN** two hunk ranges are extracted: (start=10, count=6) and (start=30, count=6)

#### Scenario: Single-line change
- **WHEN** a file has a single line changed at line 42
- **THEN** one hunk range is extracted with start=42, count=1

### Requirement: Scan engine file filtering
When `--diff` is specified, the scan engine SHALL filter the discovered file list to include only changed files before parsing and analysis. File discovery (`.gitignore`, `.atlasignore`, language detection, binary exclusion) SHALL still apply to the filtered set.

#### Scenario: Only changed files scanned
- **WHEN** `atlas scan --diff HEAD` is run in a 5,000-file project with 3 changed files
- **THEN** only the 3 changed files are parsed and analysed

#### Scenario: No changed files
- **WHEN** `atlas scan --diff HEAD` is run with a clean working tree
- **THEN** 0 files are scanned and the result indicates "No changed files to scan"

#### Scenario: Large diff suggestion
- **WHEN** the diff contains more than 80% of total project files
- **THEN** a suggestion is logged: "Consider running a full scan for comprehensive coverage"

### Requirement: Finding diff status attribution
Each Finding produced during a diff-aware scan SHALL include a `diff_status` field. The value SHALL be `new` when the finding's line range overlaps any changed hunk range, or `context` when the finding is on an unchanged line in a changed file. For non-diff scans, the field SHALL be absent.

#### Scenario: Finding on changed line
- **WHEN** a finding is detected at line 12 and lines 10-15 were changed
- **THEN** the finding has `diff_status: "new"`

#### Scenario: Finding on unchanged line
- **WHEN** a finding is detected at line 50 in a changed file but line 50 was not modified
- **THEN** the finding has `diff_status: "context"`

#### Scenario: Multi-line finding partially overlapping hunk
- **WHEN** a finding spans lines 10-15 and only line 12 was changed
- **THEN** the finding has `diff_status: "new"` (conservative: any overlap counts)

#### Scenario: Non-diff scan omits field
- **WHEN** a scan runs without `--diff`
- **THEN** findings do not include the `diff_status` field

### Requirement: Diff gate mode
The `scan` command SHALL support a `--diff-gate-mode` flag with values `all` (default) and `new-only`. In `new-only` mode, gate evaluation SHALL count only findings where `diff_status` is `new`. In `all` mode, gate evaluation SHALL count all findings in changed files regardless of `diff_status`.

#### Scenario: New-only mode excludes context findings
- **WHEN** `--diff-gate-mode new-only` is used and there are 1 new finding and 3 context findings
- **THEN** only the 1 new finding counts against the gate thresholds

#### Scenario: All mode counts all findings (default)
- **WHEN** `--diff-gate-mode all` is used (or the flag is omitted) with 1 new and 3 context findings
- **THEN** all 4 findings count against the gate thresholds

#### Scenario: New-only mode prevents false gate failures
- **WHEN** a PR has only context findings exceeding the threshold and `--diff-gate-mode new-only` is used
- **THEN** the gate passes because no new findings exceed the threshold

### Requirement: Non-git fallback
When `--diff` is specified and the target directory is not inside a git repository, the system SHALL log a warning ("Not a git repository; falling back to full scan") and perform a full scan. The fallback scan SHALL produce identical results to a scan without `--diff`.

#### Scenario: Non-git directory fallback
- **WHEN** `atlas scan --diff HEAD` is run in a non-git directory
- **THEN** a warning is logged and a full scan is performed with identical results to running without `--diff`

### Requirement: Missing git error
When `--diff` is specified and the `git` command is not available on the system PATH, the system SHALL return an error ("git command not found; --diff requires git") and SHALL NOT fall back to a full scan.

#### Scenario: Git not installed
- **WHEN** `atlas scan --diff HEAD` is run and `git` is not on the PATH
- **THEN** an error is returned and the scan does not proceed

### Requirement: Diff context in JSON reports
When `--diff` is used, JSON reports SHALL include a `diff_context` section containing: `git_ref` (the reference used), `changed_files_count`, `total_new_findings`, and `total_context_findings`. Each finding in the report SHALL include `diff_status` when produced by a diff-aware scan.

#### Scenario: JSON report includes diff context
- **WHEN** a diff-aware scan produces 5 new findings and 3 context findings across 8 changed files
- **THEN** the JSON report includes `diff_context: { git_ref: "<ref>", changed_files_count: 8, total_new_findings: 5, total_context_findings: 3 }`

#### Scenario: JSON findings include diff status
- **WHEN** a diff-aware scan produces findings
- **THEN** each finding in the JSON report includes `diff_status: "new"` or `diff_status: "context"`

### Requirement: Diff status in SARIF reports
SARIF reports SHALL include `diff_status` in each finding's `properties` section when produced by a diff-aware scan.

#### Scenario: SARIF finding properties include diff status
- **WHEN** a diff-aware scan produces findings and outputs SARIF format
- **THEN** each SARIF result's `properties` object includes `diff_status: "new"` or `diff_status: "context"`

### Requirement: Diff status in JSONL reports
JSONL reports SHALL include `diff_status` per finding line when produced by a diff-aware scan.

#### Scenario: JSONL lines include diff status
- **WHEN** a diff-aware scan produces findings and outputs JSONL format
- **THEN** each JSONL finding line includes `diff_status: "new"` or `diff_status: "context"`

### Requirement: Diff computation performance
Diff computation (git commands) SHALL complete in less than 5 seconds for repositories with up to 100,000 commits. Scan time for a diff-aware scan SHALL scale linearly with the number of changed files, not total project files.

#### Scenario: Fast diff computation on large repo
- **WHEN** `atlas scan --diff HEAD` is run on a repository with 100,000 commits and 5 changed files
- **THEN** the diff computation completes in less than 5 seconds

#### Scenario: Scan time scales with changed files
- **WHEN** a 10,000-file project has 5 changed files
- **THEN** the diff-aware scan completes in less than 5 seconds (excluding unchanged file processing)

### Requirement: Deleted-only PR handling
When a PR diff contains only deleted files, the diff-aware scan SHALL scan 0 files and the gate SHALL pass.

#### Scenario: Delete-only PR passes gate
- **WHEN** a PR only deletes files and `atlas scan --diff origin/main` is run
- **THEN** 0 files are scanned and the gate passes
