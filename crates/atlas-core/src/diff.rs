//! Git diff integration for diff-aware scanning.
//!
//! This module computes changed files and line ranges relative to a git
//! reference, enabling the scan engine to restrict analysis to modified code.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use tracing::{info, warn};

use crate::CoreError;

// Re-export DiffStatus from atlas-analysis (where Finding lives).
pub use atlas_analysis::DiffStatus;

// ---------------------------------------------------------------------------
// ChangeType
// ---------------------------------------------------------------------------

/// Type of file change in the diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Modified,
    Copied,
    Renamed,
}

// ---------------------------------------------------------------------------
// HunkRange
// ---------------------------------------------------------------------------

/// A contiguous range of changed lines in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HunkRange {
    /// 1-indexed start line of the changed range.
    pub start_line: u32,
    /// Number of lines in the changed range.
    pub line_count: u32,
}

impl HunkRange {
    /// Returns `true` if this hunk overlaps with the given line range.
    ///
    /// A finding is considered overlapping (and thus `New`) if any of its
    /// lines falls within the hunk.
    #[must_use]
    pub fn overlaps(&self, start_line: u32, end_line: u32) -> bool {
        if self.line_count == 0 {
            return false;
        }
        let hunk_end = self.start_line + self.line_count - 1;
        end_line >= self.start_line && start_line <= hunk_end
    }
}

// ---------------------------------------------------------------------------
// ChangedFile
// ---------------------------------------------------------------------------

/// A file that was modified in the diff.
#[derive(Debug, Clone)]
pub struct ChangedFile {
    /// Relative path of the file (forward slashes, no leading `./`).
    pub path: String,
    /// Type of change.
    pub change_type: ChangeType,
    /// Changed line ranges within this file.
    pub hunks: Vec<HunkRange>,
}

impl ChangedFile {
    /// Returns `true` if the given line range overlaps any hunk in this file.
    #[must_use]
    pub fn overlaps_any_hunk(&self, start_line: u32, end_line: u32) -> bool {
        self.hunks
            .iter()
            .any(|h| h.overlaps(start_line, end_line))
    }
}

// ---------------------------------------------------------------------------
// DiffContext
// ---------------------------------------------------------------------------

/// The overall diff state for a scan.
#[derive(Debug, Clone)]
pub struct DiffContext {
    /// The git reference used for the diff (e.g., `HEAD`, `origin/main`).
    pub git_ref: String,
    /// Files changed relative to the git reference.
    pub changed_files: Vec<ChangedFile>,
    /// If `true`, the diff could not be computed (e.g., not a git repo)
    /// and a full scan fallback is in effect.
    pub is_fallback: bool,
}

impl DiffContext {
    /// Returns a set of changed file paths for fast lookup.
    #[must_use]
    pub fn changed_paths(&self) -> std::collections::HashSet<&str> {
        self.changed_files.iter().map(|f| f.path.as_str()).collect()
    }

    /// Looks up a `ChangedFile` by its relative path.
    #[must_use]
    pub fn get_file(&self, path: &str) -> Option<&ChangedFile> {
        self.changed_files.iter().find(|f| f.path == path)
    }
}

// ---------------------------------------------------------------------------
// compute_diff
// ---------------------------------------------------------------------------

/// Computes the diff context by invoking `git` CLI commands.
///
/// # Steps
///
/// 1. Check that `git` is available on the system PATH.
/// 2. Check that the target directory is inside a git repository.
/// 3. Get the list of changed files via `git diff --name-only --diff-filter=ACMR`.
/// 4. Parse hunk headers from `git diff -U0` to extract changed line ranges.
///
/// # Errors
///
/// - Returns `CoreError::Config("git command not found; --diff requires git")` if
///   the `git` binary is not available.
/// - Returns `CoreError::Config("Invalid git reference: <ref>")` if the reference
///   is not valid.
///
/// # Fallback
///
/// If the target is not inside a git repository, returns a `DiffContext` with
/// `is_fallback: true` and an empty changed file list.
pub fn compute_diff(target: &Path, git_ref: &str) -> Result<DiffContext, CoreError> {
    // 1. Check git availability.
    if !is_git_available() {
        return Err(CoreError::Config(
            "git command not found; --diff requires git".to_string(),
        ));
    }

    // 2. Check if target is in a git repo.
    if !is_git_repository(target) {
        warn!("Not a git repository; falling back to full scan");
        return Ok(DiffContext {
            git_ref: git_ref.to_string(),
            changed_files: Vec::new(),
            is_fallback: true,
        });
    }

    // 3. Validate the git reference.
    if !is_valid_git_ref(target, git_ref) {
        return Err(CoreError::Config(format!(
            "Invalid git reference: {git_ref}"
        )));
    }

    // 4. Get changed file list.
    let changed_paths = get_changed_files(target, git_ref)?;
    if changed_paths.is_empty() {
        info!("No changed files to scan");
        return Ok(DiffContext {
            git_ref: git_ref.to_string(),
            changed_files: Vec::new(),
            is_fallback: false,
        });
    }

    // 5. Get hunks for all changed files in one invocation.
    let hunks_by_file = get_hunks(target, git_ref)?;

    // 6. Build ChangedFile list.
    let changed_files = changed_paths
        .into_iter()
        .map(|(path, change_type)| {
            let hunks = hunks_by_file.get(&path).cloned().unwrap_or_default();
            ChangedFile {
                path,
                change_type,
                hunks,
            }
        })
        .collect();

    Ok(DiffContext {
        git_ref: git_ref.to_string(),
        changed_files,
        is_fallback: false,
    })
}

// ---------------------------------------------------------------------------
// Git CLI helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the `git` command is available on the PATH.
fn is_git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Returns `true` if the target directory is inside a git repository.
fn is_git_repository(target: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Returns `true` if the given git reference is valid in the repository.
fn is_valid_git_ref(target: &Path, git_ref: &str) -> bool {
    Command::new("git")
        .args(["rev-parse", "--verify", git_ref])
        .current_dir(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Gets the list of changed files using `git diff --name-status --diff-filter=ACMR`.
fn get_changed_files(
    target: &Path,
    git_ref: &str,
) -> Result<Vec<(String, ChangeType)>, CoreError> {
    let output = Command::new("git")
        .args([
            "diff",
            "--name-status",
            "--diff-filter=ACMR",
            git_ref,
        ])
        .current_dir(target)
        .output()
        .map_err(|e| CoreError::Config(format!("failed to run git diff: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::Config(format!("git diff failed: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Format: "M\tpath" or "R100\told_path\tnew_path"
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }

        let status = parts[0];
        let change_type = if status.starts_with('R') {
            ChangeType::Renamed
        } else {
            match status {
                "A" => ChangeType::Added,
                "C" => ChangeType::Copied,
                "M" => ChangeType::Modified,
                _ => continue,
            }
        };

        // For renames, use the new path (second path).
        let path = if change_type == ChangeType::Renamed && parts.len() >= 3 {
            parts[2].to_string()
        } else {
            parts[1].to_string()
        };

        result.push((path, change_type));
    }

    Ok(result)
}

/// Parses hunk headers from `git diff -U0` output.
///
/// Returns a map from file path to a list of `HunkRange`s.
fn get_hunks(
    target: &Path,
    git_ref: &str,
) -> Result<HashMap<String, Vec<HunkRange>>, CoreError> {
    let output = Command::new("git")
        .args(["diff", "-U0", git_ref])
        .current_dir(target)
        .output()
        .map_err(|e| CoreError::Config(format!("failed to run git diff -U0: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::Config(format!("git diff -U0 failed: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_unified_diff_hunks(&stdout)
}

/// Parses unified diff output to extract hunk ranges grouped by file path.
///
/// Looks for lines matching:
/// - `diff --git a/path b/path` — to determine the current file
/// - `@@ ... +start,count @@` or `@@ ... +start @@` — to extract hunk ranges
fn parse_unified_diff_hunks(diff_output: &str) -> Result<HashMap<String, Vec<HunkRange>>, CoreError> {
    let mut result: HashMap<String, Vec<HunkRange>> = HashMap::new();
    let mut current_file: Option<String> = None;

    for line in diff_output.lines() {
        // Detect file boundary: "diff --git a/path b/path"
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // Extract the "b/path" portion.
            if let Some(b_path) = rest.split(" b/").nth(1) {
                current_file = Some(b_path.to_string());
            }
            continue;
        }

        // Parse hunk header: "@@ -old_start,old_count +new_start,new_count @@"
        if line.starts_with("@@") {
            if let Some(ref file_path) = current_file {
                if let Some(hunk) = parse_hunk_header(line) {
                    result.entry(file_path.clone()).or_default().push(hunk);
                }
            }
        }
    }

    Ok(result)
}

/// Parses a single `@@` hunk header line to extract the new-side range.
///
/// Format: `@@ -old_start[,old_count] +new_start[,new_count] @@`
///
/// When count is omitted, it defaults to 1.
fn parse_hunk_header(line: &str) -> Option<HunkRange> {
    // Find the "+start,count" or "+start" portion.
    let plus_idx = line.find('+')?;
    let after_plus = &line[plus_idx + 1..];

    // Find the end of the range (next space or @@).
    let end = after_plus
        .find(|c: char| c == ' ' || c == '@')
        .unwrap_or(after_plus.len());
    let range_str = &after_plus[..end];

    if let Some((start_str, count_str)) = range_str.split_once(',') {
        let start_line = start_str.parse::<u32>().ok()?;
        let line_count = count_str.parse::<u32>().ok()?;
        Some(HunkRange {
            start_line,
            line_count,
        })
    } else {
        let start_line = range_str.parse::<u32>().ok()?;
        Some(HunkRange {
            start_line,
            line_count: 1,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- HunkRange::overlaps tests -------------------------------------------

    #[test]
    fn hunk_overlaps_exact_match() {
        let hunk = HunkRange { start_line: 10, line_count: 5 };
        assert!(hunk.overlaps(10, 14));
    }

    #[test]
    fn hunk_overlaps_finding_within() {
        let hunk = HunkRange { start_line: 10, line_count: 10 };
        assert!(hunk.overlaps(12, 15));
    }

    #[test]
    fn hunk_overlaps_finding_extends_before() {
        let hunk = HunkRange { start_line: 10, line_count: 5 };
        assert!(hunk.overlaps(8, 11));
    }

    #[test]
    fn hunk_overlaps_finding_extends_after() {
        let hunk = HunkRange { start_line: 10, line_count: 5 };
        assert!(hunk.overlaps(13, 20));
    }

    #[test]
    fn hunk_no_overlap_before() {
        let hunk = HunkRange { start_line: 10, line_count: 5 };
        assert!(!hunk.overlaps(1, 9));
    }

    #[test]
    fn hunk_no_overlap_after() {
        let hunk = HunkRange { start_line: 10, line_count: 5 };
        assert!(!hunk.overlaps(15, 20));
    }

    #[test]
    fn hunk_single_line_overlap() {
        let hunk = HunkRange { start_line: 42, line_count: 1 };
        assert!(hunk.overlaps(42, 42));
        assert!(!hunk.overlaps(41, 41));
        assert!(!hunk.overlaps(43, 43));
    }

    #[test]
    fn hunk_zero_count_no_overlap() {
        // A zero-count hunk (deletion) never overlaps.
        let hunk = HunkRange { start_line: 10, line_count: 0 };
        assert!(!hunk.overlaps(10, 10));
    }

    // -- ChangedFile::overlaps_any_hunk tests --------------------------------

    #[test]
    fn changed_file_overlaps_any() {
        let file = ChangedFile {
            path: "src/main.rs".to_string(),
            change_type: ChangeType::Modified,
            hunks: vec![
                HunkRange { start_line: 5, line_count: 3 },
                HunkRange { start_line: 20, line_count: 2 },
            ],
        };
        assert!(file.overlaps_any_hunk(6, 6));
        assert!(file.overlaps_any_hunk(20, 21));
        assert!(!file.overlaps_any_hunk(10, 15));
    }

    // -- parse_hunk_header tests ---------------------------------------------

    #[test]
    fn parse_hunk_with_count() {
        let hunk = parse_hunk_header("@@ -10,3 +15,5 @@ fn foo()").unwrap();
        assert_eq!(hunk.start_line, 15);
        assert_eq!(hunk.line_count, 5);
    }

    #[test]
    fn parse_hunk_without_count() {
        let hunk = parse_hunk_header("@@ -10 +15 @@").unwrap();
        assert_eq!(hunk.start_line, 15);
        assert_eq!(hunk.line_count, 1);
    }

    #[test]
    fn parse_hunk_zero_count() {
        let hunk = parse_hunk_header("@@ -10,3 +15,0 @@").unwrap();
        assert_eq!(hunk.start_line, 15);
        assert_eq!(hunk.line_count, 0);
    }

    // -- parse_unified_diff_hunks tests --------------------------------------

    #[test]
    fn parse_multi_file_diff() {
        let diff = "\
diff --git a/src/main.rs b/src/main.rs
index abc..def 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -5,3 +5,4 @@ fn main() {
@@ -20,2 +21,3 @@ fn helper() {
diff --git a/src/lib.rs b/src/lib.rs
index ghi..jkl 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,0 +1,10 @@
";
        let result = parse_unified_diff_hunks(diff).unwrap();
        assert_eq!(result.len(), 2);

        let main_hunks = result.get("src/main.rs").unwrap();
        assert_eq!(main_hunks.len(), 2);
        assert_eq!(main_hunks[0].start_line, 5);
        assert_eq!(main_hunks[0].line_count, 4);
        assert_eq!(main_hunks[1].start_line, 21);
        assert_eq!(main_hunks[1].line_count, 3);

        let lib_hunks = result.get("src/lib.rs").unwrap();
        assert_eq!(lib_hunks.len(), 1);
        assert_eq!(lib_hunks[0].start_line, 1);
        assert_eq!(lib_hunks[0].line_count, 10);
    }

    // -- compute_diff integration tests (require git) ------------------------

    #[test]
    fn compute_diff_invalid_ref() {
        let tmp = tempfile::tempdir().unwrap();
        // Init a git repo.
        Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        // Create an initial commit.
        std::fs::write(tmp.path().join("file.txt"), "hello").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let result = compute_diff(tmp.path(), "nonexistent_ref_xyz");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid git reference"),
            "got: {err}"
        );
    }

    #[test]
    fn compute_diff_non_git_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let result = compute_diff(tmp.path(), "HEAD").unwrap();
        assert!(result.is_fallback);
        assert!(result.changed_files.is_empty());
    }

    #[test]
    fn compute_diff_clean_tree() {
        let tmp = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("file.txt"), "hello").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let result = compute_diff(tmp.path(), "HEAD").unwrap();
        assert!(!result.is_fallback);
        assert!(result.changed_files.is_empty());
    }

    #[test]
    fn compute_diff_with_changes() {
        let tmp = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        // Create initial files and commit.
        std::fs::write(tmp.path().join("a.txt"), "line1\nline2\nline3\n").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "unchanged\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        // Modify a.txt and add c.txt (leave b.txt unchanged).
        std::fs::write(tmp.path().join("a.txt"), "line1\nMODIFIED\nline3\n").unwrap();
        std::fs::write(tmp.path().join("c.txt"), "new file\n").unwrap();
        // Stage so `git diff HEAD` can see the changes.
        Command::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        let result = compute_diff(tmp.path(), "HEAD").unwrap();
        assert!(!result.is_fallback);
        assert_eq!(result.changed_files.len(), 2);

        let paths: Vec<&str> = result.changed_files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"a.txt"));
        assert!(paths.contains(&"c.txt"));
        assert!(!paths.contains(&"b.txt"));

        // a.txt should have hunk data.
        let a_file = result.get_file("a.txt").unwrap();
        assert_eq!(a_file.change_type, ChangeType::Modified);
        assert!(!a_file.hunks.is_empty());
    }

    #[test]
    fn compute_diff_deleted_files_excluded() {
        let tmp = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        std::fs::write(tmp.path().join("keep.txt"), "keep\n").unwrap();
        std::fs::write(tmp.path().join("delete_me.txt"), "remove\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(tmp.path())
            .output()
            .unwrap();

        // Delete the file.
        std::fs::remove_file(tmp.path().join("delete_me.txt")).unwrap();

        let result = compute_diff(tmp.path(), "HEAD").unwrap();
        let paths: Vec<&str> = result.changed_files.iter().map(|f| f.path.as_str()).collect();
        assert!(!paths.contains(&"delete_me.txt"));
    }
}
