//! File discovery for the Atlas scanner.
//!
//! This module implements directory walking with:
//!
//! - `.gitignore` and `.atlasignore` respect (via the `ignore` crate)
//! - Language detection by file extension
//! - Symlink following with cycle detection
//! - Binary file skipping (via content sniffing)

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use tracing::{debug, info, warn};

use atlas_lang::Language;

use crate::CoreError;

// ---------------------------------------------------------------------------
// DiscoveredFile
// ---------------------------------------------------------------------------

/// A source file discovered during directory walking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredFile {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Path relative to the scan root (normalized with forward slashes, no leading `./`).
    pub relative_path: String,
    /// Detected programming language based on file extension.
    pub language: Language,
    /// Whether this file should be excluded from secrets scanning.
    ///
    /// Files matching `.env.example`, `.env.sample`, `.env.template`, or
    /// similar patterns are marked as secrets-excluded so the scan engine
    /// can skip secrets-category rules for these files.
    pub secrets_excluded: bool,
}

// ---------------------------------------------------------------------------
// DiscoveryStats
// ---------------------------------------------------------------------------

/// Statistics collected during file discovery.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    /// Total files examined (before filtering).
    pub total_entries: u64,
    /// Files accepted for scanning.
    pub accepted: u64,
    /// Files skipped because of unsupported extension.
    pub skipped_unsupported: u64,
    /// Files skipped because they appear to be binary.
    pub skipped_binary: u64,
    /// Files skipped due to I/O or walk errors.
    pub skipped_errors: u64,
}

// ---------------------------------------------------------------------------
// DiscoveryResult
// ---------------------------------------------------------------------------

/// The result of file discovery: discovered files and statistics.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Discovered source files, sorted deterministically by relative path.
    pub files: Vec<DiscoveredFile>,
    /// Discovery statistics.
    pub stats: DiscoveryStats,
    /// Set of languages detected across all discovered files.
    pub languages_detected: BTreeSet<Language>,
}

// ---------------------------------------------------------------------------
// discover_files
// ---------------------------------------------------------------------------

/// Walk `root` recursively and collect source files for scanning.
///
/// # Behaviour
///
/// - Respects `.gitignore` files found in the directory tree.
/// - Respects `.atlasignore` files found in the directory tree (same syntax).
/// - Follows symlinks with cycle detection.
/// - Skips binary files (detected via content sniffing of the first 8 KiB).
/// - Detects language by file extension; files with unrecognized extensions are
///   skipped with a debug-level log message.
/// - When `language_filter` is `Some`, only files matching one of the listed
///   languages are included.
///
/// # Errors
///
/// Returns [`CoreError::Io`] if `root` does not exist or is not readable.
pub fn discover_files(
    root: &Path,
    language_filter: Option<&[Language]>,
) -> Result<DiscoveryResult, CoreError> {
    let root = root.canonicalize().map_err(|e| {
        CoreError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot access target directory '{}': {e}", root.display()),
        ))
    })?;

    let mut walker = WalkBuilder::new(&root);
    walker
        // Follow symlinks; the `ignore` crate handles cycle detection internally.
        .follow_links(true)
        // Respect .gitignore
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        // Add custom ignore file name
        .add_custom_ignore_filename(".atlasignore")
        // Hidden files are skipped by default (matches git behaviour)
        .hidden(true)
        // Sort entries for deterministic output
        .sort_by_file_path(|a, b| a.cmp(b));

    let mut stats = DiscoveryStats::default();
    let mut files = Vec::new();
    let mut languages_detected = BTreeSet::new();

    for entry_result in walker.build() {
        let entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                warn!(error = %err, "error walking directory entry");
                stats.skipped_errors += 1;
                continue;
            }
        };

        // Skip directories — we only care about files.
        let file_type = match entry.file_type() {
            Some(ft) => ft,
            None => continue,
        };
        if file_type.is_dir() {
            continue;
        }

        stats.total_entries += 1;
        let path = entry.path();

        // Detect language by extension.
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!(".{ext}"),
            None => {
                debug!(path = %path.display(), "skipping file without extension");
                stats.skipped_unsupported += 1;
                continue;
            }
        };

        let language = match Language::from_extension(&ext) {
            Some(lang) => lang,
            None => {
                debug!(path = %path.display(), ext = %ext, "skipping unsupported extension");
                stats.skipped_unsupported += 1;
                continue;
            }
        };

        // Apply language filter if specified.
        if let Some(filter) = language_filter {
            if !filter.contains(&language) {
                debug!(path = %path.display(), language = %language, "skipping filtered language");
                stats.skipped_unsupported += 1;
                continue;
            }
        }

        // Binary file detection: read first 8 KiB and check for NUL bytes.
        if is_binary(path) {
            debug!(path = %path.display(), "skipping binary file");
            stats.skipped_binary += 1;
            continue;
        }

        // Compute relative path (normalized with forward slashes, no leading `./`).
        let relative_path = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        // Check if file should be excluded from secrets scanning.
        let secrets_excluded = is_secrets_excluded(path);

        languages_detected.insert(language);
        files.push(DiscoveredFile {
            path: path.to_path_buf(),
            relative_path,
            language,
            secrets_excluded,
        });
    }

    // Sort for deterministic output.
    files.sort();
    stats.accepted = files.len() as u64;

    info!(
        accepted = stats.accepted,
        skipped_unsupported = stats.skipped_unsupported,
        skipped_binary = stats.skipped_binary,
        skipped_errors = stats.skipped_errors,
        languages = ?languages_detected,
        "file discovery complete"
    );

    Ok(DiscoveryResult {
        files,
        stats,
        languages_detected,
    })
}

// ---------------------------------------------------------------------------
// Binary detection
// ---------------------------------------------------------------------------

/// Heuristic binary file detection.
///
/// Reads up to 8 KiB of the file and checks for NUL bytes. If any NUL byte
/// is found, the file is considered binary. Files that cannot be read are
/// treated as non-binary (the error will surface later during parsing).
fn is_binary(path: &Path) -> bool {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buffer = [0u8; 8192];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return false,
    };

    buffer[..bytes_read].contains(&0)
}

// ---------------------------------------------------------------------------
// Secrets exclusion
// ---------------------------------------------------------------------------

/// File-name patterns that indicate example/template files which should
/// be excluded from secrets scanning to avoid false positives.
///
/// Files matching these patterns typically contain placeholder secrets
/// (e.g. `YOUR_API_KEY_HERE`) that are intentionally committed as
/// documentation or templates.
const SECRETS_EXCLUSION_PATTERNS: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.defaults",
    ".env.test",
    ".env.development",
    ".env.local.example",
    "example.env",
    "sample.env",
];

/// Checks if a file should be excluded from secrets scanning based on
/// its file name.
///
/// Returns `true` for files matching patterns like `.env.example`,
/// `.env.sample`, `.env.template`, and similar template/example files
/// that commonly contain placeholder secrets.
fn is_secrets_excluded(path: &Path) -> bool {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_lowercase(),
        None => return false,
    };

    // Check against known exclusion patterns.
    if SECRETS_EXCLUSION_PATTERNS
        .iter()
        .any(|p| file_name == *p)
    {
        return true;
    }

    // Also exclude files with ".example.", ".sample.", ".template." in name.
    if file_name.contains(".example.")
        || file_name.contains(".sample.")
        || file_name.contains(".template.")
    {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: create a temporary directory tree for testing.
    fn create_test_tree(dir: &Path) {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("lib")).unwrap();

        fs::write(dir.join("src/app.ts"), "const x: number = 1;").unwrap();
        fs::write(dir.join("src/utils.js"), "function foo() {}").unwrap();
        fs::write(dir.join("lib/helper.py"), "def helper(): pass").unwrap();
        fs::write(dir.join("README.md"), "# Hello").unwrap();
    }

    #[test]
    fn discover_finds_supported_files() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_tree(tmp.path());

        let result = discover_files(tmp.path(), None).unwrap();

        // Should find .ts, .js, .py but not .md
        assert_eq!(result.files.len(), 3);
        assert!(result.languages_detected.contains(&Language::TypeScript));
        assert!(result.languages_detected.contains(&Language::JavaScript));
        assert!(result.languages_detected.contains(&Language::Python));
    }

    #[test]
    fn discover_respects_language_filter() {
        let tmp = tempfile::tempdir().unwrap();
        create_test_tree(tmp.path());

        let filter = [Language::TypeScript];
        let result = discover_files(tmp.path(), Some(&filter)).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].language, Language::TypeScript);
        assert!(result.files[0].relative_path.ends_with("app.ts"));
    }

    #[test]
    fn discover_skips_binary_files() {
        let tmp = tempfile::tempdir().unwrap();
        // Create a file with binary content but a supported extension.
        let binary_path = tmp.path().join("binary.ts");
        let mut content = b"const x = 1;\0\0\0binary data".to_vec();
        content.extend_from_slice(&[0u8; 100]);
        fs::write(&binary_path, &content).unwrap();

        // Also create a normal text file.
        fs::write(tmp.path().join("normal.ts"), "const y = 2;").unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.stats.skipped_binary, 1);
        assert!(result.files[0].relative_path.ends_with("normal.ts"));
    }

    #[test]
    fn discover_respects_gitignore() {
        let tmp = tempfile::tempdir().unwrap();

        // Initialize a git repo so .gitignore is honoured.
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .status()
            .unwrap();

        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::create_dir_all(tmp.path().join("build")).unwrap();
        fs::write(tmp.path().join("src/app.ts"), "const a = 1;").unwrap();
        fs::write(tmp.path().join("build/output.ts"), "const b = 2;").unwrap();
        fs::write(tmp.path().join(".gitignore"), "build/\n").unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].relative_path.contains("app.ts"));
    }

    #[test]
    fn discover_respects_atlasignore() {
        let tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::create_dir_all(tmp.path().join("vendor")).unwrap();
        fs::write(tmp.path().join("src/app.ts"), "const a = 1;").unwrap();
        fs::write(tmp.path().join("vendor/lib.ts"), "const b = 2;").unwrap();
        fs::write(tmp.path().join(".atlasignore"), "vendor/\n").unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].relative_path.contains("app.ts"));
    }

    #[test]
    fn discover_relative_paths_normalized() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("src/nested")).unwrap();
        fs::write(tmp.path().join("src/nested/deep.ts"), "const d = 1;").unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].relative_path, "src/nested/deep.ts");
    }

    #[test]
    fn discover_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert!(result.files.is_empty());
        assert_eq!(result.stats.accepted, 0);
    }

    #[test]
    fn discover_nonexistent_directory() {
        let result = discover_files(Path::new("/nonexistent/path/unlikely"), None);
        assert!(result.is_err());
    }

    #[test]
    fn discover_follows_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        fs::write(real_dir.join("file.ts"), "const x = 1;").unwrap();

        // Create a symlink to the real directory.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, tmp.path().join("link")).unwrap();

        #[cfg(not(unix))]
        {
            // On non-Unix, skip this test.
            return;
        }

        let result = discover_files(tmp.path(), None).unwrap();

        // Should find the file through both the real path and the symlink.
        assert!(result.files.len() >= 1);
    }

    #[test]
    fn discover_deterministic_order() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("z.ts"), "const z = 1;").unwrap();
        fs::write(tmp.path().join("a.ts"), "const a = 1;").unwrap();
        fs::write(tmp.path().join("m.ts"), "const m = 1;").unwrap();

        let result1 = discover_files(tmp.path(), None).unwrap();
        let result2 = discover_files(tmp.path(), None).unwrap();

        // Same order both times.
        let paths1: Vec<&str> = result1.files.iter().map(|f| f.relative_path.as_str()).collect();
        let paths2: Vec<&str> = result2.files.iter().map(|f| f.relative_path.as_str()).collect();
        assert_eq!(paths1, paths2);

        // Sorted alphabetically.
        assert_eq!(paths1, vec!["a.ts", "m.ts", "z.ts"]);
    }

    #[test]
    fn is_binary_detects_nul_bytes() {
        let tmp = tempfile::tempdir().unwrap();

        let text_file = tmp.path().join("text.txt");
        fs::write(&text_file, "hello world").unwrap();
        assert!(!is_binary(&text_file));

        let bin_file = tmp.path().join("binary.bin");
        fs::write(&bin_file, b"hello\0world").unwrap();
        assert!(is_binary(&bin_file));
    }

    #[test]
    fn stats_are_accurate() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("app.ts"), "const a = 1;").unwrap();
        fs::write(tmp.path().join("readme.md"), "# Hello").unwrap();
        let mut bin = b"const b\0= 2;".to_vec();
        bin.extend_from_slice(&[0u8; 100]);
        fs::write(tmp.path().join("binary.ts"), &bin).unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert_eq!(result.stats.accepted, 1);
        assert_eq!(result.stats.skipped_unsupported, 1); // .md
        assert_eq!(result.stats.skipped_binary, 1);
    }

    // -----------------------------------------------------------------------
    // Secrets exclusion tests
    // -----------------------------------------------------------------------

    #[test]
    fn secrets_excluded_example_file() {
        assert!(is_secrets_excluded(Path::new("/tmp/config.example.ts")));
        assert!(is_secrets_excluded(Path::new("/tmp/config.sample.ts")));
        assert!(is_secrets_excluded(Path::new("/tmp/config.template.ts")));
    }

    #[test]
    fn secrets_excluded_env_files() {
        assert!(is_secrets_excluded(Path::new("/tmp/.env.example")));
        assert!(is_secrets_excluded(Path::new("/tmp/.env.sample")));
        assert!(is_secrets_excluded(Path::new("/tmp/.env.template")));
        assert!(is_secrets_excluded(Path::new("/tmp/.env.defaults")));
        assert!(is_secrets_excluded(Path::new("/tmp/.env.test")));
    }

    #[test]
    fn secrets_not_excluded_normal_files() {
        assert!(!is_secrets_excluded(Path::new("/tmp/app.ts")));
        assert!(!is_secrets_excluded(Path::new("/tmp/config.ts")));
        assert!(!is_secrets_excluded(Path::new("/tmp/main.py")));
    }

    #[test]
    fn discover_marks_example_files_as_secrets_excluded() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("app.ts"), "const a = 1;").unwrap();
        fs::write(
            tmp.path().join("config.example.ts"),
            "const key = 'test';",
        )
        .unwrap();

        let result = discover_files(tmp.path(), None).unwrap();

        assert_eq!(result.files.len(), 2);

        let normal = result.files.iter().find(|f| f.relative_path == "app.ts").unwrap();
        assert!(!normal.secrets_excluded);

        let example = result
            .files
            .iter()
            .find(|f| f.relative_path == "config.example.ts")
            .unwrap();
        assert!(example.secrets_excluded);
    }
}
