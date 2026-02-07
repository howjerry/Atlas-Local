//! Baseline management for Atlas Local SAST.
//!
//! A [`Baseline`] captures a snapshot of known findings (by fingerprint) at a
//! point in time. Subsequent scans can be diffed against the baseline to
//! identify new, baselined (already known), and resolved findings.
//!
//! # Schema
//!
//! Baselines use schema version `"1.0.0"` and are stored as pretty-printed
//! JSON files. Fingerprints are SHA-256 hex strings (64 lowercase hex chars),
//! stored in sorted order with no duplicates.
//!
//! # Workflow
//!
//! 1. Run a scan and collect fingerprints.
//! 2. Call [`create_baseline`] to build a new [`Baseline`].
//! 3. Call [`save_baseline`] to persist it to disk.
//! 4. On subsequent scans, call [`load_baseline`] and [`diff_findings`] to
//!    classify findings as new, baselined, or resolved.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The current baseline schema version.
pub const BASELINE_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when loading, saving, or validating a baseline.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    /// An I/O error occurred while reading or writing a baseline file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The JSON content could not be parsed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The baseline failed semantic validation.
    #[error("validation error: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Baseline struct
// ---------------------------------------------------------------------------

/// A snapshot of known findings captured at a specific point in time.
///
/// All fingerprints must be 64-character lowercase hex strings (SHA-256),
/// stored in sorted order with no duplicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version (must be `"1.0.0"`).
    pub schema_version: String,

    /// Unique identifier for the scan that produced this baseline.
    pub scan_id: String,

    /// ISO 8601 timestamp of when this baseline was created.
    pub created_at: String,

    /// Version of the Atlas engine that produced this baseline.
    pub engine_version: String,

    /// Sorted, unique SHA-256 hex fingerprints of baselined findings.
    pub fingerprints: Vec<String>,

    /// Number of findings in this baseline (must equal `fingerprints.len()`).
    pub findings_count: u32,

    /// Optional metadata associated with this baseline.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` if the string is a valid 64-character lowercase hex string.
fn is_valid_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl Baseline {
    /// Validates semantic invariants on this baseline.
    ///
    /// # Checks
    ///
    /// 1. `schema_version` must be `"1.0.0"`.
    /// 2. `findings_count` must equal `fingerprints.len()`.
    /// 3. All fingerprints must be exactly 64-character lowercase hex strings.
    /// 4. Fingerprints must be sorted in ascending order.
    /// 5. Fingerprints must be unique (no consecutive duplicates).
    ///
    /// # Errors
    ///
    /// Returns [`BaselineError::Validation`] if any check fails.
    pub fn validate(&self) -> Result<(), BaselineError> {
        // 1. Schema version check.
        if self.schema_version != "1.0.0" {
            return Err(BaselineError::Validation(format!(
                "unsupported schema_version '{}', expected '1.0.0'",
                self.schema_version,
            )));
        }

        // 2. Findings count check.
        if self.findings_count as usize != self.fingerprints.len() {
            return Err(BaselineError::Validation(format!(
                "findings_count ({}) does not match fingerprints length ({})",
                self.findings_count,
                self.fingerprints.len(),
            )));
        }

        // 3. Fingerprint format check.
        for (i, fp) in self.fingerprints.iter().enumerate() {
            if !is_valid_fingerprint(fp) {
                return Err(BaselineError::Validation(format!(
                    "fingerprint at index {i} is not a valid 64-char lowercase hex string: '{fp}'",
                )));
            }
        }

        // 4. Sorted order check.
        for window in self.fingerprints.windows(2) {
            if window[0] > window[1] {
                return Err(BaselineError::Validation(format!(
                    "fingerprints are not sorted: '{}' > '{}'",
                    window[0], window[1],
                )));
            }
        }

        // 5. Uniqueness check (consecutive duplicates in a sorted list).
        for window in self.fingerprints.windows(2) {
            if window[0] == window[1] {
                return Err(BaselineError::Validation(format!(
                    "duplicate fingerprint found: '{}'",
                    window[0],
                )));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load a [`Baseline`] from a JSON file on disk.
///
/// The file is read, deserialized, and validated before returning.
///
/// # Errors
///
/// Returns [`BaselineError::Io`] if the file cannot be read,
/// [`BaselineError::Json`] if the JSON is malformed, or
/// [`BaselineError::Validation`] if semantic validation fails.
pub fn load_baseline(path: &Path) -> Result<Baseline, BaselineError> {
    let content = std::fs::read_to_string(path)?;
    load_baseline_from_str(&content)
}

/// Parse a [`Baseline`] from a JSON string.
///
/// The JSON is deserialized and validated before returning.
///
/// # Errors
///
/// Returns [`BaselineError::Json`] if the JSON is malformed, or
/// [`BaselineError::Validation`] if semantic validation fails.
pub fn load_baseline_from_str(json: &str) -> Result<Baseline, BaselineError> {
    let baseline: Baseline = serde_json::from_str(json)?;
    baseline.validate()?;
    Ok(baseline)
}

// ---------------------------------------------------------------------------
// Creation (T053)
// ---------------------------------------------------------------------------

/// Create a new [`Baseline`] from a set of fingerprints.
///
/// The fingerprints are cloned, sorted, and deduplicated. The
/// `findings_count` is set to the number of unique fingerprints,
/// `created_at` is set to the current UTC time in RFC 3339 format,
/// and `schema_version` is set to [`BASELINE_SCHEMA_VERSION`].
#[must_use]
pub fn create_baseline(
    scan_id: &str,
    engine_version: &str,
    fingerprints: &[String],
    metadata: BTreeMap<String, serde_json::Value>,
) -> Baseline {
    let mut fps = fingerprints.to_vec();
    fps.sort();
    fps.dedup();

    let findings_count = fps.len() as u32;

    Baseline {
        schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        scan_id: scan_id.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        engine_version: engine_version.to_string(),
        fingerprints: fps,
        findings_count,
        metadata,
    }
}

/// Save a [`Baseline`] as pretty-printed JSON to disk.
///
/// # Errors
///
/// Returns [`BaselineError::Io`] if the file cannot be written, or
/// [`BaselineError::Json`] if serialization fails.
pub fn save_baseline(baseline: &Baseline, path: &Path) -> Result<(), BaselineError> {
    let json = serde_json::to_string_pretty(baseline)?;
    std::fs::write(path, json)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Diffing (T054)
// ---------------------------------------------------------------------------

/// Result of diffing current findings against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiffResult {
    /// Number of new findings (not in the baseline).
    pub new_count: u32,

    /// Number of baselined findings (already in the baseline).
    pub baselined_count: u32,

    /// Number of resolved findings (in the baseline but not in current).
    pub resolved_count: u32,

    /// Fingerprints of new findings.
    pub new_fingerprints: Vec<String>,

    /// Fingerprints of baselined (already known) findings.
    pub baselined_fingerprints: Vec<String>,

    /// Fingerprints of resolved findings (no longer present).
    pub resolved_fingerprints: Vec<String>,
}

/// Diff current scan fingerprints against a baseline.
///
/// Classifies each fingerprint as:
/// - **New**: present in `current_fingerprints` but not in `baseline`.
/// - **Baselined**: present in both `current_fingerprints` and `baseline`.
/// - **Resolved**: present in `baseline` but not in `current_fingerprints`.
///
/// Uses a [`HashSet`] for O(1) lookups against the baseline.
#[must_use]
pub fn diff_findings(
    current_fingerprints: &[String],
    baseline: &Baseline,
) -> BaselineDiffResult {
    let baseline_set: HashSet<&str> = baseline
        .fingerprints
        .iter()
        .map(String::as_str)
        .collect();

    let current_set: HashSet<&str> = current_fingerprints
        .iter()
        .map(String::as_str)
        .collect();

    let mut new_fingerprints = Vec::new();
    let mut baselined_fingerprints = Vec::new();

    for fp in current_fingerprints {
        if baseline_set.contains(fp.as_str()) {
            baselined_fingerprints.push(fp.clone());
        } else {
            new_fingerprints.push(fp.clone());
        }
    }

    let mut resolved_fingerprints: Vec<String> = baseline
        .fingerprints
        .iter()
        .filter(|fp| !current_set.contains(fp.as_str()))
        .cloned()
        .collect();

    // Ensure deterministic output order.
    new_fingerprints.sort();
    new_fingerprints.dedup();
    baselined_fingerprints.sort();
    baselined_fingerprints.dedup();
    resolved_fingerprints.sort();

    BaselineDiffResult {
        new_count: new_fingerprints.len() as u32,
        baselined_count: baselined_fingerprints.len() as u32,
        resolved_count: resolved_fingerprints.len() as u32,
        new_fingerprints,
        baselined_fingerprints,
        resolved_fingerprints,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // -- Helpers ------------------------------------------------------------

    /// Creates a valid 64-char lowercase hex fingerprint from a simple index.
    /// Produces deterministic, unique fingerprints like "0000...0001".
    fn make_fingerprint(index: u32) -> String {
        format!("{index:064x}")
    }

    /// Builds a minimal valid baseline for testing.
    fn valid_baseline() -> Baseline {
        let fps = vec![make_fingerprint(1), make_fingerprint(2), make_fingerprint(3)];
        Baseline {
            schema_version: "1.0.0".to_string(),
            scan_id: "test-scan-001".to_string(),
            created_at: "2026-01-15T10:30:00+00:00".to_string(),
            engine_version: "0.1.0".to_string(),
            fingerprints: fps,
            findings_count: 3,
            metadata: BTreeMap::new(),
        }
    }

    // ======================================================================
    // T052: Baseline struct and validation tests
    // ======================================================================

    #[test]
    fn validate_ok() {
        let baseline = valid_baseline();
        assert!(baseline.validate().is_ok());
    }

    #[test]
    fn validate_bad_schema_version() {
        let mut baseline = valid_baseline();
        baseline.schema_version = "2.0.0".to_string();

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("unsupported schema_version"));
                assert!(msg.contains("2.0.0"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_findings_count_mismatch() {
        let mut baseline = valid_baseline();
        baseline.findings_count = 999;

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("findings_count"));
                assert!(msg.contains("999"));
                assert!(msg.contains("3"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_bad_fingerprint_non_hex() {
        let mut baseline = valid_baseline();
        // Replace first fingerprint with non-hex characters.
        baseline.fingerprints[0] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("not a valid 64-char lowercase hex"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_bad_fingerprint_wrong_length() {
        let mut baseline = valid_baseline();
        baseline.fingerprints[0] = "abcd".to_string();

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("not a valid 64-char lowercase hex"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_bad_fingerprint_uppercase() {
        let mut baseline = valid_baseline();
        baseline.fingerprints[0] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("not a valid 64-char lowercase hex"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_unsorted_fingerprints() {
        let mut baseline = valid_baseline();
        // Reverse the sorted order.
        baseline.fingerprints.reverse();

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("not sorted"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_duplicate_fingerprints() {
        let fp = make_fingerprint(1);
        let baseline = Baseline {
            schema_version: "1.0.0".to_string(),
            scan_id: "test".to_string(),
            created_at: "2026-01-15T10:30:00+00:00".to_string(),
            engine_version: "0.1.0".to_string(),
            fingerprints: vec![fp.clone(), fp.clone()],
            findings_count: 2,
            metadata: BTreeMap::new(),
        };

        let err = baseline.validate().unwrap_err();
        match err {
            BaselineError::Validation(msg) => {
                assert!(msg.contains("duplicate fingerprint"));
            }
            other => panic!("expected Validation error, got: {other}"),
        }
    }

    #[test]
    fn validate_empty_baseline_ok() {
        let baseline = Baseline {
            schema_version: "1.0.0".to_string(),
            scan_id: "empty-scan".to_string(),
            created_at: "2026-01-15T10:30:00+00:00".to_string(),
            engine_version: "0.1.0".to_string(),
            fingerprints: vec![],
            findings_count: 0,
            metadata: BTreeMap::new(),
        };
        assert!(baseline.validate().is_ok());
    }

    #[test]
    fn json_roundtrip() {
        let baseline = valid_baseline();
        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let back: Baseline = serde_json::from_str(&json).unwrap();

        assert_eq!(back.schema_version, baseline.schema_version);
        assert_eq!(back.scan_id, baseline.scan_id);
        assert_eq!(back.created_at, baseline.created_at);
        assert_eq!(back.engine_version, baseline.engine_version);
        assert_eq!(back.fingerprints, baseline.fingerprints);
        assert_eq!(back.findings_count, baseline.findings_count);
        assert!(back.metadata.is_empty());
    }

    #[test]
    fn json_roundtrip_with_metadata() {
        let mut metadata = BTreeMap::new();
        metadata.insert("branch".to_string(), serde_json::Value::String("main".to_string()));
        metadata.insert("commit_count".to_string(), serde_json::json!(42));

        let baseline = Baseline {
            metadata,
            ..valid_baseline()
        };

        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let back: Baseline = serde_json::from_str(&json).unwrap();

        assert_eq!(back.metadata.len(), 2);
        assert_eq!(back.metadata["branch"], serde_json::Value::String("main".to_string()));
        assert_eq!(back.metadata["commit_count"], serde_json::json!(42));
    }

    #[test]
    fn load_from_str_ok() {
        let json = serde_json::to_string_pretty(&valid_baseline()).unwrap();
        let loaded = load_baseline_from_str(&json).unwrap();

        assert_eq!(loaded.schema_version, "1.0.0");
        assert_eq!(loaded.scan_id, "test-scan-001");
        assert_eq!(loaded.fingerprints.len(), 3);
        assert_eq!(loaded.findings_count, 3);
    }

    #[test]
    fn load_from_str_invalid_json() {
        let err = load_baseline_from_str("this is not json {{{").unwrap_err();
        assert!(matches!(err, BaselineError::Json(_)));
    }

    #[test]
    fn load_from_str_validates() {
        // Valid JSON but bad schema version.
        let mut baseline = valid_baseline();
        baseline.schema_version = "99.0.0".to_string();
        let json = serde_json::to_string(&baseline).unwrap();

        let err = load_baseline_from_str(&json).unwrap_err();
        assert!(matches!(err, BaselineError::Validation(_)));
    }

    #[test]
    fn load_baseline_io_error_on_missing_file() {
        let err = load_baseline(Path::new("/nonexistent/baseline.json")).unwrap_err();
        assert!(matches!(err, BaselineError::Io(_)));
    }

    // ======================================================================
    // T053: Baseline creation tests
    // ======================================================================

    #[test]
    fn create_baseline_sorts_fingerprints() {
        let fps = vec![make_fingerprint(3), make_fingerprint(1), make_fingerprint(2)];
        let baseline = create_baseline("scan-1", "0.1.0", &fps, BTreeMap::new());

        assert_eq!(baseline.fingerprints[0], make_fingerprint(1));
        assert_eq!(baseline.fingerprints[1], make_fingerprint(2));
        assert_eq!(baseline.fingerprints[2], make_fingerprint(3));
    }

    #[test]
    fn create_baseline_deduplicates() {
        let fp1 = make_fingerprint(1);
        let fp2 = make_fingerprint(2);
        let fps = vec![fp1.clone(), fp2.clone(), fp1.clone(), fp2.clone()];
        let baseline = create_baseline("scan-1", "0.1.0", &fps, BTreeMap::new());

        assert_eq!(baseline.fingerprints.len(), 2);
        assert_eq!(baseline.fingerprints, vec![fp1, fp2]);
    }

    #[test]
    fn create_baseline_sets_count() {
        let fps = vec![make_fingerprint(10), make_fingerprint(20), make_fingerprint(30)];
        let baseline = create_baseline("scan-1", "0.1.0", &fps, BTreeMap::new());

        assert_eq!(baseline.findings_count, 3);
        assert_eq!(baseline.findings_count as usize, baseline.fingerprints.len());
    }

    #[test]
    fn create_baseline_sets_schema_version() {
        let baseline = create_baseline("scan-1", "0.1.0", &[], BTreeMap::new());
        assert_eq!(baseline.schema_version, BASELINE_SCHEMA_VERSION);
    }

    #[test]
    fn create_baseline_sets_created_at() {
        let baseline = create_baseline("scan-1", "0.1.0", &[], BTreeMap::new());
        // created_at should be a non-empty RFC 3339 string.
        assert!(!baseline.created_at.is_empty());
        // Basic sanity check: contains a date-like pattern.
        assert!(baseline.created_at.contains('T'));
    }

    #[test]
    fn create_baseline_with_metadata() {
        let mut metadata = BTreeMap::new();
        metadata.insert("branch".to_string(), serde_json::Value::String("main".to_string()));
        metadata.insert("ci_run".to_string(), serde_json::json!(12345));

        let fps = vec![make_fingerprint(1)];
        let baseline = create_baseline("scan-1", "0.1.0", &fps, metadata);

        assert_eq!(baseline.metadata.len(), 2);
        assert_eq!(baseline.metadata["branch"], serde_json::Value::String("main".to_string()));
        assert_eq!(baseline.metadata["ci_run"], serde_json::json!(12345));
    }

    #[test]
    fn create_baseline_empty_fingerprints() {
        let baseline = create_baseline("scan-1", "0.1.0", &[], BTreeMap::new());
        assert!(baseline.fingerprints.is_empty());
        assert_eq!(baseline.findings_count, 0);
    }

    #[test]
    fn create_baseline_validates_successfully() {
        let fps = vec![make_fingerprint(5), make_fingerprint(3), make_fingerprint(1)];
        let baseline = create_baseline("scan-1", "0.1.0", &fps, BTreeMap::new());
        // A baseline created by create_baseline should always pass validation.
        assert!(baseline.validate().is_ok());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let fps = vec![make_fingerprint(10), make_fingerprint(5), make_fingerprint(20)];
        let mut metadata = BTreeMap::new();
        metadata.insert("key".to_string(), serde_json::Value::String("value".to_string()));

        let baseline = create_baseline("roundtrip-scan", "0.2.0", &fps, metadata);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-baseline.json");

        save_baseline(&baseline, &path).unwrap();
        let loaded = load_baseline(&path).unwrap();

        assert_eq!(loaded.schema_version, baseline.schema_version);
        assert_eq!(loaded.scan_id, baseline.scan_id);
        assert_eq!(loaded.created_at, baseline.created_at);
        assert_eq!(loaded.engine_version, baseline.engine_version);
        assert_eq!(loaded.fingerprints, baseline.fingerprints);
        assert_eq!(loaded.findings_count, baseline.findings_count);
        assert_eq!(loaded.metadata, baseline.metadata);
    }

    // ======================================================================
    // T054: Baseline diffing tests
    // ======================================================================

    #[test]
    fn diff_no_baseline_matches() {
        // All current fingerprints are new.
        let baseline = create_baseline(
            "old-scan",
            "0.1.0",
            &[make_fingerprint(1), make_fingerprint(2)],
            BTreeMap::new(),
        );

        let current = vec![make_fingerprint(10), make_fingerprint(20)];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 2);
        assert_eq!(diff.baselined_count, 0);
        assert_eq!(diff.resolved_count, 2);
        assert_eq!(diff.new_fingerprints, vec![make_fingerprint(10), make_fingerprint(20)]);
        assert!(diff.baselined_fingerprints.is_empty());
        assert_eq!(diff.resolved_fingerprints, vec![make_fingerprint(1), make_fingerprint(2)]);
    }

    #[test]
    fn diff_all_baselined() {
        // All current fingerprints match the baseline.
        let fps = vec![make_fingerprint(1), make_fingerprint(2), make_fingerprint(3)];
        let baseline = create_baseline("old-scan", "0.1.0", &fps, BTreeMap::new());

        let current = vec![make_fingerprint(1), make_fingerprint(2), make_fingerprint(3)];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.baselined_count, 3);
        assert_eq!(diff.resolved_count, 0);
        assert!(diff.new_fingerprints.is_empty());
        assert_eq!(diff.baselined_fingerprints.len(), 3);
        assert!(diff.resolved_fingerprints.is_empty());
    }

    #[test]
    fn diff_mixed_new_and_baselined() {
        let baseline = create_baseline(
            "old-scan",
            "0.1.0",
            &[make_fingerprint(1), make_fingerprint(2), make_fingerprint(3)],
            BTreeMap::new(),
        );

        // fp(1) and fp(3) are baselined; fp(10) is new.
        let current = vec![make_fingerprint(1), make_fingerprint(3), make_fingerprint(10)];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 1);
        assert_eq!(diff.baselined_count, 2);
        assert_eq!(diff.resolved_count, 1); // fp(2) was resolved
        assert_eq!(diff.new_fingerprints, vec![make_fingerprint(10)]);
        assert_eq!(diff.baselined_fingerprints, vec![make_fingerprint(1), make_fingerprint(3)]);
        assert_eq!(diff.resolved_fingerprints, vec![make_fingerprint(2)]);
    }

    #[test]
    fn diff_with_resolved() {
        // Baseline has entries not in current -> they are resolved.
        let baseline = create_baseline(
            "old-scan",
            "0.1.0",
            &[
                make_fingerprint(1),
                make_fingerprint(2),
                make_fingerprint(3),
                make_fingerprint(4),
            ],
            BTreeMap::new(),
        );

        // Only fp(1) and fp(3) remain.
        let current = vec![make_fingerprint(1), make_fingerprint(3)];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.baselined_count, 2);
        assert_eq!(diff.resolved_count, 2);
        assert!(diff.new_fingerprints.is_empty());
        assert_eq!(diff.resolved_fingerprints, vec![make_fingerprint(2), make_fingerprint(4)]);
    }

    #[test]
    fn diff_empty_baseline() {
        let baseline = create_baseline("old-scan", "0.1.0", &[], BTreeMap::new());

        let current = vec![make_fingerprint(1), make_fingerprint(2)];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 2);
        assert_eq!(diff.baselined_count, 0);
        assert_eq!(diff.resolved_count, 0);
        assert_eq!(diff.new_fingerprints.len(), 2);
        assert!(diff.baselined_fingerprints.is_empty());
        assert!(diff.resolved_fingerprints.is_empty());
    }

    #[test]
    fn diff_empty_current() {
        // All baseline entries are resolved.
        let baseline = create_baseline(
            "old-scan",
            "0.1.0",
            &[make_fingerprint(1), make_fingerprint(2), make_fingerprint(3)],
            BTreeMap::new(),
        );

        let current: Vec<String> = vec![];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.baselined_count, 0);
        assert_eq!(diff.resolved_count, 3);
        assert!(diff.new_fingerprints.is_empty());
        assert!(diff.baselined_fingerprints.is_empty());
        assert_eq!(diff.resolved_fingerprints.len(), 3);
    }

    #[test]
    fn diff_both_empty() {
        let baseline = create_baseline("old-scan", "0.1.0", &[], BTreeMap::new());
        let current: Vec<String> = vec![];
        let diff = diff_findings(&current, &baseline);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.baselined_count, 0);
        assert_eq!(diff.resolved_count, 0);
    }
}
