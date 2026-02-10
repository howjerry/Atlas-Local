//! Atlas Events JSONL v1.0.0 formatter.
//!
//! Produces line-delimited JSON (JSONL) events for streaming ingestion by
//! SIEM systems, log aggregators, and real-time dashboards. Each line is a
//! self-contained JSON object representing a discrete scan lifecycle event.
//!
//! # Event sequence
//!
//! A complete scan produces events in this order:
//!
//! 1. `scan_started` -- emitted once at the beginning.
//! 2. `finding_detected` -- one per finding (zero or more).
//! 3. `gate_evaluated` -- emitted only when a gate result is provided.
//! 4. `scan_completed` -- emitted once at the end.
//!
//! # Determinism
//!
//! When `deterministic` is `true`, all timestamps are replaced with
//! `"1970-01-01T00:00:00Z"` so that identical inputs produce byte-identical
//! output. The `correlation_id` is always deterministic (SHA-256 of
//! `target_path + engine_version`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use atlas_analysis::Finding;
use atlas_core::engine::ScanResult;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current schema version for the Atlas Events JSONL format.
pub const JSONL_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// Discriminator for the kind of event encoded in a JSONL line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Scan has started.
    ScanStarted,
    /// Scan has completed.
    ScanCompleted,
    /// A single file was analyzed.
    FileAnalyzed,
    /// A security/quality finding was detected.
    FindingDetected,
    /// The quality gate was evaluated.
    GateEvaluated,
    /// An error occurred during the scan.
    ErrorOccurred,
}

// ---------------------------------------------------------------------------
// Event struct
// ---------------------------------------------------------------------------

/// A single JSONL event (one line in the output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Schema version identifier (always `"1.0.0"`).
    pub schema_version: String,
    /// The type of event this line represents.
    pub event_type: EventType,
    /// ISO 8601 timestamp of when the event was produced.
    pub timestamp: String,
    /// Correlation ID that groups all events from a single scan run.
    pub correlation_id: String,
    /// Event-specific payload; structure varies by `event_type`.
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Correlation ID computation
// ---------------------------------------------------------------------------

/// Computes a deterministic correlation ID as a SHA-256 hex digest of
/// `target_path` concatenated with `engine_version`.
#[must_use]
pub fn compute_correlation_id(target_path: &str, engine_version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target_path.as_bytes());
    hasher.update(engine_version.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Format scan results as JSONL events.
///
/// Produces one JSON object per line:
/// 1. `scan_started` event
/// 2. One `finding_detected` event per finding
/// 3. `gate_evaluated` event (if `gate_status` provided)
/// 4. `scan_completed` event
///
/// The `correlation_id` is a deterministic SHA-256 hash of
/// `target_path + engine_version`, ensuring same inputs produce same
/// correlation IDs.
///
/// When `deterministic` is `true`, timestamps use a fixed value
/// `"1970-01-01T00:00:00Z"` for reproducible output.
///
/// # Arguments
///
/// - `scan_result` -- the scan pipeline result containing findings and statistics.
/// - `target_path` -- the absolute path to the scanned directory.
/// - `engine_version` -- the Atlas engine version string.
/// - `gate_status` -- optional gate evaluation result (e.g. `"PASS"`, `"FAIL"`).
/// - `deterministic` -- whether to use fixed timestamps for reproducible output.
///
/// # Returns
///
/// A JSONL string with one compact JSON object per line, ending with a
/// trailing newline.
#[must_use]
pub fn format_jsonl(
    scan_result: &ScanResult,
    target_path: &str,
    engine_version: &str,
    gate_status: Option<&str>,
    deterministic: bool,
) -> String {
    let correlation_id = compute_correlation_id(target_path, engine_version);

    let timestamp = if deterministic {
        "1970-01-01T00:00:00Z".to_string()
    } else {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };

    let mut events: Vec<Event> = Vec::new();

    // 1. scan_started
    events.push(Event {
        schema_version: JSONL_SCHEMA_VERSION.to_string(),
        event_type: EventType::ScanStarted,
        timestamp: timestamp.clone(),
        correlation_id: correlation_id.clone(),
        data: serde_json::json!({
            "scan_id": correlation_id,
            "engine_version": engine_version,
            "target_path": target_path,
        }),
    });

    // 2. finding_detected (one per finding)
    for finding in &scan_result.findings {
        events.push(make_finding_event(finding, &timestamp, &correlation_id));
    }

    // 3. gate_evaluated (optional)
    if let Some(status) = gate_status {
        events.push(Event {
            schema_version: JSONL_SCHEMA_VERSION.to_string(),
            event_type: EventType::GateEvaluated,
            timestamp: timestamp.clone(),
            correlation_id: correlation_id.clone(),
            data: serde_json::json!({
                "gate_result": status,
            }),
        });
    }

    // 4. scan_completed
    events.push(Event {
        schema_version: JSONL_SCHEMA_VERSION.to_string(),
        event_type: EventType::ScanCompleted,
        timestamp: timestamp.clone(),
        correlation_id: correlation_id.clone(),
        data: serde_json::json!({
            "scan_id": correlation_id,
            "files_scanned": scan_result.files_scanned,
            "findings_count": scan_result.findings.len(),
            "gate_result": gate_status,
        }),
    });

    // Serialize each event as compact JSON, one per line, with trailing newline.
    let mut output = String::new();
    for event in &events {
        let line = serde_json::to_string(event).expect("event serialization must not fail");
        output.push_str(&line);
        output.push('\n');
    }

    output
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Builds a `finding_detected` event from a single `Finding`.
fn make_finding_event(finding: &Finding, timestamp: &str, correlation_id: &str) -> Event {
    let mut data = serde_json::json!({
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity.to_string(),
        "category": finding.category.to_string(),
        "file_path": finding.file_path,
        "line": finding.line_range.start_line,
    });

    if let Some(ref ds) = finding.diff_status {
        data["diff_status"] = serde_json::json!(ds.to_string());
    }

    Event {
        schema_version: JSONL_SCHEMA_VERSION.to_string(),
        event_type: EventType::FindingDetected,
        timestamp: timestamp.to_string(),
        correlation_id: correlation_id.to_string(),
        data,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use atlas_analysis::{FindingBuilder, LineRange};
    use atlas_core::Language;
    use atlas_core::engine::ScanResult;
    use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};

    // -- Test helpers ---------------------------------------------------------

    /// Creates a sample Finding with the given severity.
    fn make_finding(severity: Severity, rule_id: &str) -> Finding {
        FindingBuilder::new()
            .rule_id(rule_id)
            .severity(severity)
            .category(Category::Security)
            .cwe_id("CWE-89")
            .file_path("src/app.ts")
            .line_range(LineRange::new(10, 1, 12, 30).unwrap())
            .snippet("const q = sql + input;")
            .description("SQL injection risk")
            .remediation("Use parameterized queries.")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap()
    }

    /// Creates a ScanResult with the given findings.
    fn make_scan_result(findings: Vec<Finding>) -> ScanResult {
        let summary = atlas_core::engine::FindingsSummary::from_findings(&findings);
        ScanResult {
            findings,
            files_scanned: 5,
            files_skipped: 1,
            languages_detected: vec![Language::TypeScript, Language::JavaScript],
            summary,
            stats: atlas_core::engine::ScanStats::default(),
            file_metrics: vec![],
            duplication: None,
        }
    }

    /// Parses JSONL output into a vector of `serde_json::Value`.
    fn parse_events(jsonl: &str) -> Vec<serde_json::Value> {
        jsonl
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("each line must be valid JSON"))
            .collect()
    }

    // -- Tests ----------------------------------------------------------------

    #[test]
    fn jsonl_produces_multiple_lines() {
        let findings = vec![
            make_finding(Severity::High, "atlas/security/ts/sqli"),
            make_finding(Severity::Medium, "atlas/quality/ts/unused"),
        ];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project/src", "0.1.0", Some("PASS"), true);
        let events = parse_events(&output);

        // scan_started + 2 finding_detected + gate_evaluated + scan_completed = 5
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn jsonl_each_line_is_valid_json() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project/src", "0.1.0", Some("PASS"), true);

        for (i, line) in output.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "line {i} is not valid JSON: {line}");
        }
    }

    #[test]
    fn jsonl_schema_version_present() {
        let findings = vec![make_finding(Severity::High, "atlas/a")];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        for event in &events {
            assert_eq!(
                event["schema_version"].as_str().unwrap(),
                "1.0.0",
                "all events must have schema_version 1.0.0"
            );
        }
    }

    #[test]
    fn jsonl_correlation_id_consistent() {
        let findings = vec![
            make_finding(Severity::High, "atlas/a"),
            make_finding(Severity::Low, "atlas/b"),
        ];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", Some("PASS"), true);
        let events = parse_events(&output);

        let first_id = events[0]["correlation_id"].as_str().unwrap();
        for event in &events {
            assert_eq!(
                event["correlation_id"].as_str().unwrap(),
                first_id,
                "all events must share the same correlation_id"
            );
        }
    }

    #[test]
    fn jsonl_scan_started_is_first() {
        let scan_result = make_scan_result(vec![make_finding(Severity::High, "atlas/a")]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        assert_eq!(events[0]["event_type"].as_str().unwrap(), "scan_started");
    }

    #[test]
    fn jsonl_scan_completed_is_last() {
        let scan_result = make_scan_result(vec![make_finding(Severity::High, "atlas/a")]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", Some("PASS"), true);
        let events = parse_events(&output);

        assert_eq!(
            events.last().unwrap()["event_type"].as_str().unwrap(),
            "scan_completed"
        );
    }

    #[test]
    fn jsonl_finding_detected_events() {
        let findings = vec![
            make_finding(Severity::High, "atlas/a"),
            make_finding(Severity::Medium, "atlas/b"),
            make_finding(Severity::Low, "atlas/c"),
        ];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        let finding_events: Vec<_> = events
            .iter()
            .filter(|e| e["event_type"].as_str().unwrap() == "finding_detected")
            .collect();

        assert_eq!(
            finding_events.len(),
            3,
            "should have one finding_detected event per finding"
        );
    }

    #[test]
    fn jsonl_gate_evaluated_included() {
        let scan_result = make_scan_result(vec![]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", Some("FAIL"), true);
        let events = parse_events(&output);

        let gate_events: Vec<_> = events
            .iter()
            .filter(|e| e["event_type"].as_str().unwrap() == "gate_evaluated")
            .collect();

        assert_eq!(gate_events.len(), 1);
        assert_eq!(
            gate_events[0]["data"]["gate_result"].as_str().unwrap(),
            "FAIL"
        );
    }

    #[test]
    fn jsonl_no_gate_event_when_none() {
        let scan_result = make_scan_result(vec![]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        let gate_events: Vec<_> = events
            .iter()
            .filter(|e| e["event_type"].as_str().unwrap() == "gate_evaluated")
            .collect();

        assert_eq!(
            gate_events.len(),
            0,
            "no gate_evaluated event when gate_status is None"
        );
    }

    #[test]
    fn jsonl_deterministic_output() {
        let findings = vec![
            make_finding(Severity::High, "atlas/a"),
            make_finding(Severity::Medium, "atlas/b"),
        ];
        let scan_result = make_scan_result(findings);

        let output1 = format_jsonl(&scan_result, "/project", "0.1.0", Some("PASS"), true);
        let output2 = format_jsonl(&scan_result, "/project", "0.1.0", Some("PASS"), true);

        assert_eq!(
            output1, output2,
            "deterministic=true must produce identical output"
        );
    }

    #[test]
    fn jsonl_empty_findings() {
        let scan_result = make_scan_result(vec![]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        // Only scan_started + scan_completed
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event_type"].as_str().unwrap(), "scan_started");
        assert_eq!(events[1]["event_type"].as_str().unwrap(), "scan_completed");
    }

    #[test]
    fn jsonl_correlation_id_deterministic() {
        let scan_result = make_scan_result(vec![]);

        let output1 = format_jsonl(&scan_result, "/project/src", "0.1.0", None, true);
        let output2 = format_jsonl(&scan_result, "/project/src", "0.1.0", None, true);

        let events1 = parse_events(&output1);
        let events2 = parse_events(&output2);

        assert_eq!(
            events1[0]["correlation_id"].as_str().unwrap(),
            events2[0]["correlation_id"].as_str().unwrap(),
            "same inputs must produce the same correlation_id"
        );

        // Different inputs produce different correlation_id.
        let output3 = format_jsonl(&scan_result, "/other/path", "0.1.0", None, true);
        let events3 = parse_events(&output3);

        assert_ne!(
            events1[0]["correlation_id"].as_str().unwrap(),
            events3[0]["correlation_id"].as_str().unwrap(),
            "different inputs must produce different correlation_ids"
        );
    }

    #[test]
    fn jsonl_finding_data_structure() {
        let findings = vec![make_finding(Severity::High, "atlas/security/ts/sqli")];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        let finding_event = events
            .iter()
            .find(|e| e["event_type"].as_str().unwrap() == "finding_detected")
            .expect("must have a finding_detected event");

        let data = &finding_event["data"];

        // Verify all required fields are present.
        assert!(
            data["fingerprint"].is_string(),
            "finding data must have fingerprint"
        );
        assert_eq!(data["rule_id"].as_str().unwrap(), "atlas/security/ts/sqli");
        assert_eq!(data["severity"].as_str().unwrap(), "high");
        assert_eq!(data["category"].as_str().unwrap(), "security");
        assert_eq!(data["file_path"].as_str().unwrap(), "src/app.ts");
        assert_eq!(data["line"].as_u64().unwrap(), 10);
    }

    #[test]
    fn jsonl_trailing_newline() {
        let scan_result = make_scan_result(vec![]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);

        assert!(
            output.ends_with('\n'),
            "JSONL output must end with a trailing newline"
        );
    }

    #[test]
    fn jsonl_scan_completed_data() {
        let findings = vec![
            make_finding(Severity::High, "atlas/a"),
            make_finding(Severity::Medium, "atlas/b"),
        ];
        let scan_result = make_scan_result(findings);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", Some("PASS"), true);
        let events = parse_events(&output);

        let completed = events.last().unwrap();
        let data = &completed["data"];

        assert!(data["scan_id"].is_string());
        assert_eq!(data["files_scanned"].as_u64().unwrap(), 5);
        assert_eq!(data["findings_count"].as_u64().unwrap(), 2);
        assert_eq!(data["gate_result"].as_str().unwrap(), "PASS");
    }

    #[test]
    fn jsonl_scan_completed_gate_null_when_none() {
        let scan_result = make_scan_result(vec![]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        let completed = events.last().unwrap();
        assert!(
            completed["data"]["gate_result"].is_null(),
            "gate_result should be null when no gate_status is provided"
        );
    }

    #[test]
    fn jsonl_scan_started_data() {
        let scan_result = make_scan_result(vec![]);

        let output = format_jsonl(&scan_result, "/project/src", "0.2.0", None, true);
        let events = parse_events(&output);

        let started = &events[0];
        let data = &started["data"];

        assert_eq!(data["engine_version"].as_str().unwrap(), "0.2.0");
        assert_eq!(data["target_path"].as_str().unwrap(), "/project/src");
        assert!(data["scan_id"].is_string());
    }

    #[test]
    fn jsonl_no_pretty_printing() {
        let scan_result = make_scan_result(vec![make_finding(Severity::High, "atlas/a")]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);

        for line in output.lines() {
            if line.is_empty() {
                continue;
            }
            assert!(
                !line.starts_with(' ') && !line.starts_with('\t'),
                "JSONL lines must not be indented (no pretty-printing)"
            );
            // Each line should be a single-line JSON object.
            assert!(
                !line.contains('\n'),
                "JSONL lines must not contain embedded newlines"
            );
        }
    }

    #[test]
    fn jsonl_finding_includes_diff_status_when_present() {
        use atlas_analysis::DiffStatus;

        let mut finding = make_finding(Severity::High, "atlas/security/ts/sqli");
        finding.diff_status = Some(DiffStatus::New);

        let scan_result = make_scan_result(vec![finding]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        let finding_event = events
            .iter()
            .find(|e| e["event_type"].as_str().unwrap() == "finding_detected")
            .expect("must have a finding_detected event");

        assert_eq!(
            finding_event["data"]["diff_status"].as_str().unwrap(),
            "new",
            "diff_status should be included in JSONL finding data"
        );
    }

    #[test]
    fn jsonl_finding_omits_diff_status_when_none() {
        let finding = make_finding(Severity::High, "atlas/security/ts/sqli");
        assert!(finding.diff_status.is_none());

        let scan_result = make_scan_result(vec![finding]);

        let output = format_jsonl(&scan_result, "/project", "0.1.0", None, true);
        let events = parse_events(&output);

        let finding_event = events
            .iter()
            .find(|e| e["event_type"].as_str().unwrap() == "finding_detected")
            .expect("must have a finding_detected event");

        assert!(
            finding_event["data"].get("diff_status").is_none()
                || finding_event["data"]["diff_status"].is_null(),
            "diff_status should be omitted when None"
        );
    }
}
