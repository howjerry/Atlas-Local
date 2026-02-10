//! Gate evaluation engine for Atlas policy-based CI/CD gating.
//!
//! This module compares findings counts against policy thresholds to produce
//! a [`GateResult`] (PASS, FAIL, or WARN) along with [`GateDetails`] that
//! records which specific thresholds were breached.
//!
//! # Algorithm
//!
//! 1. Count findings by severity (critical, high, medium, low, info) and total.
//! 2. If `category_overrides` are provided, also count findings grouped by
//!    `(category, severity)`.
//! 3. Check `fail_on` global thresholds: for each configured threshold value,
//!    if the actual count **exceeds** the threshold, record a FAIL breach.
//! 4. Check category-specific `fail_on` overrides (security, quality, secrets):
//!    count findings within that category and compare against category thresholds.
//! 5. If any FAIL thresholds were breached, return [`GateResult::Fail`].
//! 6. Repeat steps 3-4 for `warn_on` thresholds, recording WARN breaches.
//! 7. If any WARN thresholds were breached, return [`GateResult::Warn`].
//! 8. Otherwise, return [`GateResult::Pass`].
//!
//! The threshold semantics are "max allowed": a threshold of `0` means
//! "fail/warn if there are more than 0 findings", i.e. any finding at that
//! severity triggers the gate.

use atlas_core::{Category, GateResult, Severity};
use serde::{Deserialize, Serialize};

use crate::policy::{CategoryOverrides, Thresholds};

// ---------------------------------------------------------------------------
// GateDetails
// ---------------------------------------------------------------------------

/// Result of gate evaluation, including the overall outcome and a list of
/// all thresholds that were breached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDetails {
    /// The overall gate evaluation outcome.
    pub result: GateResult,

    /// All thresholds that were breached during evaluation.
    ///
    /// Empty when `result` is [`GateResult::Pass`].
    pub breached_thresholds: Vec<BreachedThreshold>,
}

// ---------------------------------------------------------------------------
// BreachedThreshold
// ---------------------------------------------------------------------------

/// A single threshold that was exceeded during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachedThreshold {
    /// The severity level or `"total"` for the aggregate threshold.
    pub severity: String,

    /// `None` for global thresholds, `Some("security")` etc. for
    /// category-specific overrides.
    pub category: Option<String>,

    /// The configured maximum-allowed count.
    pub threshold: u32,

    /// The actual count of findings at this severity/category.
    pub actual: u32,

    /// Either `"fail"` or `"warn"`, indicating which gate level was breached.
    pub level: String,
}

// ---------------------------------------------------------------------------
// SeverityCounts (internal)
// ---------------------------------------------------------------------------

/// Internal helper that tracks finding counts by severity.
#[derive(Debug, Default)]
struct SeverityCounts {
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    info: u32,
    total: u32,
}

impl SeverityCounts {
    /// Returns the count for the given severity.
    fn get(&self, severity: Severity) -> u32 {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }

    /// Increments the count for the given severity and the total.
    fn increment(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
        self.total += 1;
    }
}

// ---------------------------------------------------------------------------
// Finding abstraction
// ---------------------------------------------------------------------------

/// Trait that abstracts over Finding types, allowing the gate engine to work
/// without a hard dependency on `atlas-analysis` at compile time.
///
/// The `atlas-analysis` crate's `Finding` struct implements this trait via a
/// blanket implementation or explicit impl in the integration layer. For the
/// gate engine itself, we only need severity and category.
pub trait GateFinding {
    /// Returns the severity of this finding.
    fn severity(&self) -> Severity;

    /// Returns the category of this finding.
    fn category(&self) -> Category;
}

// ---------------------------------------------------------------------------
// evaluate_gate
// ---------------------------------------------------------------------------

/// Evaluates findings against policy thresholds and produces a gate result.
///
/// # Parameters
///
/// - `findings`: the set of findings to evaluate.
/// - `fail_on`: thresholds that trigger a FAIL gate result when exceeded.
/// - `warn_on`: optional thresholds that trigger a WARN gate result when exceeded.
/// - `category_overrides`: optional per-category threshold overrides.
///
/// # Returns
///
/// A [`GateDetails`] containing the overall [`GateResult`] and a list of all
/// [`BreachedThreshold`]s that contributed to the outcome.
///
/// # Threshold semantics
///
/// A threshold value represents the maximum allowed count. If the actual count
/// of findings **exceeds** the threshold (i.e., `actual > threshold`), the
/// threshold is considered breached. For example, `fail_on: { critical: 0 }`
/// means "fail if there are more than 0 critical findings".
pub fn evaluate_gate<F: GateFinding>(
    findings: &[F],
    fail_on: &Thresholds,
    warn_on: Option<&Thresholds>,
    category_overrides: Option<&CategoryOverrides>,
) -> GateDetails {
    // Step 1: Count findings by severity (global).
    let global_counts = count_by_severity(findings);

    // Step 2: Count findings by (category, severity) if category overrides exist.
    let category_counts = if category_overrides.is_some() {
        Some(count_by_category(findings))
    } else {
        None
    };

    let mut breached = Vec::new();

    // Step 3: Check fail_on global thresholds.
    check_thresholds(
        &global_counts,
        fail_on,
        None, // no category filter
        "fail",
        &mut breached,
    );

    // Step 4: Check category-specific fail_on overrides.
    if let Some(overrides) = category_overrides {
        if let Some(cat_counts) = &category_counts {
            check_category_overrides(cat_counts, overrides, "fail", &mut breached);
        }
    }

    // Step 5: If any FAIL thresholds breached, return FAIL (but continue
    // collecting WARN breaches for reporting completeness).
    let has_fail = breached.iter().any(|b| b.level == "fail");

    // Step 6: Check warn_on global thresholds.
    if let Some(warn) = warn_on {
        check_thresholds(&global_counts, warn, None, "warn", &mut breached);
    }

    // Step 7: Check category-specific warn_on overrides.
    if let Some(overrides) = category_overrides {
        if let Some(ref cat_counts) = category_counts {
            check_category_warn_overrides(cat_counts, overrides, &mut breached);
        }
    }

    let has_warn = breached.iter().any(|b| b.level == "warn");

    // Step 8: Determine overall result.
    let result = if has_fail {
        GateResult::Fail
    } else if has_warn {
        GateResult::Warn
    } else {
        GateResult::Pass
    };

    GateDetails {
        result,
        breached_thresholds: breached,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Counts findings by severity across all categories.
fn count_by_severity<F: GateFinding>(findings: &[F]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings {
        counts.increment(finding.severity());
    }
    counts
}

/// Category-keyed severity counts.
struct CategoryCounts {
    security: SeverityCounts,
    quality: SeverityCounts,
    secrets: SeverityCounts,
    metrics: SeverityCounts,
}

impl CategoryCounts {
    fn get(&self, category: Category) -> &SeverityCounts {
        match category {
            Category::Security => &self.security,
            Category::Quality => &self.quality,
            Category::Secrets => &self.secrets,
            Category::Metrics => &self.metrics,
        }
    }
}

/// Counts findings by (category, severity).
fn count_by_category<F: GateFinding>(findings: &[F]) -> CategoryCounts {
    let mut counts = CategoryCounts {
        security: SeverityCounts::default(),
        quality: SeverityCounts::default(),
        secrets: SeverityCounts::default(),
        metrics: SeverityCounts::default(),
    };
    for finding in findings {
        let bucket = match finding.category() {
            Category::Security => &mut counts.security,
            Category::Quality => &mut counts.quality,
            Category::Secrets => &mut counts.secrets,
            Category::Metrics => &mut counts.metrics,
        };
        bucket.increment(finding.severity());
    }
    counts
}

/// Checks severity and total thresholds, appending any breaches to `breached`.
fn check_thresholds(
    counts: &SeverityCounts,
    thresholds: &Thresholds,
    category: Option<&str>,
    level: &str,
    breached: &mut Vec<BreachedThreshold>,
) {
    let category_owned = category.map(String::from);

    // Check each severity threshold.
    let severity_checks: &[(Severity, Option<u32>)] = &[
        (Severity::Critical, thresholds.critical),
        (Severity::High, thresholds.high),
        (Severity::Medium, thresholds.medium),
        (Severity::Low, thresholds.low),
        (Severity::Info, thresholds.info),
    ];

    for &(severity, threshold_opt) in severity_checks {
        if let Some(threshold) = threshold_opt {
            let actual = counts.get(severity);
            if actual > threshold {
                breached.push(BreachedThreshold {
                    severity: severity.to_string(),
                    category: category_owned.clone(),
                    threshold,
                    actual,
                    level: level.to_string(),
                });
            }
        }
    }

    // Check total threshold.
    if let Some(threshold) = thresholds.total {
        if counts.total > threshold {
            breached.push(BreachedThreshold {
                severity: "total".to_string(),
                category: category_owned,
                threshold,
                actual: counts.total,
                level: level.to_string(),
            });
        }
    }
}

/// Checks category-specific fail_on overrides.
fn check_category_overrides(
    cat_counts: &CategoryCounts,
    overrides: &CategoryOverrides,
    level: &str,
    breached: &mut Vec<BreachedThreshold>,
) {
    if let Some(ref security) = overrides.security {
        check_thresholds(
            cat_counts.get(Category::Security),
            security,
            Some("security"),
            level,
            breached,
        );
    }
    if let Some(ref quality) = overrides.quality {
        check_thresholds(
            cat_counts.get(Category::Quality),
            quality,
            Some("quality"),
            level,
            breached,
        );
    }
    if let Some(ref secrets) = overrides.secrets {
        check_thresholds(
            cat_counts.get(Category::Secrets),
            secrets,
            Some("secrets"),
            level,
            breached,
        );
    }
    if let Some(ref metrics) = overrides.metrics {
        check_thresholds(
            cat_counts.get(Category::Metrics),
            metrics,
            Some("metrics"),
            level,
            breached,
        );
    }
}

/// Checks category-specific warn_on overrides.
///
/// The `CategoryOverrides` type represents fail-level per-category thresholds
/// in the policy schema. For warn-level category overrides, we check the same
/// structure but mark breaches as `"warn"` level. This supports future
/// extension where `CategoryOverrides` could have separate warn thresholds.
fn check_category_warn_overrides(
    _cat_counts: &CategoryCounts,
    _overrides: &CategoryOverrides,
    _breached: &mut Vec<BreachedThreshold>,
) {
    // The current policy schema defines `category_overrides` as fail-level
    // thresholds only. Warn-level category overrides are not yet specified
    // in the schema. This function is a no-op placeholder for forward
    // compatibility. When the schema is extended to support per-category
    // warn thresholds, implement the logic here.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helper: mock Finding ------------------------------------------

    /// A minimal mock finding for gate evaluation tests.
    #[derive(Debug, Clone)]
    struct MockFinding {
        severity: Severity,
        category: Category,
    }

    impl GateFinding for MockFinding {
        fn severity(&self) -> Severity {
            self.severity
        }

        fn category(&self) -> Category {
            self.category
        }
    }

    /// Shorthand to create a `MockFinding`.
    fn finding(severity: Severity, category: Category) -> MockFinding {
        MockFinding { severity, category }
    }

    /// Creates a default `Thresholds` with all fields `None`.
    fn empty_thresholds() -> Thresholds {
        Thresholds {
            critical: None,
            high: None,
            medium: None,
            low: None,
            info: None,
            total: None,
        }
    }

    // -- Test 1: PASS when no thresholds breached ---------------------------

    #[test]
    fn gate_pass_when_no_thresholds_breached() {
        // No findings at all, any thresholds should pass.
        let findings: Vec<MockFinding> = vec![];
        let fail_on = Thresholds {
            critical: Some(0),
            high: Some(5),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Pass);
        assert!(
            details.breached_thresholds.is_empty(),
            "expected no breached thresholds, got: {:?}",
            details.breached_thresholds
        );
    }

    // -- Test 2: FAIL on critical exceeds threshold -------------------------

    #[test]
    fn gate_fail_on_critical_exceeds_threshold() {
        // 1 critical finding, fail_on.critical = 0 => FAIL (1 > 0).
        let findings = vec![finding(Severity::Critical, Category::Security)];
        let fail_on = Thresholds {
            critical: Some(0),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 1);

        let breach = &details.breached_thresholds[0];
        assert_eq!(breach.severity, "critical");
        assert_eq!(breach.threshold, 0);
        assert_eq!(breach.actual, 1);
        assert_eq!(breach.level, "fail");
        assert!(breach.category.is_none());
    }

    // -- Test 3: PASS when at threshold (not exceeding) ---------------------

    #[test]
    fn gate_pass_when_at_threshold() {
        // 0 critical findings, fail_on.critical = 0 => PASS (0 > 0 is false).
        let findings: Vec<MockFinding> = vec![];
        let fail_on = Thresholds {
            critical: Some(0),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Pass);
        assert!(details.breached_thresholds.is_empty());
    }

    // -- Test 4: FAIL on total threshold ------------------------------------

    #[test]
    fn gate_fail_on_total() {
        // 5 findings total, fail_on.total = 3 => FAIL (5 > 3).
        let findings = vec![
            finding(Severity::Low, Category::Quality),
            finding(Severity::Low, Category::Quality),
            finding(Severity::Medium, Category::Security),
            finding(Severity::Info, Category::Quality),
            finding(Severity::High, Category::Security),
        ];
        let fail_on = Thresholds {
            total: Some(3),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 1);

        let breach = &details.breached_thresholds[0];
        assert_eq!(breach.severity, "total");
        assert_eq!(breach.threshold, 3);
        assert_eq!(breach.actual, 5);
        assert_eq!(breach.level, "fail");
    }

    // -- Test 5: WARN when warn threshold breached --------------------------

    #[test]
    fn gate_warn_when_warn_threshold_breached() {
        // 3 high findings.
        // fail_on.high = 5 (not breached: 3 <= 5).
        // warn_on.high = 2 (breached: 3 > 2).
        let findings = vec![
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Security),
        ];
        let fail_on = Thresholds {
            high: Some(5),
            ..empty_thresholds()
        };
        let warn_on = Thresholds {
            high: Some(2),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, Some(&warn_on), None);
        assert_eq!(details.result, GateResult::Warn);
        assert_eq!(details.breached_thresholds.len(), 1);

        let breach = &details.breached_thresholds[0];
        assert_eq!(breach.severity, "high");
        assert_eq!(breach.threshold, 2);
        assert_eq!(breach.actual, 3);
        assert_eq!(breach.level, "warn");
    }

    // -- Test 6: FAIL takes precedence over WARN ----------------------------

    #[test]
    fn gate_fail_takes_precedence_over_warn() {
        // 2 critical findings, 4 high findings.
        // fail_on.critical = 1 (breached: 2 > 1).
        // warn_on.high = 2 (breached: 4 > 2).
        // Result should be FAIL, but both breaches are recorded.
        let findings = vec![
            finding(Severity::Critical, Category::Security),
            finding(Severity::Critical, Category::Security),
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Quality),
            finding(Severity::High, Category::Quality),
        ];
        let fail_on = Thresholds {
            critical: Some(1),
            ..empty_thresholds()
        };
        let warn_on = Thresholds {
            high: Some(2),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, Some(&warn_on), None);
        assert_eq!(details.result, GateResult::Fail);

        // Both the fail and warn breaches should be recorded.
        let fail_breaches: Vec<_> = details
            .breached_thresholds
            .iter()
            .filter(|b| b.level == "fail")
            .collect();
        let warn_breaches: Vec<_> = details
            .breached_thresholds
            .iter()
            .filter(|b| b.level == "warn")
            .collect();

        assert_eq!(fail_breaches.len(), 1);
        assert_eq!(fail_breaches[0].severity, "critical");
        assert_eq!(fail_breaches[0].actual, 2);

        assert_eq!(warn_breaches.len(), 1);
        assert_eq!(warn_breaches[0].severity, "high");
        assert_eq!(warn_breaches[0].actual, 4);
    }

    // -- Test 7: Category override (security) triggers FAIL -----------------

    #[test]
    fn gate_category_override_security() {
        // 2 security findings (both high), 3 quality findings (all low).
        // Global fail_on: no thresholds (all None) -> would pass.
        // Category override: security.high = 1 -> FAIL (2 > 1).
        let findings = vec![
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Security),
            finding(Severity::Low, Category::Quality),
            finding(Severity::Low, Category::Quality),
            finding(Severity::Low, Category::Quality),
        ];
        let fail_on = empty_thresholds();
        let overrides = CategoryOverrides {
            security: Some(Thresholds {
                high: Some(1),
                ..empty_thresholds()
            }),
            quality: None,
            secrets: None,
            metrics: None,
        };

        let details = evaluate_gate(&findings, &fail_on, None, Some(&overrides));
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 1);

        let breach = &details.breached_thresholds[0];
        assert_eq!(breach.severity, "high");
        assert_eq!(breach.category.as_deref(), Some("security"));
        assert_eq!(breach.threshold, 1);
        assert_eq!(breach.actual, 2);
        assert_eq!(breach.level, "fail");
    }

    // -- Test 8: Records all breached thresholds ----------------------------

    #[test]
    fn gate_records_all_breached_thresholds() {
        // 3 critical, 5 high, 10 medium findings.
        // fail_on: critical = 0, high = 2, total = 10 (all breached).
        let findings: Vec<MockFinding> = {
            let mut v = Vec::new();
            for _ in 0..3 {
                v.push(finding(Severity::Critical, Category::Security));
            }
            for _ in 0..5 {
                v.push(finding(Severity::High, Category::Security));
            }
            for _ in 0..10 {
                v.push(finding(Severity::Medium, Category::Quality));
            }
            v
        };
        let fail_on = Thresholds {
            critical: Some(0),
            high: Some(2),
            total: Some(10),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Fail);

        // Should have 3 breached thresholds: critical, high, total.
        assert_eq!(
            details.breached_thresholds.len(),
            3,
            "expected 3 breached thresholds, got: {:?}",
            details.breached_thresholds
        );

        let severities: Vec<&str> = details
            .breached_thresholds
            .iter()
            .map(|b| b.severity.as_str())
            .collect();
        assert!(severities.contains(&"critical"));
        assert!(severities.contains(&"high"));
        assert!(severities.contains(&"total"));

        // Verify individual counts.
        let critical_breach = details
            .breached_thresholds
            .iter()
            .find(|b| b.severity == "critical")
            .unwrap();
        assert_eq!(critical_breach.actual, 3);
        assert_eq!(critical_breach.threshold, 0);

        let high_breach = details
            .breached_thresholds
            .iter()
            .find(|b| b.severity == "high")
            .unwrap();
        assert_eq!(high_breach.actual, 5);
        assert_eq!(high_breach.threshold, 2);

        let total_breach = details
            .breached_thresholds
            .iter()
            .find(|b| b.severity == "total")
            .unwrap();
        assert_eq!(total_breach.actual, 18); // 3 + 5 + 10
        assert_eq!(total_breach.threshold, 10);
    }

    // -- Additional edge case tests -----------------------------------------

    #[test]
    fn gate_pass_with_findings_below_all_thresholds() {
        // 2 medium findings, fail_on.medium = 5 -> PASS (2 <= 5).
        let findings = vec![
            finding(Severity::Medium, Category::Quality),
            finding(Severity::Medium, Category::Quality),
        ];
        let fail_on = Thresholds {
            medium: Some(5),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Pass);
        assert!(details.breached_thresholds.is_empty());
    }

    #[test]
    fn gate_exactly_at_threshold_does_not_breach() {
        // 3 high findings, fail_on.high = 3 -> PASS (3 > 3 is false).
        let findings = vec![
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Security),
            finding(Severity::High, Category::Security),
        ];
        let fail_on = Thresholds {
            high: Some(3),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Pass);
        assert!(details.breached_thresholds.is_empty());
    }

    #[test]
    fn gate_category_override_quality_total() {
        // 4 quality findings total.
        // Category override: quality.total = 2 -> FAIL (4 > 2).
        let findings = vec![
            finding(Severity::Low, Category::Quality),
            finding(Severity::Low, Category::Quality),
            finding(Severity::Medium, Category::Quality),
            finding(Severity::Info, Category::Quality),
        ];
        let fail_on = empty_thresholds();
        let overrides = CategoryOverrides {
            security: None,
            quality: Some(Thresholds {
                total: Some(2),
                ..empty_thresholds()
            }),
            secrets: None,
            metrics: None,
        };

        let details = evaluate_gate(&findings, &fail_on, None, Some(&overrides));
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 1);
        assert_eq!(
            details.breached_thresholds[0].category.as_deref(),
            Some("quality")
        );
        assert_eq!(details.breached_thresholds[0].severity, "total");
        assert_eq!(details.breached_thresholds[0].actual, 4);
    }

    #[test]
    fn gate_category_override_secrets() {
        // 1 secret finding (critical).
        // Category override: secrets.critical = 0 -> FAIL (1 > 0).
        let findings = vec![finding(Severity::Critical, Category::Secrets)];
        let fail_on = empty_thresholds();
        let overrides = CategoryOverrides {
            security: None,
            quality: None,
            secrets: Some(Thresholds {
                critical: Some(0),
                ..empty_thresholds()
            }),
            metrics: None,
        };

        let details = evaluate_gate(&findings, &fail_on, None, Some(&overrides));
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 1);
        assert_eq!(
            details.breached_thresholds[0].category.as_deref(),
            Some("secrets")
        );
        assert_eq!(details.breached_thresholds[0].severity, "critical");
    }

    #[test]
    fn gate_mixed_global_and_category_fail() {
        // 2 critical (security), 3 high (quality).
        // Global fail_on: critical = 0 (breached).
        // Category override: quality.high = 1 (breached).
        let findings = vec![
            finding(Severity::Critical, Category::Security),
            finding(Severity::Critical, Category::Security),
            finding(Severity::High, Category::Quality),
            finding(Severity::High, Category::Quality),
            finding(Severity::High, Category::Quality),
        ];
        let fail_on = Thresholds {
            critical: Some(0),
            ..empty_thresholds()
        };
        let overrides = CategoryOverrides {
            security: None,
            quality: Some(Thresholds {
                high: Some(1),
                ..empty_thresholds()
            }),
            secrets: None,
            metrics: None,
        };

        let details = evaluate_gate(&findings, &fail_on, None, Some(&overrides));
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 2);

        let global_breach = details
            .breached_thresholds
            .iter()
            .find(|b| b.category.is_none())
            .unwrap();
        assert_eq!(global_breach.severity, "critical");
        assert_eq!(global_breach.actual, 2);

        let category_breach = details
            .breached_thresholds
            .iter()
            .find(|b| b.category.is_some())
            .unwrap();
        assert_eq!(category_breach.severity, "high");
        assert_eq!(category_breach.category.as_deref(), Some("quality"));
        assert_eq!(category_breach.actual, 3);
    }

    #[test]
    fn gate_details_serialization_roundtrip() {
        let details = GateDetails {
            result: GateResult::Fail,
            breached_thresholds: vec![
                BreachedThreshold {
                    severity: "critical".to_string(),
                    category: None,
                    threshold: 0,
                    actual: 1,
                    level: "fail".to_string(),
                },
                BreachedThreshold {
                    severity: "high".to_string(),
                    category: Some("security".to_string()),
                    threshold: 5,
                    actual: 10,
                    level: "fail".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&details).unwrap();
        let back: GateDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(details, back);
    }

    #[test]
    fn gate_pass_details_empty_breaches() {
        let details = GateDetails {
            result: GateResult::Pass,
            breached_thresholds: vec![],
        };

        let json = serde_json::to_string(&details).unwrap();
        let back: GateDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(back.result, GateResult::Pass);
        assert!(back.breached_thresholds.is_empty());
    }

    #[test]
    fn gate_only_unconfigured_severities_present() {
        // Findings exist for severities that have no thresholds configured.
        // All configured thresholds are for other severities.
        let findings = vec![
            finding(Severity::Info, Category::Quality),
            finding(Severity::Info, Category::Quality),
            finding(Severity::Low, Category::Quality),
        ];
        let fail_on = Thresholds {
            critical: Some(0),
            high: Some(0),
            ..empty_thresholds()
        };

        let details = evaluate_gate(&findings, &fail_on, None, None);
        assert_eq!(details.result, GateResult::Pass);
        assert!(details.breached_thresholds.is_empty());
    }

    // -- Test: Category override (metrics) triggers FAIL --------------------

    #[test]
    fn gate_category_override_metrics() {
        // 3 個 Metrics findings（medium severity）。
        // Category override: metrics.medium = 2 → FAIL（3 > 2）。
        let findings = vec![
            finding(Severity::Medium, Category::Metrics),
            finding(Severity::Medium, Category::Metrics),
            finding(Severity::Medium, Category::Metrics),
        ];
        let fail_on = empty_thresholds();
        let overrides = CategoryOverrides {
            security: None,
            quality: None,
            secrets: None,
            metrics: Some(Thresholds {
                medium: Some(2),
                ..empty_thresholds()
            }),
        };

        let details = evaluate_gate(&findings, &fail_on, None, Some(&overrides));
        assert_eq!(details.result, GateResult::Fail);
        assert_eq!(details.breached_thresholds.len(), 1);
        assert_eq!(
            details.breached_thresholds[0].category.as_deref(),
            Some("metrics")
        );
        assert_eq!(details.breached_thresholds[0].severity, "medium");
        assert_eq!(details.breached_thresholds[0].actual, 3);
        assert_eq!(details.breached_thresholds[0].threshold, 2);
    }

    #[test]
    fn gate_metrics_pass_when_below_threshold() {
        // 2 個 Metrics findings。
        // Category override: metrics.medium = 5 → PASS（2 <= 5）。
        let findings = vec![
            finding(Severity::Medium, Category::Metrics),
            finding(Severity::Medium, Category::Metrics),
        ];
        let fail_on = empty_thresholds();
        let overrides = CategoryOverrides {
            security: None,
            quality: None,
            secrets: None,
            metrics: Some(Thresholds {
                medium: Some(5),
                ..empty_thresholds()
            }),
        };

        let details = evaluate_gate(&findings, &fail_on, None, Some(&overrides));
        assert_eq!(details.result, GateResult::Pass);
        assert!(details.breached_thresholds.is_empty());
    }
}
