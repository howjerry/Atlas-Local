//! Atlas Audit — audit bundle generation and verification.
//!
//! Generates tamper-evident archives containing the complete record of a scan
//! for compliance and audit purposes. Bundles include the scan report, rules
//! applied, policy configuration, and a signed manifest.

pub mod bundle;

// ---------------------------------------------------------------------------
// AuditError
// ---------------------------------------------------------------------------

/// Error type for audit operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("integrity violation: {0}")]
    IntegrityViolation(String),

    #[error("signature error: {0}")]
    Signature(String),
}
