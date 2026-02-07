//! Atlas License — license validation and management.
//!
//! Supports two licence models:
//!
//! - **Node-locked** ([`node_locked`]) — bound to a machine via hardware fingerprint.
//! - **Floating** ([`floating`]) — seat-based pool managed by a remote server (stub).
//!
//! The [`validator`] module contains the shared [`License`](validator::License)
//! struct, signature verification, expiry checks, and feature entitlement logic.

pub mod floating;
pub mod node_locked;
pub mod validator;

// ---------------------------------------------------------------------------
// LicenseError
// ---------------------------------------------------------------------------

/// Error type for licence operations.
#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("license parse error: {0}")]
    Parse(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid expiry: {0}")]
    InvalidExpiry(String),

    #[error("license expired on {expiry}")]
    Expired { expiry: String },

    #[error("feature not entitled: {feature} (entitled: {entitled:?})")]
    FeatureNotEntitled {
        feature: String,
        entitled: Vec<String>,
    },

    #[error("hardware fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch { expected: String, actual: String },

    #[error("missing hardware fingerprint in node-locked license")]
    MissingFingerprint,

    #[error("missing server URL in floating license")]
    MissingServerUrl,

    #[error("license type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    #[error("license server unreachable at {url}: {reason}")]
    ServerUnreachable { url: String, reason: String },

    #[error("no license file found")]
    NotFound,
}
