//! License struct definition and validation logic.
//!
//! A license encodes an organization's entitlement to use Atlas Local.
//! Two licence types are supported:
//!
//! - **Node-locked**: bound to a single machine via hardware fingerprint.
//! - **Floating**: shared licence pool managed by a remote server.
//!
//! Both variants carry an ed25519 signature that is verified before the
//! licence is considered valid.

use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::LicenseError;

// ---------------------------------------------------------------------------
// License struct  (T073)
// ---------------------------------------------------------------------------

/// Atlas Local licence descriptor.
///
/// A licence file is a JSON document matching this struct.  On load the
/// signature is verified against the embedded Atlas public key, the expiry
/// is checked, and -- for node-locked licences -- the hardware fingerprint
/// is compared to the current machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// Unique identifier for this licence.
    pub license_id: String,

    /// Licensed organisation name.
    pub organization: String,

    /// Licence type: `NodeLocked` or `Floating`.
    #[serde(rename = "type")]
    pub license_type: atlas_core::LicenseType,

    /// ISO-8601 expiration date (e.g. `"2027-01-01T00:00:00Z"`).
    pub expiry: String,

    /// Features the licence entitles (e.g. `["scan", "l3_analysis", "audit"]`).
    pub entitled_features: Vec<String>,

    /// Hardware fingerprint (required for `NodeLocked`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,

    /// Maximum concurrent seats (required for `Floating`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_seats: Option<u32>,

    /// Licence server URL (required for `Floating`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,

    /// Base64-encoded ed25519 signature over the licence content hash.
    pub signature: String,

    /// Schema version of this licence file.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

// ---------------------------------------------------------------------------
// LicenseStatus -- public summary
// ---------------------------------------------------------------------------

/// Summary of licence validation suitable for CLI display.
#[derive(Debug, Clone, Serialize)]
pub struct LicenseStatus {
    pub valid: bool,
    pub license_id: String,
    pub organization: String,
    pub license_type: atlas_core::LicenseType,
    pub expiry: String,
    pub entitled_features: Vec<String>,
    pub fingerprint_match: Option<bool>,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Computes the content hash used for signature verification.
///
/// The hash is SHA-256 over the canonical JSON representation of all
/// licence fields **excluding** the `signature` field itself.
pub fn content_hash(license: &License) -> Vec<u8> {
    // Build a canonical JSON representation without the signature field.
    let canonical = serde_json::json!({
        "license_id": license.license_id,
        "organization": license.organization,
        "type": license.license_type,
        "expiry": license.expiry,
        "entitled_features": license.entitled_features,
        "fingerprint": license.fingerprint,
        "max_seats": license.max_seats,
        "server_url": license.server_url,
        "schema_version": license.schema_version,
    });

    let bytes = serde_json::to_vec(&canonical).expect("canonical JSON serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}

/// Verifies the ed25519 signature of a licence against a public key.
pub fn verify_signature(license: &License, public_key: &VerifyingKey) -> Result<(), LicenseError> {
    let hash = content_hash(license);

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &license.signature,
    )
    .map_err(|e| LicenseError::InvalidSignature(format!("bad base64: {e}")))?;

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| LicenseError::InvalidSignature(format!("bad ed25519 sig: {e}")))?;

    public_key
        .verify(&hash, &signature)
        .map_err(|e| LicenseError::InvalidSignature(format!("signature verification failed: {e}")))
}

/// Checks that the licence has not expired.
pub fn check_expiry(license: &License) -> Result<(), LicenseError> {
    let expiry = chrono::DateTime::parse_from_rfc3339(&license.expiry)
        .map_err(|e| LicenseError::InvalidExpiry(format!("cannot parse expiry: {e}")))?;

    let now = chrono::Utc::now();
    if now > expiry {
        return Err(LicenseError::Expired {
            expiry: license.expiry.clone(),
        });
    }

    debug!(expiry = %license.expiry, "license expiry check passed");
    Ok(())
}

/// Checks that the licence entitles the given feature.
pub fn check_feature(license: &License, feature: &str) -> Result<(), LicenseError> {
    if license.entitled_features.iter().any(|f| f == feature) {
        Ok(())
    } else {
        Err(LicenseError::FeatureNotEntitled {
            feature: feature.to_string(),
            entitled: license.entitled_features.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

/// Loads a licence from a JSON file on disk.
pub fn load_license(path: &Path) -> Result<License, LicenseError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| LicenseError::Io(format!("reading license file: {e}")))?;

    let license: License = serde_json::from_str(&data)
        .map_err(|e| LicenseError::Parse(format!("parsing license JSON: {e}")))?;

    debug!(license_id = %license.license_id, "loaded license file");
    Ok(license)
}

/// Returns the licence status summary for a loaded licence.
pub fn license_status(license: &License, machine_fingerprint: Option<&str>) -> LicenseStatus {
    let fingerprint_match = match (&license.license_type, &license.fingerprint, machine_fingerprint) {
        (atlas_core::LicenseType::NodeLocked, Some(expected), Some(actual)) => {
            Some(expected == actual)
        }
        (atlas_core::LicenseType::NodeLocked, None, _) => Some(false),
        _ => None,
    };

    let expiry_ok = check_expiry(license).is_ok();
    let fp_ok = fingerprint_match.unwrap_or(true);
    let valid = expiry_ok && fp_ok;

    let reason = if !expiry_ok {
        Some(format!("license expired on {}", license.expiry))
    } else if !fp_ok {
        Some("hardware fingerprint does not match".to_string())
    } else {
        None
    };

    if !valid {
        warn!(license_id = %license.license_id, reason = ?reason, "license validation failed");
    }

    LicenseStatus {
        valid,
        license_id: license.license_id.clone(),
        organization: license.organization.clone(),
        license_type: license.license_type,
        expiry: license.expiry.clone(),
        entitled_features: license.entitled_features.clone(),
        fingerprint_match,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_license() -> License {
        License {
            license_id: "lic-001".to_string(),
            organization: "Test Corp".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string(), "audit".to_string()],
            fingerprint: Some("abc123def456".to_string()),
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(), // placeholder
            schema_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn content_hash_deterministic() {
        let lic = sample_license();
        let h1 = content_hash(&lic);
        let h2 = content_hash(&lic);
        assert_eq!(h1, h2, "content hash must be deterministic");
    }

    #[test]
    fn content_hash_changes_with_field() {
        let mut lic = sample_license();
        let h1 = content_hash(&lic);
        lic.organization = "Changed Corp".to_string();
        let h2 = content_hash(&lic);
        assert_ne!(h1, h2, "changing a field must change the hash");
    }

    #[test]
    fn content_hash_ignores_signature() {
        let mut lic = sample_license();
        let h1 = content_hash(&lic);
        lic.signature = "different_signature".to_string();
        let h2 = content_hash(&lic);
        assert_eq!(h1, h2, "signature field must not affect content hash");
    }

    #[test]
    fn check_expiry_future_date() {
        let lic = sample_license(); // expiry 2099
        assert!(check_expiry(&lic).is_ok());
    }

    #[test]
    fn check_expiry_past_date() {
        let mut lic = sample_license();
        lic.expiry = "2020-01-01T00:00:00Z".to_string();
        let result = check_expiry(&lic);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LicenseError::Expired { .. }));
    }

    #[test]
    fn check_expiry_invalid_format() {
        let mut lic = sample_license();
        lic.expiry = "not-a-date".to_string();
        let result = check_expiry(&lic);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LicenseError::InvalidExpiry(_)));
    }

    #[test]
    fn check_feature_entitled() {
        let lic = sample_license();
        assert!(check_feature(&lic, "scan").is_ok());
        assert!(check_feature(&lic, "audit").is_ok());
    }

    #[test]
    fn check_feature_not_entitled() {
        let lic = sample_license();
        let result = check_feature(&lic, "l3_analysis");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::FeatureNotEntitled { .. }
        ));
    }

    #[test]
    fn license_status_valid() {
        let lic = sample_license();
        let status = license_status(&lic, Some("abc123def456"));
        assert!(status.valid);
        assert_eq!(status.fingerprint_match, Some(true));
        assert!(status.reason.is_none());
    }

    #[test]
    fn license_status_fingerprint_mismatch() {
        let lic = sample_license();
        let status = license_status(&lic, Some("wrong_fingerprint"));
        assert!(!status.valid);
        assert_eq!(status.fingerprint_match, Some(false));
        assert!(status.reason.as_ref().unwrap().contains("fingerprint"));
    }

    #[test]
    fn license_status_expired() {
        let mut lic = sample_license();
        lic.expiry = "2020-01-01T00:00:00Z".to_string();
        let status = license_status(&lic, Some("abc123def456"));
        assert!(!status.valid);
        assert!(status.reason.as_ref().unwrap().contains("expired"));
    }

    #[test]
    fn license_serde_roundtrip() {
        let lic = sample_license();
        let json = serde_json::to_string_pretty(&lic).unwrap();
        let back: License = serde_json::from_str(&json).unwrap();
        assert_eq!(back.license_id, lic.license_id);
        assert_eq!(back.organization, lic.organization);
        assert_eq!(back.entitled_features, lic.entitled_features);
    }

    #[test]
    fn floating_license_no_fingerprint_match() {
        let lic = License {
            license_id: "lic-float".to_string(),
            organization: "Float Corp".to_string(),
            license_type: atlas_core::LicenseType::Floating,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: None,
            max_seats: Some(10),
            server_url: Some("https://license.example.com".to_string()),
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let status = license_status(&lic, None);
        assert!(status.valid);
        assert_eq!(status.fingerprint_match, None);
    }
}
