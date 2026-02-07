//! Node-locked licence validation.
//!
//! A node-locked licence is tied to a specific machine via a hardware
//! fingerprint.  The fingerprint is computed from deterministic system
//! attributes: sorted MAC addresses, hostname, and OS identifier.
//!
//! Validation pipeline (T075):
//! 1. Load licence file
//! 2. Verify ed25519 signature
//! 3. Check expiry date
//! 4. Match hardware fingerprint
//! 5. Check entitled features

use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::LicenseError;
use crate::validator::{self, License, LicenseStatus};

// ---------------------------------------------------------------------------
// Hardware fingerprint generation  (T074)
// ---------------------------------------------------------------------------

/// Components used to build the hardware fingerprint.
#[derive(Debug, Clone)]
struct FingerprintComponents {
    mac_addresses: Vec<String>,
    hostname: String,
    os_id: String,
}

/// Collects system-level components for fingerprint generation.
fn collect_components() -> FingerprintComponents {
    let hostname = hostname();
    let os_id = os_identifier();
    let mut mac_addresses = mac_addresses();
    mac_addresses.sort(); // deterministic ordering

    FingerprintComponents {
        mac_addresses,
        hostname,
        os_id,
    }
}

/// Returns the system hostname.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            // Fallback: read from gethostname-style approach
            #[cfg(unix)]
            {
                use std::process::Command;
                Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            }
            #[cfg(not(unix))]
            {
                "unknown".to_string()
            }
        })
}

/// Returns an OS identifier string.
fn os_identifier() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Returns a list of MAC addresses found on the system.
///
/// On platforms where MAC addresses cannot be read easily, returns a
/// placeholder based on the hostname to keep the fingerprint deterministic
/// per machine.
fn mac_addresses() -> Vec<String> {
    // Reading MAC addresses portably without extra dependencies is tricky.
    // We use a best-effort approach: parse `ifconfig` on unix or `getmac` on Windows.
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ifconfig").output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let macs: Vec<String> = text
                    .lines()
                    .filter_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.starts_with("ether ") {
                            Some(trimmed.trim_start_matches("ether ").trim().to_string())
                        } else {
                            None
                        }
                    })
                    .filter(|mac| mac != "00:00:00:00:00:00")
                    .collect();
                if !macs.is_empty() {
                    return macs;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ip").args(["link", "show"]).output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let macs: Vec<String> = text
                    .lines()
                    .filter_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.starts_with("link/ether ") {
                            Some(
                                trimmed
                                    .trim_start_matches("link/ether ")
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("")
                                    .to_string(),
                            )
                        } else {
                            None
                        }
                    })
                    .filter(|mac| mac != "00:00:00:00:00:00")
                    .collect();
                if !macs.is_empty() {
                    return macs;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("getmac").args(["/fo", "csv", "/nh"]).output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let macs: Vec<String> = text
                    .lines()
                    .filter_map(|line| {
                        line.split(',')
                            .next()
                            .map(|s| s.trim_matches('"').to_string())
                    })
                    .filter(|mac| !mac.is_empty() && mac != "N/A")
                    .collect();
                if !macs.is_empty() {
                    return macs;
                }
            }
        }
    }

    // Fallback: use hostname as a pseudo-MAC so fingerprint stays deterministic.
    vec![format!("fallback-{}", hostname())]
}

/// Generates a deterministic hardware fingerprint for the current machine.
///
/// The fingerprint is the hex-encoded SHA-256 of:
/// `"{sorted_mac_addresses}:{hostname}:{os_id}"`
///
/// This value is deterministic across reboots on the same machine.
#[must_use]
pub fn hardware_fingerprint() -> String {
    let components = collect_components();

    let input = format!(
        "{}:{}:{}",
        components.mac_addresses.join(","),
        components.hostname,
        components.os_id,
    );

    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    debug!(
        hostname = %components.hostname,
        os = %components.os_id,
        macs = components.mac_addresses.len(),
        "computed hardware fingerprint"
    );

    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Node-locked validation pipeline  (T075)
// ---------------------------------------------------------------------------

/// Full validation pipeline for a node-locked licence.
///
/// Steps:
/// 1. Verify ed25519 signature (if public key is provided).
/// 2. Check expiry date.
/// 3. Match hardware fingerprint.
/// 4. Check that "scan" feature is entitled.
pub fn validate_node_locked(
    license: &License,
    public_key: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<LicenseStatus, LicenseError> {
    // Ensure this is actually a NodeLocked licence.
    if license.license_type != atlas_core::LicenseType::NodeLocked {
        return Err(LicenseError::TypeMismatch {
            expected: "NodeLocked".to_string(),
            actual: license.license_type.to_string(),
        });
    }

    // Step 1: Verify signature (if public key provided).
    if let Some(pk) = public_key {
        validator::verify_signature(license, pk)?;
        info!(license_id = %license.license_id, "signature verification passed");
    } else {
        debug!("no public key provided, skipping signature verification");
    }

    // Step 2: Check expiry.
    validator::check_expiry(license)?;
    info!(expiry = %license.expiry, "expiry check passed");

    // Step 3: Match hardware fingerprint.
    let machine_fp = hardware_fingerprint();
    let license_fp = license
        .fingerprint
        .as_deref()
        .ok_or(LicenseError::MissingFingerprint)?;

    let fp_match = machine_fp == license_fp;
    if !fp_match {
        return Err(LicenseError::FingerprintMismatch {
            expected: license_fp.to_string(),
            actual: machine_fp,
        });
    }
    info!("hardware fingerprint match confirmed");

    // Step 4: Entitled features check.
    validator::check_feature(license, "scan")?;

    Ok(validator::license_status(license, Some(&machine_fp)))
}

/// Validates a node-locked licence from a file path, skipping signature
/// verification (no public key embedded at this stage).
pub fn validate_from_file(path: &std::path::Path) -> Result<LicenseStatus, LicenseError> {
    let license = validator::load_license(path)?;
    validate_node_locked(&license, None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let fp1 = hardware_fingerprint();
        let fp2 = hardware_fingerprint();
        assert_eq!(fp1, fp2, "fingerprint must be deterministic across calls");
    }

    #[test]
    fn fingerprint_is_hex_sha256() {
        let fp = hardware_fingerprint();
        // SHA-256 hex is 64 chars
        assert_eq!(fp.len(), 64, "fingerprint must be 64 hex chars (SHA-256)");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must contain only hex digits"
        );
    }

    #[test]
    fn os_identifier_format() {
        let os = os_identifier();
        assert!(
            os.contains('-'),
            "os identifier must contain dash separator"
        );
        assert!(
            os.contains(std::env::consts::OS),
            "os identifier must contain OS name"
        );
    }

    #[test]
    fn hostname_non_empty() {
        let h = hostname();
        assert!(!h.is_empty(), "hostname must not be empty");
    }

    #[test]
    fn validate_node_locked_type_mismatch() {
        let lic = License {
            license_id: "lic-float".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::Floating,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: None,
            max_seats: Some(10),
            server_url: Some("https://example.com".to_string()),
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = validate_node_locked(&lic, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn validate_node_locked_expired() {
        let lic = License {
            license_id: "lic-expired".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2020-01-01T00:00:00Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: Some(hardware_fingerprint()),
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = validate_node_locked(&lic, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LicenseError::Expired { .. }));
    }

    #[test]
    fn validate_node_locked_missing_fingerprint() {
        let lic = License {
            license_id: "lic-no-fp".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: None,
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = validate_node_locked(&lic, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::MissingFingerprint
        ));
    }

    #[test]
    fn validate_node_locked_fingerprint_mismatch() {
        let lic = License {
            license_id: "lic-bad-fp".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = validate_node_locked(&lic, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::FingerprintMismatch { .. }
        ));
    }

    #[test]
    fn validate_node_locked_valid() {
        let fp = hardware_fingerprint();
        let lic = License {
            license_id: "lic-valid".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string(), "audit".to_string()],
            fingerprint: Some(fp),
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = validate_node_locked(&lic, None);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.valid);
        assert_eq!(status.fingerprint_match, Some(true));
    }

    #[test]
    fn validate_node_locked_missing_feature() {
        let fp = hardware_fingerprint();
        let lic = License {
            license_id: "lic-no-feat".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["audit".to_string()], // no "scan"
            fingerprint: Some(fp),
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = validate_node_locked(&lic, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::FeatureNotEntitled { .. }
        ));
    }
}
