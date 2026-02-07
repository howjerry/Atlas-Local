//! Floating licence client stub (T076).
//!
//! A floating licence is managed by a remote licence server using a
//! seat-based model.  This module provides the client-side stub for the
//! checkout / checkin / heartbeat protocol.
//!
//! **Current status**: stub implementation.  All operations that require
//! network access will fail with [`LicenseError::ServerUnreachable`] since
//! the licence server is not yet deployed.  This ensures the correct exit
//! code (3) is returned when the server cannot be reached.

use tracing::{info, warn};

use crate::LicenseError;
use crate::validator::License;

// ---------------------------------------------------------------------------
// FloatingClient
// ---------------------------------------------------------------------------

/// Client for the floating licence server.
///
/// The protocol is mTLS + JSON-RPC.  Operations:
/// - `checkout`: request a seat allocation
/// - `checkin`: release a seat
/// - `heartbeat`: keep-alive signal
#[derive(Debug)]
pub struct FloatingClient {
    server_url: String,
    license_id: String,
}

/// Seat allocation receipt returned by `checkout`.
#[derive(Debug, Clone)]
pub struct SeatReceipt {
    pub seat_id: String,
    pub expires_at: String,
}

impl FloatingClient {
    /// Creates a new floating licence client from a licence descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`LicenseError::TypeMismatch`] if the licence is not `Floating`,
    /// or [`LicenseError::MissingServerUrl`] if `server_url` is absent.
    pub fn new(license: &License) -> Result<Self, LicenseError> {
        if license.license_type != atlas_core::LicenseType::Floating {
            return Err(LicenseError::TypeMismatch {
                expected: "Floating".to_string(),
                actual: license.license_type.to_string(),
            });
        }

        let server_url = license
            .server_url
            .as_deref()
            .ok_or(LicenseError::MissingServerUrl)?
            .to_string();

        info!(
            server_url = %server_url,
            license_id = %license.license_id,
            "created floating license client"
        );

        Ok(Self {
            server_url,
            license_id: license.license_id.clone(),
        })
    }

    /// Returns the server URL this client is configured to connect to.
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Attempts to check out a seat from the licence server.
    ///
    /// **Stub**: always returns [`LicenseError::ServerUnreachable`].
    pub fn checkout(&self) -> Result<SeatReceipt, LicenseError> {
        warn!(
            server_url = %self.server_url,
            license_id = %self.license_id,
            "floating license checkout: server not available (stub)"
        );
        Err(LicenseError::ServerUnreachable {
            url: self.server_url.clone(),
            reason: "floating licence server is not yet deployed; \
                     check network connectivity or use a node-locked licence"
                .to_string(),
        })
    }

    /// Releases a seat back to the licence server.
    ///
    /// **Stub**: always returns [`LicenseError::ServerUnreachable`].
    pub fn checkin(&self, _seat_id: &str) -> Result<(), LicenseError> {
        warn!(
            server_url = %self.server_url,
            license_id = %self.license_id,
            "floating license checkin: server not available (stub)"
        );
        Err(LicenseError::ServerUnreachable {
            url: self.server_url.clone(),
            reason: "floating licence server is not yet deployed".to_string(),
        })
    }

    /// Sends a heartbeat signal to maintain the seat allocation.
    ///
    /// **Stub**: always returns [`LicenseError::ServerUnreachable`].
    pub fn heartbeat(&self, _seat_id: &str) -> Result<(), LicenseError> {
        warn!(
            server_url = %self.server_url,
            license_id = %self.license_id,
            "floating license heartbeat: server not available (stub)"
        );
        Err(LicenseError::ServerUnreachable {
            url: self.server_url.clone(),
            reason: "floating licence server is not yet deployed".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::License;

    fn floating_license() -> License {
        License {
            license_id: "lic-float-001".to_string(),
            organization: "Float Corp".to_string(),
            license_type: atlas_core::LicenseType::Floating,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: None,
            max_seats: Some(10),
            server_url: Some("https://license.example.com".to_string()),
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn new_client_from_floating_license() {
        let lic = floating_license();
        let client = FloatingClient::new(&lic).unwrap();
        assert_eq!(client.server_url(), "https://license.example.com");
    }

    #[test]
    fn new_client_wrong_type() {
        let lic = License {
            license_id: "lic-node".to_string(),
            organization: "Test".to_string(),
            license_type: atlas_core::LicenseType::NodeLocked,
            expiry: "2099-12-31T23:59:59Z".to_string(),
            entitled_features: vec!["scan".to_string()],
            fingerprint: Some("abc".to_string()),
            max_seats: None,
            server_url: None,
            signature: "dGVzdA==".to_string(),
            schema_version: "1.0.0".to_string(),
        };
        let result = FloatingClient::new(&lic);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn new_client_missing_server_url() {
        let mut lic = floating_license();
        lic.server_url = None;
        let result = FloatingClient::new(&lic);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::MissingServerUrl
        ));
    }

    #[test]
    fn checkout_returns_unreachable() {
        let lic = floating_license();
        let client = FloatingClient::new(&lic).unwrap();
        let result = client.checkout();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::ServerUnreachable { .. }
        ));
    }

    #[test]
    fn checkin_returns_unreachable() {
        let lic = floating_license();
        let client = FloatingClient::new(&lic).unwrap();
        let result = client.checkin("seat-123");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::ServerUnreachable { .. }
        ));
    }

    #[test]
    fn heartbeat_returns_unreachable() {
        let lic = floating_license();
        let client = FloatingClient::new(&lic).unwrap();
        let result = client.heartbeat("seat-123");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::ServerUnreachable { .. }
        ));
    }
}
