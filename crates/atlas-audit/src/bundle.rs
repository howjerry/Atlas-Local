//! Audit bundle generation (T078-T079).
//!
//! An audit bundle is a tamper-evident archive containing the complete record
//! of a scan: the report, rules applied, policy config, and engine version.
//! A signed manifest ensures the bundle has not been modified after creation.
//!
//! # Archive layout
//!
//! ```text
//! bundle.tar.gz
//! ├── scan-report.json       Full scan findings and metadata
//! ├── rules-applied.json     Metadata for each rule that was active
//! ├── policy.json            Policy configuration (if any)
//! ├── config.json            Scan configuration snapshot
//! └── manifest.json          Checksums + ed25519 signature
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::AuditError;

// ---------------------------------------------------------------------------
// AuditBundle  (T078)
// ---------------------------------------------------------------------------

/// Complete audit bundle descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBundle {
    /// ID of the associated scan.
    pub scan_id: String,

    /// ISO-8601 creation timestamp.
    pub created_at: String,

    /// Atlas engine version.
    pub engine_version: String,

    /// Full scan report as a JSON value.
    pub report: serde_json::Value,

    /// Metadata of rules that were active during the scan.
    pub rules_applied: Vec<RuleMetadata>,

    /// Policy configuration used (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<serde_json::Value>,

    /// Scan configuration snapshot.
    pub config: BTreeMap<String, serde_json::Value>,

    /// Manifest with file checksums.
    pub manifest: AuditManifest,

    /// Schema version of this audit bundle.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

/// Metadata for a rule that was active during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub rule_id: String,
    pub name: String,
    pub version: String,
    pub category: String,
    pub severity: String,
}

/// Manifest of file checksums and the bundle signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditManifest {
    /// Map of filename -> SHA-256 hex digest.
    pub files: BTreeMap<String, String>,

    /// ISO-8601 timestamp of manifest creation.
    pub created_at: String,

    /// Atlas engine version.
    pub engine_version: String,

    /// Base64-encoded ed25519 signature over the manifest content hash.
    #[serde(default)]
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Bundle builder  (T079)
// ---------------------------------------------------------------------------

/// Builder for constructing an audit bundle step by step.
pub struct AuditBundleBuilder {
    scan_id: String,
    engine_version: String,
    report: Option<serde_json::Value>,
    rules_applied: Vec<RuleMetadata>,
    policy: Option<serde_json::Value>,
    config: BTreeMap<String, serde_json::Value>,
    /// Ed25519 簽署金鑰（可選）。提供時 `build()` 會計算 manifest 簽署。
    signing_key: Option<SigningKey>,
}

impl AuditBundleBuilder {
    /// Creates a new builder with the required scan ID and engine version.
    pub fn new(scan_id: impl Into<String>, engine_version: impl Into<String>) -> Self {
        Self {
            scan_id: scan_id.into(),
            engine_version: engine_version.into(),
            report: None,
            rules_applied: Vec::new(),
            policy: None,
            config: BTreeMap::new(),
            signing_key: None,
        }
    }

    /// 設定 Ed25519 簽署金鑰。`build()` 時會自動計算 manifest 簽署。
    pub fn signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Sets the scan report (as a JSON value).
    pub fn report(mut self, report: serde_json::Value) -> Self {
        self.report = Some(report);
        self
    }

    /// Sets the list of rules that were applied.
    pub fn rules_applied(mut self, rules: Vec<RuleMetadata>) -> Self {
        self.rules_applied = rules;
        self
    }

    /// Sets the policy configuration.
    pub fn policy(mut self, policy: serde_json::Value) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Adds a config entry.
    pub fn config_entry(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.config.insert(key.into(), value);
        self
    }

    /// Builds the audit bundle, computing checksums and creating the manifest.
    pub fn build(self) -> Result<AuditBundle, AuditError> {
        let report = self
            .report
            .ok_or_else(|| AuditError::MissingField("report".to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();

        // Serialize each component and compute its SHA-256.
        let report_json = serde_json::to_string_pretty(&report)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;
        let rules_json = serde_json::to_string_pretty(&self.rules_applied)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;
        let config_json = serde_json::to_string_pretty(&self.config)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        let mut files = BTreeMap::new();
        files.insert("scan-report.json".to_string(), sha256_hex(&report_json));
        files.insert("rules-applied.json".to_string(), sha256_hex(&rules_json));
        files.insert("config.json".to_string(), sha256_hex(&config_json));

        if let Some(ref policy) = self.policy {
            let policy_json = serde_json::to_string_pretty(policy)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;
            files.insert("policy.json".to_string(), sha256_hex(&policy_json));
        }

        // 計算 manifest 簽署（若有 signing_key）。
        let signature = if let Some(ref signing_key) = self.signing_key {
            use ed25519_dalek::Signer;

            // 先建立無簽署的 manifest 來序列化。
            let unsigned_manifest = AuditManifest {
                files: files.clone(),
                created_at: now.clone(),
                engine_version: self.engine_version.clone(),
                signature: String::new(),
            };
            let manifest_bytes = serde_json::to_vec(&unsigned_manifest)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;
            let digest = Sha256::digest(&manifest_bytes);
            let sig = signing_key.sign(&digest);
            BASE64.encode(sig.to_bytes())
        } else {
            String::new()
        };

        let manifest = AuditManifest {
            files,
            created_at: now.clone(),
            engine_version: self.engine_version.clone(),
            signature,
        };

        debug!(
            scan_id = %self.scan_id,
            files = manifest.files.len(),
            "built audit manifest"
        );

        Ok(AuditBundle {
            scan_id: self.scan_id,
            created_at: now,
            engine_version: self.engine_version,
            report,
            rules_applied: self.rules_applied,
            policy: self.policy,
            config: self.config,
            manifest,
            schema_version: "1.0.0".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Archive generation
// ---------------------------------------------------------------------------

/// Writes the audit bundle as a gzip-compressed tar archive.
pub fn write_bundle_archive(bundle: &AuditBundle, output: &Path) -> Result<(), AuditError> {
    let file = std::fs::File::create(output)
        .map_err(|e| AuditError::Io(format!("creating output file: {e}")))?;

    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(enc);

    // Helper: add a JSON string as a file entry in the archive.
    let mut add_entry = |name: &str, content: &[u8]| -> Result<(), AuditError> {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        archive
            .append_data(&mut header, name, content)
            .map_err(|e| AuditError::Io(format!("appending {name}: {e}")))?;

        Ok(())
    };

    let report_json = serde_json::to_vec_pretty(&bundle.report)
        .map_err(|e| AuditError::Serialization(e.to_string()))?;
    add_entry("scan-report.json", &report_json)?;

    let rules_json = serde_json::to_vec_pretty(&bundle.rules_applied)
        .map_err(|e| AuditError::Serialization(e.to_string()))?;
    add_entry("rules-applied.json", &rules_json)?;

    if let Some(ref policy) = bundle.policy {
        let policy_json = serde_json::to_vec_pretty(policy)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;
        add_entry("policy.json", &policy_json)?;
    }

    let config_json = serde_json::to_vec_pretty(&bundle.config)
        .map_err(|e| AuditError::Serialization(e.to_string()))?;
    add_entry("config.json", &config_json)?;

    let manifest_json = serde_json::to_vec_pretty(&bundle.manifest)
        .map_err(|e| AuditError::Serialization(e.to_string()))?;
    add_entry("manifest.json", &manifest_json)?;

    let gz = archive
        .into_inner()
        .map_err(|e| AuditError::Io(format!("finalizing archive: {e}")))?;
    gz.finish()
        .map_err(|e| AuditError::Io(format!("finishing gzip: {e}")))?;

    info!(path = %output.display(), "audit bundle written");
    Ok(())
}

/// Reads an audit bundle archive and verifies manifest checksums.
///
/// 若提供 `verify_key`，同時驗證 manifest 的 Ed25519 簽署。
/// 同時檢查 archive 是否包含 manifest 未列出的額外檔案。
pub fn verify_bundle_archive(path: &Path) -> Result<AuditBundle, AuditError> {
    verify_bundle_archive_with_key(path, None)
}

/// 帶簽署驗證的 bundle 驗證。
pub fn verify_bundle_archive_with_key(
    path: &Path,
    verify_key: Option<&VerifyingKey>,
) -> Result<AuditBundle, AuditError> {
    let file =
        std::fs::File::open(path).map_err(|e| AuditError::Io(format!("opening bundle: {e}")))?;
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for entry in archive
        .entries()
        .map_err(|e| AuditError::Io(format!("reading entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| AuditError::Io(format!("reading entry: {e}")))?;
        let name = entry
            .path()
            .map_err(|e| AuditError::Io(format!("entry path: {e}")))?
            .to_string_lossy()
            .to_string();
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut data)
            .map_err(|e| AuditError::Io(format!("reading {name}: {e}")))?;
        files.insert(name, data);
    }

    // Parse manifest
    let manifest_data = files.get("manifest.json").ok_or_else(|| {
        AuditError::MissingField("manifest.json not found in archive".to_string())
    })?;
    let manifest: AuditManifest = serde_json::from_slice(manifest_data)
        .map_err(|e| AuditError::Serialization(format!("parsing manifest: {e}")))?;

    // 驗證 Ed25519 簽署（若提供 verify_key 且 signature 非空）。
    if let Some(vk) = verify_key {
        if !manifest.signature.is_empty() {
            // 重建無簽署的 manifest 以計算可驗證的 bytes。
            let unsigned = AuditManifest {
                files: manifest.files.clone(),
                created_at: manifest.created_at.clone(),
                engine_version: manifest.engine_version.clone(),
                signature: String::new(),
            };
            let manifest_bytes = serde_json::to_vec(&unsigned)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;
            let digest = Sha256::digest(&manifest_bytes);

            let sig_bytes = BASE64.decode(&manifest.signature).map_err(|e| {
                AuditError::Signature(format!("invalid signature base64: {e}"))
            })?;
            let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
                AuditError::Signature(format!("invalid signature format: {e}"))
            })?;

            vk.verify(&digest, &signature).map_err(|e| {
                AuditError::IntegrityViolation(format!("manifest signature verification failed: {e}"))
            })?;

            info!("audit bundle signature verified");
        }
    }

    // 檢查 archive 是否包含 manifest 未列出的額外檔案。
    let known_files: std::collections::BTreeSet<&str> = manifest
        .files
        .keys()
        .map(String::as_str)
        .chain(std::iter::once("manifest.json"))
        .collect();
    for archive_file in files.keys() {
        if !known_files.contains(archive_file.as_str()) {
            return Err(AuditError::IntegrityViolation(format!(
                "unexpected file in archive not listed in manifest: '{archive_file}'"
            )));
        }
    }

    // Verify checksums
    for (filename, expected_hash) in &manifest.files {
        let data = files.get(filename.as_str()).ok_or_else(|| {
            AuditError::IntegrityViolation(format!(
                "{filename} listed in manifest but not in archive"
            ))
        })?;
        let actual_hash = sha256_hex(&String::from_utf8_lossy(data));
        if actual_hash != *expected_hash {
            return Err(AuditError::IntegrityViolation(format!(
                "{filename}: expected {expected_hash}, got {actual_hash}"
            )));
        }
    }

    // Parse the rest
    let report_data = files
        .get("scan-report.json")
        .ok_or_else(|| AuditError::MissingField("scan-report.json not in archive".to_string()))?;
    let report: serde_json::Value = serde_json::from_slice(report_data)
        .map_err(|e| AuditError::Serialization(format!("parsing report: {e}")))?;

    let rules_data = files
        .get("rules-applied.json")
        .ok_or_else(|| AuditError::MissingField("rules-applied.json not in archive".to_string()))?;
    let rules_applied: Vec<RuleMetadata> = serde_json::from_slice(rules_data)
        .map_err(|e| AuditError::Serialization(format!("parsing rules: {e}")))?;

    let config_data = files
        .get("config.json")
        .ok_or_else(|| AuditError::MissingField("config.json not in archive".to_string()))?;
    let config: BTreeMap<String, serde_json::Value> = serde_json::from_slice(config_data)
        .map_err(|e| AuditError::Serialization(format!("parsing config: {e}")))?;

    let policy = files
        .get("policy.json")
        .and_then(|data| serde_json::from_slice(data).ok());

    info!(path = %path.display(), "audit bundle verified");

    Ok(AuditBundle {
        scan_id: String::new(), // Not stored separately in archive — derive from report if needed
        created_at: manifest.created_at.clone(),
        engine_version: manifest.engine_version.clone(),
        report,
        rules_applied,
        policy,
        config,
        manifest,
        schema_version: "1.0.0".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Computes the hex-encoded SHA-256 digest of a string.
fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> serde_json::Value {
        serde_json::json!({
            "findings": [],
            "files_scanned": 10,
            "files_skipped": 0,
        })
    }

    fn sample_rules() -> Vec<RuleMetadata> {
        vec![RuleMetadata {
            rule_id: "atlas/security/typescript/sql-injection".to_string(),
            name: "SQL Injection".to_string(),
            version: "1.0.0".to_string(),
            category: "security".to_string(),
            severity: "high".to_string(),
        }]
    }

    #[test]
    fn builder_minimal() {
        let bundle = AuditBundleBuilder::new("scan-001", "0.1.0")
            .report(sample_report())
            .build()
            .unwrap();

        assert_eq!(bundle.scan_id, "scan-001");
        assert_eq!(bundle.engine_version, "0.1.0");
        assert!(!bundle.created_at.is_empty());
        assert!(bundle.manifest.files.contains_key("scan-report.json"));
        assert!(bundle.manifest.files.contains_key("config.json"));
    }

    #[test]
    fn builder_with_all_fields() {
        let bundle = AuditBundleBuilder::new("scan-002", "0.1.0")
            .report(sample_report())
            .rules_applied(sample_rules())
            .policy(serde_json::json!({"fail_on": {"critical": 0}}))
            .config_entry("max_file_size_kb", serde_json::json!(1024))
            .build()
            .unwrap();

        assert_eq!(bundle.rules_applied.len(), 1);
        assert!(bundle.policy.is_some());
        assert!(bundle.manifest.files.contains_key("policy.json"));
        assert_eq!(bundle.manifest.files.len(), 4); // report, rules, config, policy
    }

    #[test]
    fn builder_missing_report() {
        let result = AuditBundleBuilder::new("scan-003", "0.1.0").build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuditError::MissingField(_)));
    }

    #[test]
    fn manifest_checksums_deterministic() {
        let b1 = AuditBundleBuilder::new("scan-004", "0.1.0")
            .report(sample_report())
            .rules_applied(sample_rules())
            .build()
            .unwrap();

        let b2 = AuditBundleBuilder::new("scan-004", "0.1.0")
            .report(sample_report())
            .rules_applied(sample_rules())
            .build()
            .unwrap();

        // Checksums should match for same content
        assert_eq!(
            b1.manifest.files.get("scan-report.json"),
            b2.manifest.files.get("scan-report.json")
        );
        assert_eq!(
            b1.manifest.files.get("rules-applied.json"),
            b2.manifest.files.get("rules-applied.json")
        );
    }

    #[test]
    fn sha256_hex_known_value() {
        let hash = sha256_hex("hello");
        assert_eq!(hash.len(), 64);
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn write_and_verify_bundle_roundtrip() {
        let bundle = AuditBundleBuilder::new("scan-roundtrip", "0.1.0")
            .report(sample_report())
            .rules_applied(sample_rules())
            .policy(serde_json::json!({"level": "strict"}))
            .config_entry("jobs", serde_json::json!(4))
            .build()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("audit-bundle.tar.gz");

        write_bundle_archive(&bundle, &archive_path).unwrap();
        assert!(archive_path.exists());

        let verified = verify_bundle_archive(&archive_path).unwrap();
        assert_eq!(verified.report, bundle.report);
        assert_eq!(verified.rules_applied.len(), bundle.rules_applied.len());
        assert!(verified.policy.is_some());
    }

    #[test]
    fn rule_metadata_serde_roundtrip() {
        let meta = RuleMetadata {
            rule_id: "test/rule".to_string(),
            name: "Test Rule".to_string(),
            version: "1.0.0".to_string(),
            category: "security".to_string(),
            severity: "high".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: RuleMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule_id, meta.rule_id);
        assert_eq!(back.name, meta.name);
    }

    // -- 1C: Audit Bundle 簽署測試 -----------------------------------------

    /// 產生測試用 Ed25519 keypair。
    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let seed = [42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn signed_bundle_roundtrip() {
        let (sk, vk) = test_keypair();

        let bundle = AuditBundleBuilder::new("scan-signed", "0.1.0")
            .report(sample_report())
            .rules_applied(sample_rules())
            .signing_key(sk)
            .build()
            .unwrap();

        // 簽署不應為空。
        assert!(!bundle.manifest.signature.is_empty());

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("signed-bundle.tar.gz");

        write_bundle_archive(&bundle, &archive_path).unwrap();

        // 用正確金鑰驗證 → 成功。
        let verified = verify_bundle_archive_with_key(&archive_path, Some(&vk)).unwrap();
        assert_eq!(verified.report, bundle.report);
    }

    #[test]
    fn tampered_bundle_fails_verification() {
        let (sk, vk) = test_keypair();

        let bundle = AuditBundleBuilder::new("scan-tamper", "0.1.0")
            .report(sample_report())
            .signing_key(sk)
            .build()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("tampered-bundle.tar.gz");

        write_bundle_archive(&bundle, &archive_path).unwrap();

        // 篡改 archive 內容：重寫 scan-report.json 為不同內容。
        {
            // 讀取原始 archive
            let file = std::fs::File::open(&archive_path).unwrap();
            let dec = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(dec);
            let mut file_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();

            for entry in archive.entries().unwrap() {
                let mut entry = entry.unwrap();
                let name = entry.path().unwrap().to_string_lossy().to_string();
                let mut data = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut data).unwrap();
                file_map.insert(name, data);
            }

            // 篡改 report 內容
            file_map.insert(
                "scan-report.json".to_string(),
                b"{\"findings\": [\"INJECTED\"]}".to_vec(),
            );

            // 重建 archive
            let out = std::fs::File::create(&archive_path).unwrap();
            let enc =
                flate2::write::GzEncoder::new(out, flate2::Compression::default());
            let mut builder = tar::Builder::new(enc);
            for (name, data) in &file_map {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, data.as_slice()).unwrap();
            }
            builder.finish().unwrap();
        }

        // 驗證應失敗（checksum 不匹配）。
        let result = verify_bundle_archive_with_key(&archive_path, Some(&vk));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expected") || err.contains("integrity"),
            "got: {err}"
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (sk, _vk) = test_keypair();

        let bundle = AuditBundleBuilder::new("scan-wrongkey", "0.1.0")
            .report(sample_report())
            .signing_key(sk)
            .build()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("wrongkey-bundle.tar.gz");
        write_bundle_archive(&bundle, &archive_path).unwrap();

        // 用不同金鑰驗證 → 失敗。
        let wrong_seed = [99u8; 32];
        let wrong_sk = SigningKey::from_bytes(&wrong_seed);
        let wrong_vk = wrong_sk.verifying_key();

        let result = verify_bundle_archive_with_key(&archive_path, Some(&wrong_vk));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("signature verification failed"), "got: {err}");
    }

    #[test]
    fn extra_file_in_archive_detected() {
        let bundle = AuditBundleBuilder::new("scan-extra", "0.1.0")
            .report(sample_report())
            .build()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("extra-bundle.tar.gz");

        // 手動建立含額外檔案的 archive。
        {
            let file = std::fs::File::create(&archive_path).unwrap();
            let enc =
                flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut builder = tar::Builder::new(enc);

            let mut add = |name: &str, data: &[u8]| {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, data)
                    .unwrap();
            };

            let report_json = serde_json::to_vec_pretty(&bundle.report).unwrap();
            add("scan-report.json", &report_json);

            let rules_json = serde_json::to_vec_pretty(&bundle.rules_applied).unwrap();
            add("rules-applied.json", &rules_json);

            let config_json = serde_json::to_vec_pretty(&bundle.config).unwrap();
            add("config.json", &config_json);

            let manifest_json = serde_json::to_vec_pretty(&bundle.manifest).unwrap();
            add("manifest.json", &manifest_json);

            // 額外檔案 — manifest 中未列出。
            add("evil-payload.bin", b"malicious data");

            builder.finish().unwrap();
        }

        let result = verify_bundle_archive(&archive_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("evil-payload.bin"), "got: {err}");
    }
}
