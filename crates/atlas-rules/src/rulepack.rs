//! Rulepack management for Atlas Local SAST.
//!
//! This module implements the rulepack lifecycle:
//!
//! - **T042**: [`RulepackManifest`] struct with manifest deserialization.
//! - **T043**: Ed25519 signature verification via [`verify_manifest`].
//! - **T044**: Install pipeline via [`install_rulepack`] -- decompress `.pack`
//!   archive, verify signature, extract rules to the store directory.
//! - **T045**: Rollback via [`rollback_rulepack`] -- archive the current
//!   version and restore the previous one.
//! - **T046**: List installed rulepacks via [`list_rulepacks`].
//! - **T049**: Rule conflict resolution -- newer rule version replaces older;
//!   conflicts are logged as warnings.
//!
//! # Pack archive format
//!
//! A `.pack` file is a gzipped tar archive containing:
//!
//! - `manifest.json` at the archive root
//! - Rule files (YAML, `.rhai`, `.so`) referenced by [`ManifestRuleEntry::file`]
//!
//! # Store directory layout
//!
//! ```text
//! {store_dir}/
//!   {pack_id}/
//!     {version}/
//!       manifest.json
//!       rules/
//!         ...rule files...
//!     .rollback/
//!       {prev_version}/
//!         manifest.json
//!         rules/
//!           ...rule files...
//! ```

use std::collections::HashMap;
use std::io::Read as IoRead;
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use hex;
use sha2::{Digest, Sha256};
use tar::Archive;
use tracing::warn;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during rulepack operations.
#[derive(Debug, thiserror::Error)]
pub enum RulepackError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The manifest could not be parsed or is structurally invalid.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// The requested rulepack was not found in the store.
    #[error("rulepack not found: {0}")]
    NotFound(String),

    /// No rollback data is available for the given rulepack.
    #[error("no rollback available for rulepack '{0}'")]
    NoRollback(String),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A lightweight entry describing a single rule inside a rulepack manifest.
///
/// This does *not* contain the full rule definition -- it is just the metadata
/// needed to locate and categorize the rule within the pack archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRuleEntry {
    /// Unique rule identifier (e.g. `atlas/security/typescript/sql-injection`).
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// Severity level (e.g. `critical`, `high`, `medium`, `low`, `info`).
    pub severity: String,
    /// Category (e.g. `security`, `quality`, `secrets`).
    pub category: String,
    /// Target programming language.
    pub language: String,
    /// Analysis depth (`L1`, `L2`, `L3`).
    pub analysis_level: String,
    /// Rule implementation type (`Declarative`, `Scripted`, `Compiled`).
    pub rule_type: String,
    /// Rule version in SemVer format.
    pub version: String,
    /// Relative path to the rule file within the pack archive.
    pub file: String,
    /// SHA-256 hex digest of the rule file content（向後相容，可選欄位）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The rulepack manifest that is stored as `manifest.json` inside a `.pack`
/// archive and in the installed pack directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulepackManifest {
    /// Rulepack identifier (e.g. `atlas-security-rules`).
    pub id: String,
    /// SemVer version string.
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Author or organization.
    pub author: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Rule entries in the manifest.
    pub rules: Vec<ManifestRuleEntry>,
    /// Must equal `rules.len()`.
    pub rule_count: u32,
    /// Ed25519 signature (base64) over the SHA-256 of the manifest without
    /// the `signature` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Signing public key (base64-encoded Ed25519 verifying key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// SHA-256 hex digest of the pack archive content.
    pub checksum: String,
    /// Minimum engine version required to run these rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_engine_version: Option<String>,
}

impl RulepackManifest {
    /// Validates internal consistency of the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`RulepackError::InvalidManifest`] if:
    /// - `id` is empty.
    /// - `rule_count` does not match `rules.len()`.
    pub fn validate(&self) -> Result<(), RulepackError> {
        if self.id.is_empty() {
            return Err(RulepackError::InvalidManifest(
                "rulepack id must not be empty".to_owned(),
            ));
        }
        if self.rule_count as usize != self.rules.len() {
            return Err(RulepackError::InvalidManifest(format!(
                "rule_count ({}) does not match rules.len() ({})",
                self.rule_count,
                self.rules.len()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Information about a conflict between rules from different packs.
#[derive(Debug, Clone)]
pub struct RuleConflict {
    /// The rule ID that conflicted.
    pub rule_id: String,
    /// The pack that previously owned this rule.
    pub existing_pack: String,
    /// The version of the rule that was replaced.
    pub existing_version: String,
    /// The version of the rule that won.
    pub new_version: String,
}

/// Result of a successful rulepack installation.
#[derive(Debug)]
pub struct InstallResult {
    /// The installed rulepack identifier.
    pub pack_id: String,
    /// The installed version.
    pub version: String,
    /// Directory where the pack was installed.
    pub install_dir: PathBuf,
    /// Number of rule files extracted.
    pub rules_installed: usize,
    /// Whether a previous version was archived for rollback.
    pub previous_archived: bool,
    /// Any rule conflicts that were resolved during installation.
    pub conflicts: Vec<RuleConflict>,
}

/// Result of a successful rollback operation.
#[derive(Debug)]
pub struct RollbackResult {
    /// The rulepack that was rolled back.
    pub pack_id: String,
    /// The version that was rolled back (removed).
    pub rolled_back_version: String,
    /// The version that was restored.
    pub restored_version: String,
}

/// Summary of an installed rulepack (returned by [`list_rulepacks`]).
#[derive(Debug, Clone)]
pub struct InstalledRulepack {
    /// Rulepack identifier.
    pub id: String,
    /// Installed version.
    pub version: String,
    /// Pack description.
    pub description: String,
    /// Author.
    pub author: String,
    /// Number of rules in this pack.
    pub rule_count: u32,
    /// Installation directory.
    pub install_dir: PathBuf,
    /// Whether a rollback archive exists.
    pub has_rollback: bool,
}

// ---------------------------------------------------------------------------
// T043: Signature verification
// ---------------------------------------------------------------------------

/// Verifies an Ed25519 signature over the SHA-256 hash of manifest bytes.
///
/// The verification process:
/// 1. Decode the base64 public key into a 32-byte Ed25519 verifying key.
/// 2. Decode the base64 signature into a 64-byte Ed25519 signature.
/// 3. Compute SHA-256 of `manifest_bytes`.
/// 4. Verify the signature over the SHA-256 digest.
///
/// # Errors
///
/// Returns [`RulepackError::SignatureVerification`] if:
/// - The public key or signature cannot be base64-decoded.
/// - The decoded bytes have incorrect lengths.
/// - The cryptographic verification fails.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), RulepackError> {
    // Decode public key from base64.
    let pk_bytes = BASE64.decode(public_key_b64).map_err(|e| {
        RulepackError::SignatureVerification(format!("invalid public key base64: {e}"))
    })?;

    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|v: Vec<u8>| {
        RulepackError::SignatureVerification(format!(
            "public key must be 32 bytes, got {}",
            v.len()
        ))
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|e| {
        RulepackError::SignatureVerification(format!("invalid Ed25519 public key: {e}"))
    })?;

    // Decode signature from base64.
    let sig_bytes = BASE64.decode(signature_b64).map_err(|e| {
        RulepackError::SignatureVerification(format!("invalid signature base64: {e}"))
    })?;

    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|v: Vec<u8>| {
        RulepackError::SignatureVerification(format!("signature must be 64 bytes, got {}", v.len()))
    })?;

    let signature = Signature::from_bytes(&sig_array);

    // Compute SHA-256 of the manifest bytes.
    let digest = Sha256::digest(manifest_bytes);

    // Verify the signature over the digest.
    verifying_key
        .verify(&digest, &signature)
        .map_err(|e| RulepackError::SignatureVerification(format!("verification failed: {e}")))?;

    Ok(())
}

/// Produces the manifest bytes suitable for signing -- the JSON encoding of
/// the manifest with the `signature` field stripped out.
///
/// This is used both during signing (to create the bytes to sign) and during
/// verification (to recreate the bytes that were signed).
fn manifest_bytes_for_signing(manifest: &RulepackManifest) -> Result<Vec<u8>, RulepackError> {
    // Clone and remove the signature so the bytes are deterministic.
    let mut signable = manifest.clone();
    signable.signature = None;
    let bytes = serde_json::to_vec(&signable)?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Path safety validation
// ---------------------------------------------------------------------------

/// 驗證相對路徑不含路徑穿越或絕對路徑元件。
///
/// 拒絕包含 `..`（ParentDir）、根目錄（RootDir）、前綴（Prefix）的路徑，
/// 防止 rulepack 安裝時寫入 install_dir 以外的位置。
fn is_safe_relative_path(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    let path = Path::new(p);
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

// ---------------------------------------------------------------------------
// T044: Install pipeline
// ---------------------------------------------------------------------------

/// Installs a rulepack from a `.pack` archive into the store directory.
///
/// # Steps
///
/// 1. Read and decompress the `.pack` archive (gzipped tar).
/// 2. Extract `manifest.json` from the archive root.
/// 3. Deserialize and validate the manifest.
/// 4. If the manifest has a signature, verify it against the trusted keys.
/// 5. Create the install directory at `{store_dir}/{pack_id}/{version}/`.
/// 6. Extract rule files into the install directory.
/// 7. Write `manifest.json` to the install directory.
/// 8. If a previous version exists, archive it to `.rollback/`.
///
/// # Rule conflict resolution (T049)
///
/// After installation, any rule ID that already exists from a different pack
/// is checked: the rule with the newer version wins and a `WARNING` is logged.
///
/// # Errors
///
/// Returns [`RulepackError`] on I/O failures, invalid manifests, or failed
/// signature verification.
pub fn install_rulepack(
    pack_path: &Path,
    store_dir: &Path,
    trusted_keys: &[String],
) -> Result<InstallResult, RulepackError> {
    // Read the entire .pack archive into memory.
    let pack_bytes = std::fs::read(pack_path)?;

    // Decompress and scan the tar archive for manifest.json and rule files.
    let gz = GzDecoder::new(pack_bytes.as_slice());
    let mut archive = Archive::new(gz);

    let mut manifest_json: Option<Vec<u8>> = None;
    let mut rule_files: HashMap<String, Vec<u8>> = HashMap::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy().to_string();

        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        if path_str == "manifest.json" {
            manifest_json = Some(contents);
        } else {
            rule_files.insert(path_str, contents);
        }
    }

    // Parse the manifest.
    let manifest_bytes = manifest_json.ok_or_else(|| {
        RulepackError::InvalidManifest("manifest.json not found in archive".to_owned())
    })?;

    let manifest: RulepackManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate()?;

    // Verify signature if present.
    if let Some(ref sig) = manifest.signature {
        let signable_bytes = manifest_bytes_for_signing(&manifest)?;

        // Try the manifest's own public key first, then trusted keys.
        let mut keys_to_try: Vec<&str> = Vec::new();
        if let Some(ref pk) = manifest.public_key {
            keys_to_try.push(pk.as_str());
        }
        for tk in trusted_keys {
            keys_to_try.push(tk.as_str());
        }

        if keys_to_try.is_empty() {
            return Err(RulepackError::SignatureVerification(
                "manifest has a signature but no public key is available for verification"
                    .to_owned(),
            ));
        }

        let mut verified = false;
        for key in &keys_to_try {
            if verify_manifest(&signable_bytes, sig, key).is_ok() {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err(RulepackError::SignatureVerification(
                "signature does not match any trusted key".to_owned(),
            ));
        }
    }

    // Archive previous version for rollback if one exists.
    let pack_dir = store_dir.join(&manifest.id);
    let previous_archived = archive_previous_version(&pack_dir, &manifest.id)?;

    // Create install directory.
    let install_dir = pack_dir.join(&manifest.version);
    std::fs::create_dir_all(&install_dir)?;

    // Write manifest.json.
    let manifest_out = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(install_dir.join("manifest.json"), &manifest_out)?;

    // Extract rule files（含路徑穿越防護 + 完整性驗證）。
    let mut rules_installed = 0;
    for entry in &manifest.rules {
        // 1A: 路徑穿越防護 — 拒絕含 `..`、絕對路徑等危險路徑元件。
        if !is_safe_relative_path(&entry.file) {
            return Err(RulepackError::InvalidManifest(format!(
                "unsafe file path in manifest: '{}'",
                entry.file
            )));
        }

        let contents = match rule_files.get(&entry.file) {
            Some(c) => c,
            None => {
                // 1B: manifest 列出但 archive 缺失的檔案 → 錯誤。
                return Err(RulepackError::InvalidManifest(format!(
                    "rule file '{}' listed in manifest but not found in archive",
                    entry.file
                )));
            }
        };

        // 1B: SHA-256 完整性驗證 — 若 manifest 提供 sha256，必須匹配。
        if let Some(ref expected_hash) = entry.sha256 {
            let actual_hash = hex::encode(Sha256::digest(contents));
            if actual_hash != *expected_hash {
                return Err(RulepackError::InvalidManifest(format!(
                    "SHA-256 mismatch for '{}': expected {}, got {}",
                    entry.file, expected_hash, actual_hash
                )));
            }
        }

        // 安裝前用 canonicalize 驗證目標路徑仍在 install_dir 之下。
        let dest = install_dir.join(&entry.file);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, contents)?;

        // 驗證寫入後的實際路徑仍在 install_dir 內。
        let canonical_dest = dest.canonicalize()?;
        let canonical_install = install_dir.canonicalize()?;
        if !canonical_dest.starts_with(&canonical_install) {
            // 清理已寫入的檔案
            let _ = std::fs::remove_file(&dest);
            return Err(RulepackError::InvalidManifest(format!(
                "rule file '{}' resolved outside install directory",
                entry.file
            )));
        }

        rules_installed += 1;
    }

    // Conflict resolution (T049).
    let conflicts = detect_conflicts(&manifest, store_dir)?;
    for conflict in &conflicts {
        warn!(
            rule_id = %conflict.rule_id,
            existing_pack = %conflict.existing_pack,
            existing_version = %conflict.existing_version,
            new_version = %conflict.new_version,
            "rule conflict: rule '{}' from pack '{}' v{} replaced by v{} from pack '{}'",
            conflict.rule_id,
            conflict.existing_pack,
            conflict.existing_version,
            conflict.new_version,
            manifest.id,
        );
    }

    Ok(InstallResult {
        pack_id: manifest.id.clone(),
        version: manifest.version.clone(),
        install_dir,
        rules_installed,
        previous_archived,
        conflicts,
    })
}

/// Scans other installed packs for rules that conflict with the newly
/// installed manifest's rules. A conflict occurs when a rule ID exists in
/// another pack. The newer version wins.
fn detect_conflicts(
    new_manifest: &RulepackManifest,
    store_dir: &Path,
) -> Result<Vec<RuleConflict>, RulepackError> {
    let mut conflicts = Vec::new();

    // Build a map of new rule IDs to their versions.
    let new_rules: HashMap<&str, &str> = new_manifest
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r.version.as_str()))
        .collect();

    // Scan existing installed packs.
    let entries = match std::fs::read_dir(store_dir) {
        Ok(e) => e,
        Err(_) => return Ok(conflicts), // store_dir doesn't exist yet
    };

    for entry in entries {
        let entry = entry?;
        let pack_id = entry.file_name().to_string_lossy().to_string();

        // Skip the pack we just installed and hidden directories.
        if pack_id == new_manifest.id || pack_id.starts_with('.') {
            continue;
        }

        if !entry.path().is_dir() {
            continue;
        }

        // Find the current version directory (skip .rollback).
        let sub_entries = std::fs::read_dir(entry.path())?;
        for sub in sub_entries {
            let sub = sub?;
            let sub_name = sub.file_name().to_string_lossy().to_string();
            if sub_name.starts_with('.') || !sub.path().is_dir() {
                continue;
            }

            let manifest_path = sub.path().join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }

            let bytes = std::fs::read(&manifest_path)?;
            let existing: RulepackManifest = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };

            for existing_rule in &existing.rules {
                if let Some(&new_version) = new_rules.get(existing_rule.id.as_str()) {
                    conflicts.push(RuleConflict {
                        rule_id: existing_rule.id.clone(),
                        existing_pack: pack_id.clone(),
                        existing_version: existing_rule.version.clone(),
                        new_version: new_version.to_owned(),
                    });
                }
            }
        }
    }

    Ok(conflicts)
}

/// Archives the current installed version of a pack to `.rollback/`.
///
/// Returns `true` if a previous version was archived, `false` if there was
/// nothing to archive.
fn archive_previous_version(pack_dir: &Path, _pack_id: &str) -> Result<bool, RulepackError> {
    if !pack_dir.exists() {
        return Ok(false);
    }

    // Find the current version directory (not .rollback).
    let mut current_version_dir: Option<PathBuf> = None;
    let mut current_version_name: Option<String> = None;

    let entries = std::fs::read_dir(pack_dir)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || !entry.path().is_dir() {
            continue;
        }
        // Take the first version directory found.
        current_version_dir = Some(entry.path());
        current_version_name = Some(name);
        break;
    }

    let (src_dir, version_name) = match (current_version_dir, current_version_name) {
        (Some(d), Some(n)) => (d, n),
        _ => return Ok(false),
    };

    // Create rollback directory.
    let rollback_dir = pack_dir.join(".rollback").join(&version_name);

    // Remove any existing rollback for this version.
    if rollback_dir.exists() {
        std::fs::remove_dir_all(&rollback_dir)?;
    }

    std::fs::create_dir_all(&rollback_dir)?;

    // Copy files from current version to rollback.
    copy_dir_recursive(&src_dir, &rollback_dir)?;

    // Remove the current version directory.
    std::fs::remove_dir_all(&src_dir)?;

    Ok(true)
}

/// Recursively copies all files and subdirectories from `src` to `dst`.
///
/// 包含路徑穿越防護：驗證所有相對路徑不含 `..` 等危險元件。
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), RulepackError> {
    for entry in walkdir::WalkDir::new(src) {
        let entry = entry.map_err(|e| std::io::Error::other(e.to_string()))?;

        let relative = entry
            .path()
            .strip_prefix(src)
            .expect("walkdir entry should be under src");

        // 路徑穿越防護
        let relative_str = relative.to_string_lossy();
        if !relative_str.is_empty() && !is_safe_relative_path(&relative_str) {
            return Err(RulepackError::InvalidManifest(format!(
                "unsafe path during copy: '{relative_str}'"
            )));
        }

        let dest_path = dst.join(relative);

        if entry.path().is_dir() {
            std::fs::create_dir_all(&dest_path)?;
        } else {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// T045: Rollback
// ---------------------------------------------------------------------------

/// Rolls back a rulepack to its previously installed version.
///
/// # Steps
///
/// 1. Find the current installed version directory under
///    `{store_dir}/{pack_id}/`.
/// 2. Find the rollback archive under `{store_dir}/{pack_id}/.rollback/`.
/// 3. Remove the current version directory.
/// 4. Restore the rollback version into a new version directory.
/// 5. Remove the rollback archive.
///
/// # Errors
///
/// - [`RulepackError::NotFound`] if the pack is not installed.
/// - [`RulepackError::NoRollback`] if no rollback archive exists.
pub fn rollback_rulepack(pack_id: &str, store_dir: &Path) -> Result<RollbackResult, RulepackError> {
    let pack_dir = store_dir.join(pack_id);

    if !pack_dir.exists() {
        return Err(RulepackError::NotFound(pack_id.to_owned()));
    }

    // Find the current version directory.
    let mut current_dir: Option<PathBuf> = None;
    let mut current_version: Option<String> = None;

    let entries = std::fs::read_dir(&pack_dir)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || !entry.path().is_dir() {
            continue;
        }
        current_dir = Some(entry.path());
        current_version = Some(name);
        break;
    }

    let (cur_dir, cur_ver) = match (current_dir, current_version) {
        (Some(d), Some(v)) => (d, v),
        _ => return Err(RulepackError::NotFound(pack_id.to_owned())),
    };

    // Find the rollback archive.
    let rollback_base = pack_dir.join(".rollback");
    if !rollback_base.exists() {
        return Err(RulepackError::NoRollback(pack_id.to_owned()));
    }

    let mut rollback_dir: Option<PathBuf> = None;
    let mut rollback_version: Option<String> = None;

    let rb_entries = std::fs::read_dir(&rollback_base)?;
    for entry in rb_entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.path().is_dir() {
            rollback_dir = Some(entry.path());
            rollback_version = Some(name);
            break;
        }
    }

    let (rb_dir, rb_ver) = match (rollback_dir, rollback_version) {
        (Some(d), Some(v)) => (d, v),
        _ => return Err(RulepackError::NoRollback(pack_id.to_owned())),
    };

    // Remove current version.
    std::fs::remove_dir_all(&cur_dir)?;

    // Restore rollback version into the pack directory.
    let restored_dir = pack_dir.join(&rb_ver);
    std::fs::create_dir_all(&restored_dir)?;
    copy_dir_recursive(&rb_dir, &restored_dir)?;

    // Remove the rollback archive.
    std::fs::remove_dir_all(&rollback_base)?;

    Ok(RollbackResult {
        pack_id: pack_id.to_owned(),
        rolled_back_version: cur_ver,
        restored_version: rb_ver,
    })
}

// ---------------------------------------------------------------------------
// T046: List installed rulepacks
// ---------------------------------------------------------------------------

/// Lists all rulepacks installed in the store directory.
///
/// Each subdirectory of `store_dir` is treated as a pack ID. Inside each pack
/// directory, version subdirectories (excluding `.rollback`) are scanned for
/// `manifest.json`.
///
/// # Errors
///
/// Returns [`RulepackError::Io`] if the store directory cannot be read.
#[must_use = "the list of installed rulepacks should be used"]
pub fn list_rulepacks(store_dir: &Path) -> Result<Vec<InstalledRulepack>, RulepackError> {
    let mut result = Vec::new();

    if !store_dir.exists() {
        return Ok(result);
    }

    let entries = std::fs::read_dir(store_dir)?;
    for entry in entries {
        let entry = entry?;
        let pack_id = entry.file_name().to_string_lossy().to_string();

        if !entry.path().is_dir() || pack_id.starts_with('.') {
            continue;
        }

        let has_rollback = entry.path().join(".rollback").exists();

        // Find version directories.
        let sub_entries = std::fs::read_dir(entry.path())?;
        for sub in sub_entries {
            let sub = sub?;
            let sub_name = sub.file_name().to_string_lossy().to_string();
            if sub_name.starts_with('.') || !sub.path().is_dir() {
                continue;
            }

            let manifest_path = sub.path().join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }

            let bytes = std::fs::read(&manifest_path)?;
            let manifest: RulepackManifest = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };

            result.push(InstalledRulepack {
                id: manifest.id,
                version: manifest.version,
                description: manifest.description,
                author: manifest.author,
                rule_count: manifest.rule_count,
                install_dir: sub.path(),
                has_rollback,
            });
        }
    }

    // Sort by id for deterministic output.
    result.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tempfile::TempDir;

    // -- Helpers ----------------------------------------------------------

    /// Creates a minimal [`RulepackManifest`] for testing.
    fn make_manifest(id: &str, version: &str, rules: Vec<ManifestRuleEntry>) -> RulepackManifest {
        let rule_count = rules.len() as u32;
        RulepackManifest {
            id: id.to_owned(),
            version: version.to_owned(),
            description: format!("Test rulepack {id}"),
            author: "Atlas Test".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            rules,
            rule_count,
            signature: None,
            public_key: None,
            checksum: "abc123".to_owned(),
            min_engine_version: None,
        }
    }

    /// Creates a single [`ManifestRuleEntry`].
    fn make_rule_entry(id: &str, version: &str) -> ManifestRuleEntry {
        ManifestRuleEntry {
            id: id.to_owned(),
            name: format!("Rule {id}"),
            severity: "high".to_owned(),
            category: "security".to_owned(),
            language: "TypeScript".to_owned(),
            analysis_level: "L1".to_owned(),
            rule_type: "Declarative".to_owned(),
            version: version.to_owned(),
            file: format!("rules/{}.yaml", id.replace('/', "_")),
            sha256: None,
        }
    }

    /// Builds a `.pack` archive (gzipped tar) in memory from a manifest and
    /// rule file contents.
    fn build_pack_archive(
        manifest: &RulepackManifest,
        rule_contents: &HashMap<String, Vec<u8>>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::fast());
            let mut builder = tar::Builder::new(gz);

            // Add manifest.json.
            let manifest_bytes = serde_json::to_vec_pretty(manifest).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_path("manifest.json").unwrap();
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, manifest_bytes.as_slice()).unwrap();

            // Add rule files.
            for (path, contents) in rule_contents {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_path(path).unwrap();
                hdr.set_size(contents.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                builder.append(&hdr, contents.as_slice()).unwrap();
            }

            builder.finish().unwrap();
            // GzEncoder is finished when builder is dropped.
        }
        buf
    }

    /// Writes a `.pack` file to a temp dir and returns the path.
    fn write_pack_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Generates an Ed25519 keypair, signs the manifest, and mutates it
    /// in-place to set `public_key` and `signature`. Returns the public key
    /// base64 string for use as a trusted key.
    ///
    /// The manifest's `public_key` is set *before* computing the signable
    /// bytes so that the signature covers the full manifest (minus `signature`).
    /// Test-only counter for generating distinct deterministic keys.
    static TEST_KEY_COUNTER: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

    fn sign_manifest_in_place(manifest: &mut RulepackManifest) -> String {
        use ed25519_dalek::Signer;

        // Generate a deterministic key from a seed (no RNG dependency needed).
        let counter = TEST_KEY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut seed = [0u8; 32];
        seed[0] = counter;
        seed[31] = 0xAB; // make it non-trivial
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 = BASE64.encode(verifying_key.as_bytes());

        // Set public_key before computing signable bytes (signature is still None).
        manifest.public_key = Some(public_key_b64.clone());

        let signable_bytes = manifest_bytes_for_signing(manifest).unwrap();
        let digest = Sha256::digest(&signable_bytes);
        let signature = signing_key.sign(&digest);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        manifest.signature = Some(signature_b64);

        public_key_b64
    }

    /// Returns a (public_key_b64, signature_b64) for a manifest without
    /// mutating it. Used by standalone verification tests.
    fn sign_manifest(manifest: &RulepackManifest) -> (String, String) {
        use ed25519_dalek::Signer;

        let counter = TEST_KEY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut seed = [0u8; 32];
        seed[0] = counter;
        seed[31] = 0xAB;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 = BASE64.encode(verifying_key.as_bytes());

        let signable_bytes = manifest_bytes_for_signing(manifest).unwrap();
        let digest = Sha256::digest(&signable_bytes);
        let signature = signing_key.sign(&digest);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        (public_key_b64, signature_b64)
    }

    // -- T042: Manifest deserialization -----------------------------------

    #[test]
    fn manifest_deserialize_minimal() {
        let json = r#"{
            "id": "test-pack",
            "version": "1.0.0",
            "description": "Test",
            "author": "Atlas",
            "created_at": "2026-01-01T00:00:00Z",
            "rules": [],
            "rule_count": 0,
            "checksum": "abc"
        }"#;

        let manifest: RulepackManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.id, "test-pack");
        assert_eq!(manifest.version, "1.0.0");
        assert!(manifest.signature.is_none());
        assert!(manifest.public_key.is_none());
        assert!(manifest.min_engine_version.is_none());
    }

    #[test]
    fn manifest_deserialize_with_rules() {
        let entry = make_rule_entry("rule-1", "1.0.0");
        let manifest = make_manifest("test-pack", "2.0.0", vec![entry.clone()]);
        let json = serde_json::to_string(&manifest).unwrap();

        let deserialized: RulepackManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.rules[0].id, "rule-1");
        assert_eq!(deserialized.rule_count, 1);
    }

    #[test]
    fn manifest_validate_ok() {
        let manifest = make_manifest("test", "1.0.0", vec![make_rule_entry("r1", "1.0.0")]);
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_validate_empty_id() {
        let manifest = make_manifest("", "1.0.0", vec![]);
        let err = manifest.validate().unwrap_err();
        assert!(matches!(err, RulepackError::InvalidManifest(_)));
        assert!(err.to_string().contains("id must not be empty"));
    }

    #[test]
    fn manifest_validate_rule_count_mismatch() {
        let mut manifest = make_manifest("test", "1.0.0", vec![make_rule_entry("r1", "1.0.0")]);
        manifest.rule_count = 5;
        let err = manifest.validate().unwrap_err();
        assert!(matches!(err, RulepackError::InvalidManifest(_)));
        assert!(err.to_string().contains("rule_count"));
    }

    #[test]
    fn manifest_json_roundtrip() {
        let manifest = make_manifest(
            "atlas-security",
            "3.1.0",
            vec![
                make_rule_entry("r1", "1.0.0"),
                make_rule_entry("r2", "2.0.0"),
            ],
        );
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let back: RulepackManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    // -- T043: Signature verification ------------------------------------

    #[test]
    fn verify_valid_signature() {
        let manifest = make_manifest("signed-pack", "1.0.0", vec![]);
        let (pk_b64, sig_b64) = sign_manifest(&manifest);
        let signable = manifest_bytes_for_signing(&manifest).unwrap();

        let result = verify_manifest(&signable, &sig_b64, &pk_b64);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn verify_invalid_signature_data() {
        let manifest = make_manifest("signed-pack", "1.0.0", vec![]);
        let (pk_b64, _sig_b64) = sign_manifest(&manifest);
        let signable = manifest_bytes_for_signing(&manifest).unwrap();

        // Tamper with the signature.
        let bad_sig = BASE64.encode([0u8; 64]);

        let result = verify_manifest(&signable, &bad_sig, &pk_b64);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RulepackError::SignatureVerification(_))
        ));
    }

    #[test]
    fn verify_invalid_public_key() {
        let manifest = make_manifest("signed-pack", "1.0.0", vec![]);
        let (_pk_b64, sig_b64) = sign_manifest(&manifest);
        let signable = manifest_bytes_for_signing(&manifest).unwrap();

        // Use a different key.
        let bad_pk = BASE64.encode([1u8; 32]);

        let result = verify_manifest(&signable, &sig_b64, &bad_pk);
        assert!(result.is_err());
    }

    #[test]
    fn verify_tampered_manifest() {
        let manifest = make_manifest("signed-pack", "1.0.0", vec![]);
        let (pk_b64, sig_b64) = sign_manifest(&manifest);

        // Tamper with the manifest bytes.
        let mut signable = manifest_bytes_for_signing(&manifest).unwrap();
        signable.push(b'X');

        let result = verify_manifest(&signable, &sig_b64, &pk_b64);
        assert!(result.is_err());
    }

    #[test]
    fn verify_bad_base64_signature() {
        let result = verify_manifest(b"data", "not-base64!!!", "AAAA");
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_length_key() {
        let short_key = BASE64.encode([0u8; 16]); // 16 bytes, not 32
        let sig = BASE64.encode([0u8; 64]);
        let result = verify_manifest(b"data", &sig, &short_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    // -- T044: Install pipeline ------------------------------------------

    #[test]
    fn install_unsigned_pack() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let entry = make_rule_entry("atlas/sec/ts/sqli", "1.0.0");
        let manifest = make_manifest("test-pack", "1.0.0", vec![entry.clone()]);

        let mut rule_contents = HashMap::new();
        rule_contents.insert(
            entry.file.clone(),
            b"id: atlas/sec/ts/sqli\npattern: (ident)\n".to_vec(),
        );

        let archive = build_pack_archive(&manifest, &rule_contents);
        let pack_path = write_pack_file(tmp.path(), "test.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]).unwrap();

        assert_eq!(result.pack_id, "test-pack");
        assert_eq!(result.version, "1.0.0");
        assert_eq!(result.rules_installed, 1);
        assert!(!result.previous_archived);
        assert!(result.install_dir.exists());
        assert!(result.install_dir.join("manifest.json").exists());
        assert!(result.install_dir.join(&entry.file).exists());
    }

    #[test]
    fn install_signed_pack_with_trusted_key() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let mut manifest = make_manifest("signed-pack", "1.0.0", vec![]);
        let pk_b64 = sign_manifest_in_place(&mut manifest);

        let archive = build_pack_archive(&manifest, &HashMap::new());
        let pack_path = write_pack_file(tmp.path(), "signed.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[pk_b64]).unwrap();
        assert_eq!(result.pack_id, "signed-pack");
    }

    #[test]
    fn install_fails_with_bad_signature() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let mut manifest = make_manifest("bad-sig-pack", "1.0.0", vec![]);
        let pk_b64 = sign_manifest_in_place(&mut manifest);
        // Overwrite with a bad signature.
        manifest.signature = Some(BASE64.encode([0u8; 64]));
        // Keep the public_key from sign_manifest_in_place.
        let _ = pk_b64;

        let archive = build_pack_archive(&manifest, &HashMap::new());
        let pack_path = write_pack_file(tmp.path(), "badsig.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(RulepackError::SignatureVerification(_))
        ));
    }

    #[test]
    fn install_archives_previous_version() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Install v1.
        let manifest_v1 = make_manifest("upgrade-pack", "1.0.0", vec![]);
        let archive_v1 = build_pack_archive(&manifest_v1, &HashMap::new());
        let pack_v1 = write_pack_file(tmp.path(), "v1.pack", &archive_v1);
        let r1 = install_rulepack(&pack_v1, &store, &[]).unwrap();
        assert!(!r1.previous_archived);

        // Install v2 -- should archive v1.
        let manifest_v2 = make_manifest("upgrade-pack", "2.0.0", vec![]);
        let archive_v2 = build_pack_archive(&manifest_v2, &HashMap::new());
        let pack_v2 = write_pack_file(tmp.path(), "v2.pack", &archive_v2);
        let r2 = install_rulepack(&pack_v2, &store, &[]).unwrap();
        assert!(r2.previous_archived);
        assert_eq!(r2.version, "2.0.0");

        // Rollback dir should exist.
        let rollback_dir = store.join("upgrade-pack").join(".rollback").join("1.0.0");
        assert!(rollback_dir.exists());
        assert!(rollback_dir.join("manifest.json").exists());
    }

    #[test]
    fn install_fails_missing_manifest() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Build a tar.gz with no manifest.json.
        let mut buf = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::fast());
            let mut builder = tar::Builder::new(gz);
            let data = b"hello world";
            let mut header = tar::Header::new_gnu();
            header.set_path("some_file.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, data.as_slice()).unwrap();
            builder.finish().unwrap();
        }

        let pack_path = write_pack_file(tmp.path(), "nomanifest.pack", &buf);
        let result = install_rulepack(&pack_path, &store, &[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(RulepackError::InvalidManifest(_))));
    }

    // -- T045: Rollback --------------------------------------------------

    #[test]
    fn rollback_restores_previous_version() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Install v1.
        let entry = make_rule_entry("r1", "1.0.0");
        let manifest_v1 = make_manifest("rollback-pack", "1.0.0", vec![entry.clone()]);
        let mut rules = HashMap::new();
        rules.insert(entry.file.clone(), b"v1 content".to_vec());
        let archive_v1 = build_pack_archive(&manifest_v1, &rules);
        let pack_v1 = write_pack_file(tmp.path(), "v1.pack", &archive_v1);
        install_rulepack(&pack_v1, &store, &[]).unwrap();

        // Install v2.
        let entry2 = make_rule_entry("r1", "2.0.0");
        let manifest_v2 = make_manifest("rollback-pack", "2.0.0", vec![entry2.clone()]);
        let mut rules2 = HashMap::new();
        rules2.insert(entry2.file.clone(), b"v2 content".to_vec());
        let archive_v2 = build_pack_archive(&manifest_v2, &rules2);
        let pack_v2 = write_pack_file(tmp.path(), "v2.pack", &archive_v2);
        install_rulepack(&pack_v2, &store, &[]).unwrap();

        // Rollback.
        let result = rollback_rulepack("rollback-pack", &store).unwrap();
        assert_eq!(result.pack_id, "rollback-pack");
        assert_eq!(result.rolled_back_version, "2.0.0");
        assert_eq!(result.restored_version, "1.0.0");

        // Verify v1 is restored.
        let restored_manifest = store
            .join("rollback-pack")
            .join("1.0.0")
            .join("manifest.json");
        assert!(restored_manifest.exists());

        // v2 should be gone.
        assert!(!store.join("rollback-pack").join("2.0.0").exists());

        // Rollback dir should be removed.
        assert!(!store.join("rollback-pack").join(".rollback").exists());
    }

    #[test]
    fn rollback_fails_when_pack_not_found() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");
        std::fs::create_dir_all(&store).unwrap();

        let result = rollback_rulepack("nonexistent", &store);
        assert!(result.is_err());
        assert!(matches!(result, Err(RulepackError::NotFound(_))));
    }

    #[test]
    fn rollback_fails_when_no_rollback_data() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Install once (no previous version to archive).
        let manifest = make_manifest("no-rb-pack", "1.0.0", vec![]);
        let archive = build_pack_archive(&manifest, &HashMap::new());
        let pack_path = write_pack_file(tmp.path(), "pack.pack", &archive);
        install_rulepack(&pack_path, &store, &[]).unwrap();

        let result = rollback_rulepack("no-rb-pack", &store);
        assert!(result.is_err());
        assert!(matches!(result, Err(RulepackError::NoRollback(_))));
    }

    // -- T046: List installed packs --------------------------------------

    #[test]
    fn list_empty_store() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let result = list_rulepacks(&store).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_installed_packs() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Install two packs（提供 rule 檔案內容以通過完整性驗證）。
        let e1 = make_rule_entry("r1", "1.0.0");
        let m1 = make_manifest("beta-pack", "1.0.0", vec![e1.clone()]);
        let mut rc1 = HashMap::new();
        rc1.insert(e1.file.clone(), b"rule r1".to_vec());
        let a1 = build_pack_archive(&m1, &rc1);
        let p1 = write_pack_file(tmp.path(), "m1.pack", &a1);
        install_rulepack(&p1, &store, &[]).unwrap();

        let e2 = make_rule_entry("r2", "1.0.0");
        let e3 = make_rule_entry("r3", "1.0.0");
        let m2 = make_manifest("alpha-pack", "2.0.0", vec![e2.clone(), e3.clone()]);
        let mut rc2 = HashMap::new();
        rc2.insert(e2.file.clone(), b"rule r2".to_vec());
        rc2.insert(e3.file.clone(), b"rule r3".to_vec());
        let a2 = build_pack_archive(&m2, &rc2);
        let p2 = write_pack_file(tmp.path(), "m2.pack", &a2);
        install_rulepack(&p2, &store, &[]).unwrap();

        let packs = list_rulepacks(&store).unwrap();
        assert_eq!(packs.len(), 2);

        // Sorted by id.
        assert_eq!(packs[0].id, "alpha-pack");
        assert_eq!(packs[0].version, "2.0.0");
        assert_eq!(packs[0].rule_count, 2);

        assert_eq!(packs[1].id, "beta-pack");
        assert_eq!(packs[1].version, "1.0.0");
        assert_eq!(packs[1].rule_count, 1);
    }

    #[test]
    fn list_shows_rollback_availability() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Install v1 then v2 to create rollback data.
        let m1 = make_manifest("rb-list-pack", "1.0.0", vec![]);
        let a1 = build_pack_archive(&m1, &HashMap::new());
        let p1 = write_pack_file(tmp.path(), "v1.pack", &a1);
        install_rulepack(&p1, &store, &[]).unwrap();

        let m2 = make_manifest("rb-list-pack", "2.0.0", vec![]);
        let a2 = build_pack_archive(&m2, &HashMap::new());
        let p2 = write_pack_file(tmp.path(), "v2.pack", &a2);
        install_rulepack(&p2, &store, &[]).unwrap();

        let packs = list_rulepacks(&store).unwrap();
        assert_eq!(packs.len(), 1);
        assert!(packs[0].has_rollback);
    }

    // -- T049: Conflict resolution ----------------------------------------

    #[test]
    fn conflict_detected_between_packs() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // Install pack-a with rule "shared-rule".
        let entry_a = make_rule_entry("shared-rule", "1.0.0");
        let m_a = make_manifest("pack-a", "1.0.0", vec![entry_a.clone()]);
        let mut rules_a = HashMap::new();
        rules_a.insert(entry_a.file.clone(), b"rule a content".to_vec());
        let a_a = build_pack_archive(&m_a, &rules_a);
        let p_a = write_pack_file(tmp.path(), "pack-a.pack", &a_a);
        install_rulepack(&p_a, &store, &[]).unwrap();

        // Install pack-b with the same rule ID but newer version.
        let entry_b = make_rule_entry("shared-rule", "2.0.0");
        let m_b = make_manifest("pack-b", "1.0.0", vec![entry_b.clone()]);
        let mut rules_b = HashMap::new();
        rules_b.insert(entry_b.file.clone(), b"rule b content".to_vec());
        let a_b = build_pack_archive(&m_b, &rules_b);
        let p_b = write_pack_file(tmp.path(), "pack-b.pack", &a_b);
        let result = install_rulepack(&p_b, &store, &[]).unwrap();

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].rule_id, "shared-rule");
        assert_eq!(result.conflicts[0].existing_pack, "pack-a");
        assert_eq!(result.conflicts[0].existing_version, "1.0.0");
        assert_eq!(result.conflicts[0].new_version, "2.0.0");
    }

    #[test]
    fn no_conflict_when_no_other_packs() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let entry = make_rule_entry("unique-rule", "1.0.0");
        let manifest = make_manifest("solo-pack", "1.0.0", vec![entry.clone()]);
        let mut rules = HashMap::new();
        rules.insert(entry.file.clone(), b"content".to_vec());
        let archive = build_pack_archive(&manifest, &rules);
        let pack_path = write_pack_file(tmp.path(), "solo.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]).unwrap();
        assert!(result.conflicts.is_empty());
    }

    // -- 1A: 路徑穿越防護測試 ---------------------------------------------

    #[test]
    fn is_safe_relative_path_rejects_parent_dir() {
        assert!(!is_safe_relative_path("../../etc/passwd"));
        assert!(!is_safe_relative_path("../secret"));
        assert!(!is_safe_relative_path("rules/../../etc/shadow"));
    }

    #[test]
    fn is_safe_relative_path_rejects_absolute() {
        assert!(!is_safe_relative_path("/etc/passwd"));
        assert!(!is_safe_relative_path("/tmp/evil"));
    }

    #[test]
    fn is_safe_relative_path_rejects_empty() {
        assert!(!is_safe_relative_path(""));
    }

    #[test]
    fn is_safe_relative_path_accepts_normal() {
        assert!(is_safe_relative_path("rules/sql_injection.yaml"));
        assert!(is_safe_relative_path("a/b/c.yaml"));
        assert!(is_safe_relative_path("rule.yaml"));
    }

    #[test]
    fn install_rejects_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        // manifest 中引用含 `..` 的路徑，但 archive 中用安全名稱存放。
        // tar 不允許含 `..` 的路徑名，所以我們用安全名稱存入 archive，
        // 但 manifest 的 file 欄位指向不安全路徑。
        let mut entry = make_rule_entry("evil-rule", "1.0.0");
        entry.file = "../../.ssh/authorized_keys".to_string();
        let manifest = make_manifest("evil-pack", "1.0.0", vec![entry]);

        // archive 不含對應檔案（manifest 引用的路徑會被路徑驗證攔截）
        let archive = build_pack_archive(&manifest, &HashMap::new());
        let pack_path = write_pack_file(tmp.path(), "evil.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsafe file path"), "got: {err}");
    }

    // -- 1B: 規則檔案完整性驗證測試 -----------------------------------------

    #[test]
    fn install_rejects_missing_rule_file() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let entry = make_rule_entry("missing-rule", "1.0.0");
        let manifest = make_manifest("missing-pack", "1.0.0", vec![entry]);

        // 不放入任何 rule 檔案
        let archive = build_pack_archive(&manifest, &HashMap::new());
        let pack_path = write_pack_file(tmp.path(), "missing.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found in archive"),
            "got: {err}"
        );
    }

    #[test]
    fn install_rejects_sha256_mismatch() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let mut entry = make_rule_entry("hash-rule", "1.0.0");
        entry.sha256 = Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());

        let manifest = make_manifest("hash-pack", "1.0.0", vec![entry.clone()]);

        let mut rule_contents = HashMap::new();
        rule_contents.insert(entry.file.clone(), b"actual content".to_vec());

        let archive = build_pack_archive(&manifest, &rule_contents);
        let pack_path = write_pack_file(tmp.path(), "hash.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SHA-256 mismatch"), "got: {err}");
    }

    #[test]
    fn install_accepts_correct_sha256() {
        let tmp = TempDir::new().unwrap();
        let store = tmp.path().join("store");

        let content = b"id: hash-rule\npattern: (ident)\n";
        let hash = hex::encode(Sha256::digest(content));

        let mut entry = make_rule_entry("hash-rule", "1.0.0");
        entry.sha256 = Some(hash);

        let manifest = make_manifest("hash-ok-pack", "1.0.0", vec![entry.clone()]);

        let mut rule_contents = HashMap::new();
        rule_contents.insert(entry.file.clone(), content.to_vec());

        let archive = build_pack_archive(&manifest, &rule_contents);
        let pack_path = write_pack_file(tmp.path(), "hash-ok.pack", &archive);

        let result = install_rulepack(&pack_path, &store, &[]).unwrap();
        assert_eq!(result.rules_installed, 1);
    }
}
