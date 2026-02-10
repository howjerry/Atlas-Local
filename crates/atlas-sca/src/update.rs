//! 漏洞資料庫更新機制 — Ed25519 簽章驗證與原子替換。

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::ScaError;

// ---------------------------------------------------------------------------
// Bundle 格式
// ---------------------------------------------------------------------------

/// 資料庫 bundle 由兩個檔案組成：
/// - `vuln.db`: SQLite 資料庫
/// - `vuln.db.sig`: JSON 格式的簽章 metadata
///
/// 簽章 metadata 格式：
/// ```json
/// {
///   "sha256": "hex-encoded hash of vuln.db",
///   "signature": "base64-encoded Ed25519 signature of the SHA-256 hash",
///   "public_key": "base64-encoded Ed25519 public key"
/// }
/// ```
/// 簽章 metadata 結構。
#[derive(serde::Deserialize)]
struct BundleSignature {
    sha256: String,
    signature: String,
    public_key: String,
}

// ---------------------------------------------------------------------------
// update_database
// ---------------------------------------------------------------------------

/// 驗證 bundle 的 Ed25519 簽章，然後原子替換本地資料庫。
///
/// # 流程
///
/// 1. 讀取 bundle 檔案（SQLite 資料庫）
/// 2. 讀取對應的 `.sig` 簽章檔案
/// 3. 計算 bundle 的 SHA-256 hash
/// 4. 驗證 Ed25519 簽章
/// 5. 寫入暫時檔案，然後 rename 到目標路徑
pub fn update_database(
    bundle_path: &Path,
    target_path: &Path,
) -> Result<(), ScaError> {
    // 1. 讀取 bundle
    let db_bytes = fs::read(bundle_path)?;

    // 2. 讀取簽章檔案
    let sig_path = bundle_path.with_extension("sig");
    let sig_content = fs::read_to_string(&sig_path).map_err(|e| {
        ScaError::SignatureInvalid(format!(
            "無法讀取簽章檔案 {}: {}",
            sig_path.display(),
            e
        ))
    })?;

    let sig_meta: BundleSignature =
        serde_json::from_str(&sig_content).map_err(|e| {
            ScaError::SignatureInvalid(format!("簽章 metadata 格式錯誤: {}", e))
        })?;

    // 3. 計算 SHA-256
    let hash = Sha256::digest(&db_bytes);
    let hash_hex = hex::encode(hash);

    if hash_hex != sig_meta.sha256 {
        return Err(ScaError::SignatureInvalid(format!(
            "SHA-256 不符: 預期 {}, 實際 {}",
            sig_meta.sha256, hash_hex
        )));
    }

    // 4. Ed25519 簽章驗證
    verify_ed25519(
        &hash,
        &sig_meta.signature,
        &sig_meta.public_key,
    )?;

    // 5. 原子替換：寫入暫時檔案再 rename
    let parent = target_path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    let temp_path = target_path.with_extension("db.tmp");
    fs::write(&temp_path, &db_bytes)?;
    fs::rename(&temp_path, target_path)?;

    Ok(())
}

/// 驗證 Ed25519 簽章。
fn verify_ed25519(
    message: &[u8],
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), ScaError> {
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signature_b64,
    )
    .map_err(|e| ScaError::SignatureInvalid(format!("簽章 base64 解碼失敗: {}", e)))?;

    let key_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_key_b64,
    )
    .map_err(|e| ScaError::SignatureInvalid(format!("公鑰 base64 解碼失敗: {}", e)))?;

    let public_key = VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ScaError::SignatureInvalid("公鑰長度不正確".to_string()))?,
    )
    .map_err(|e| ScaError::SignatureInvalid(format!("公鑰無效: {}", e)))?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ScaError::SignatureInvalid("簽章長度不正確".to_string()))?,
    );

    public_key
        .verify(message, &signature)
        .map_err(|_| ScaError::SignatureInvalid("Invalid database signature".to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// 建立一個有效的簽章 bundle 用於測試。
    fn create_signed_bundle(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let bundle_path = dir.join("vuln.db");
        let sig_path = dir.join("vuln.sig");
        let db_content = b"test database content";

        // 計算 hash
        let hash = Sha256::digest(db_content);
        let hash_hex = hex::encode(&hash);

        // 產生 key pair 並簽署
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = signing_key.sign(&hash);
        let public_key = signing_key.verifying_key();

        use base64::Engine as _;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());

        // 寫入檔案
        fs::write(&bundle_path, db_content).unwrap();
        let sig_meta = format!(
            r#"{{"sha256":"{}","signature":"{}","public_key":"{}"}}"#,
            hash_hex, sig_b64, key_b64
        );
        fs::write(&sig_path, sig_meta).unwrap();

        (bundle_path, sig_path)
    }

    #[test]
    fn valid_signature_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, _) = create_signed_bundle(dir.path());
        let target = dir.path().join("installed.db");

        // 因為 .sig 路徑是 bundle_path.with_extension("sig")
        // 而我們的 bundle_path 是 vuln.db → vuln.sig
        let result = update_database(&bundle_path, &target);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        assert!(target.exists());
    }

    #[test]
    fn tampered_bundle_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, _) = create_signed_bundle(dir.path());
        let target = dir.path().join("installed.db");

        // 篡改 bundle 內容
        fs::write(&bundle_path, b"tampered content").unwrap();

        let result = update_database(&bundle_path, &target);
        assert!(result.is_err());
        assert!(!target.exists());
    }

    #[test]
    fn missing_signature_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("vuln.db");
        let target = dir.path().join("installed.db");

        fs::write(&bundle_path, b"content").unwrap();
        // 不建立 .sig 檔案

        let result = update_database(&bundle_path, &target);
        assert!(result.is_err());
    }
}
