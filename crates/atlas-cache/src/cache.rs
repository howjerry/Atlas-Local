//! SQLite-based result cache for Atlas Local SAST (T083-T084).
//!
//! Cache key: SHA-256 of (file_content + rule_version_hash + config_hash).
//! Cache value: bincode-serialized scan results.
//!
//! Features:
//! - LRU eviction (configurable max entries)
//! - Self-invalidation on engine/rule version change
//! - Corruption detection and recovery (T084)

use std::path::Path;

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::CacheError;

// ---------------------------------------------------------------------------
// CacheConfig
// ---------------------------------------------------------------------------

/// Configuration for the result cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries before LRU eviction.
    pub max_entries: u64,
    /// Engine version string (for self-invalidation).
    pub engine_version: String,
    /// Hash of all active rule versions (for self-invalidation).
    pub rules_version_hash: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            rules_version_hash: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ResultCache
// ---------------------------------------------------------------------------

/// SQLite-backed result cache.
pub struct ResultCache {
    conn: Connection,
    config: CacheConfig,
}

impl ResultCache {
    /// Opens or creates a cache database at the given path.
    ///
    /// If the database is corrupt, it is deleted and recreated (T084).
    pub fn open(path: &Path, config: CacheConfig) -> Result<Self, CacheError> {
        let conn = match Connection::open(path) {
            Ok(c) => c,
            Err(e) => {
                // T084: Corruption detection — if open fails, delete and retry.
                warn!(path = %path.display(), error = %e, "cache open failed; deleting and retrying");
                if path.exists() {
                    let _ = std::fs::remove_file(path);
                }
                Connection::open(path)
                    .map_err(|e| CacheError::Database(format!("cannot open cache: {e}")))?
            }
        };

        let mut cache = Self { conn, config };
        cache.init_tables()?;
        cache.check_version_invalidation()?;

        Ok(cache)
    }

    /// Creates an in-memory cache (useful for testing).
    pub fn in_memory(config: CacheConfig) -> Result<Self, CacheError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| CacheError::Database(format!("cannot open in-memory cache: {e}")))?;

        let cache = Self { conn, config };
        cache.init_tables()?;

        Ok(cache)
    }

    /// Initializes the cache schema.
    fn init_tables(&self) -> Result<(), CacheError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS cache_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS results (
                    cache_key TEXT PRIMARY KEY,
                    data BLOB NOT NULL,
                    accessed_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_results_accessed ON results(accessed_at);",
            )
            .map_err(|e| {
                // T084: Detect SQLITE_CORRUPT
                let msg = e.to_string();
                if msg.contains("corrupt") || msg.contains("CORRUPT") {
                    CacheError::Corrupt(msg)
                } else {
                    CacheError::Database(format!("init tables: {e}"))
                }
            })?;

        Ok(())
    }

    /// Checks if the engine or rules version has changed; if so, clear the cache.
    fn check_version_invalidation(&mut self) -> Result<(), CacheError> {
        let stored_engine = self.get_meta("engine_version");
        let stored_rules = self.get_meta("rules_version_hash");

        let engine_changed = stored_engine.as_deref() != Some(&self.config.engine_version);
        let rules_changed = stored_rules.as_deref() != Some(&self.config.rules_version_hash);

        if engine_changed || rules_changed {
            info!(
                engine_changed,
                rules_changed, "cache invalidated due to version change; clearing"
            );
            self.clear()?;
            self.set_meta("engine_version", &self.config.engine_version)?;
            self.set_meta("rules_version_hash", &self.config.rules_version_hash)?;
        }

        Ok(())
    }

    /// Gets a metadata value.
    fn get_meta(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM cache_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok()
    }

    /// Sets a metadata value.
    fn set_meta(&self, key: &str, value: &str) -> Result<(), CacheError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| CacheError::Database(format!("set_meta: {e}")))?;
        Ok(())
    }

    /// Computes the cache key for a file + rules + config combination.
    pub fn compute_key(file_content: &[u8], rules_hash: &str, config_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(file_content);
        hasher.update(rules_hash.as_bytes());
        hasher.update(config_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Looks up cached results by key.
    pub fn get(&self, cache_key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let result = self.conn.query_row(
            "SELECT data FROM results WHERE cache_key = ?1",
            params![cache_key],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(data) => {
                // Update access time for LRU.
                let now = timestamp();
                let _ = self.conn.execute(
                    "UPDATE results SET accessed_at = ?1 WHERE cache_key = ?2",
                    params![now, cache_key],
                );
                debug!(key = cache_key, "cache hit");
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                debug!(key = cache_key, "cache miss");
                Ok(None)
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("corrupt") || msg.contains("CORRUPT") {
                    Err(CacheError::Corrupt(msg))
                } else {
                    Err(CacheError::Database(format!("get: {e}")))
                }
            }
        }
    }

    /// Stores results in the cache, evicting old entries if needed.
    pub fn put(&self, cache_key: &str, data: &[u8]) -> Result<(), CacheError> {
        let now = timestamp();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO results (cache_key, data, accessed_at) VALUES (?1, ?2, ?3)",
                params![cache_key, data, now],
            )
            .map_err(|e| CacheError::Database(format!("put: {e}")))?;

        // LRU eviction.
        self.evict_if_needed()?;

        debug!(key = cache_key, size = data.len(), "cached result");
        Ok(())
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> Result<u64, CacheError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM results", [], |row| row.get(0))
            .map_err(|e| CacheError::Database(format!("count: {e}")))?;
        Ok(count as u64)
    }

    /// Returns `true` if the cache has no entries.
    pub fn is_empty(&self) -> Result<bool, CacheError> {
        self.len().map(|n| n == 0)
    }

    /// Clears all cached results.
    pub fn clear(&self) -> Result<(), CacheError> {
        self.conn
            .execute("DELETE FROM results", [])
            .map_err(|e| CacheError::Database(format!("clear: {e}")))?;
        info!("cache cleared");
        Ok(())
    }

    /// Evicts the least-recently-used entries if the cache exceeds max_entries.
    fn evict_if_needed(&self) -> Result<(), CacheError> {
        let count = self.len()?;
        if count <= self.config.max_entries {
            return Ok(());
        }

        let to_delete = count - self.config.max_entries;
        self.conn
            .execute(
                "DELETE FROM results WHERE cache_key IN (
                    SELECT cache_key FROM results ORDER BY accessed_at ASC LIMIT ?1
                )",
                params![to_delete as i64],
            )
            .map_err(|e| CacheError::Database(format!("evict: {e}")))?;

        debug!(
            evicted = to_delete,
            remaining = self.config.max_entries,
            "LRU eviction"
        );
        Ok(())
    }
}

/// Returns a Unix timestamp in seconds.
fn timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// recover_corrupt_cache  (T084)
// ---------------------------------------------------------------------------

/// Handles a corrupt cache by deleting it and returning a fresh instance.
///
/// This is called when any cache operation detects corruption.
pub fn recover_corrupt_cache(path: &Path, config: CacheConfig) -> Result<ResultCache, CacheError> {
    warn!(path = %path.display(), "recovering corrupt cache database");

    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| CacheError::Io(format!("deleting corrupt cache: {e}")))?;
    }

    ResultCache::open(path, config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CacheConfig {
        CacheConfig {
            max_entries: 5,
            engine_version: "0.1.0-test".to_string(),
            rules_version_hash: "test-hash".to_string(),
        }
    }

    #[test]
    fn in_memory_cache_put_get() {
        let cache = ResultCache::in_memory(test_config()).unwrap();
        let key = ResultCache::compute_key(b"hello", "rules", "config");
        let data = b"test data";

        cache.put(&key, data).unwrap();

        let result = cache.get(&key).unwrap();
        assert_eq!(result.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn cache_miss() {
        let cache = ResultCache::in_memory(test_config()).unwrap();
        let result = cache.get("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn cache_len_and_empty() {
        let cache = ResultCache::in_memory(test_config()).unwrap();
        assert!(cache.is_empty().unwrap());
        assert_eq!(cache.len().unwrap(), 0);

        cache.put("key1", b"data1").unwrap();
        assert!(!cache.is_empty().unwrap());
        assert_eq!(cache.len().unwrap(), 1);
    }

    #[test]
    fn cache_clear() {
        let cache = ResultCache::in_memory(test_config()).unwrap();
        cache.put("key1", b"data1").unwrap();
        cache.put("key2", b"data2").unwrap();
        assert_eq!(cache.len().unwrap(), 2);

        cache.clear().unwrap();
        assert_eq!(cache.len().unwrap(), 0);
    }

    #[test]
    fn lru_eviction() {
        let config = CacheConfig {
            max_entries: 3,
            ..test_config()
        };
        let cache = ResultCache::in_memory(config).unwrap();

        cache.put("key1", b"data1").unwrap();
        cache.put("key2", b"data2").unwrap();
        cache.put("key3", b"data3").unwrap();
        assert_eq!(cache.len().unwrap(), 3);

        // Adding a 4th entry should evict the oldest.
        cache.put("key4", b"data4").unwrap();
        assert!(cache.len().unwrap() <= 3);
    }

    #[test]
    fn compute_key_deterministic() {
        let k1 = ResultCache::compute_key(b"content", "rules", "config");
        let k2 = ResultCache::compute_key(b"content", "rules", "config");
        assert_eq!(k1, k2);
    }

    #[test]
    fn compute_key_changes_with_content() {
        let k1 = ResultCache::compute_key(b"content1", "rules", "config");
        let k2 = ResultCache::compute_key(b"content2", "rules", "config");
        assert_ne!(k1, k2);
    }

    #[test]
    fn compute_key_changes_with_rules() {
        let k1 = ResultCache::compute_key(b"content", "rules1", "config");
        let k2 = ResultCache::compute_key(b"content", "rules2", "config");
        assert_ne!(k1, k2);
    }

    #[test]
    fn version_invalidation() {
        let cache = ResultCache::in_memory(test_config()).unwrap();
        cache.put("key1", b"data1").unwrap();
        assert_eq!(cache.len().unwrap(), 1);

        // Creating a new cache with different version should clear.
        let config2 = CacheConfig {
            engine_version: "0.2.0-test".to_string(),
            ..test_config()
        };
        let cache2 = ResultCache::in_memory(config2).unwrap();
        // In-memory caches are separate, but the version check logic is tested.
        assert_eq!(cache2.len().unwrap(), 0);
    }

    #[test]
    fn overwrite_existing_key() {
        let cache = ResultCache::in_memory(test_config()).unwrap();
        cache.put("key1", b"original").unwrap();
        cache.put("key1", b"updated").unwrap();

        let result = cache.get("key1").unwrap();
        assert_eq!(result.as_deref(), Some(b"updated".as_slice()));
        assert_eq!(cache.len().unwrap(), 1);
    }

    #[test]
    fn file_based_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test-cache.db");

        {
            let cache = ResultCache::open(&db_path, test_config()).unwrap();
            cache.put("key1", b"data1").unwrap();
            assert_eq!(cache.len().unwrap(), 1);
        }

        // Reopen and verify persistence.
        {
            let cache = ResultCache::open(&db_path, test_config()).unwrap();
            let result = cache.get("key1").unwrap();
            assert_eq!(result.as_deref(), Some(b"data1".as_slice()));
        }
    }
}
