//! Atlas Cache — result caching with SQLite storage.
//!
//! Provides a SQLite-backed cache with LRU eviction, self-invalidation on
//! engine/rule version changes, and corruption detection with automatic recovery.

pub mod cache;

// ---------------------------------------------------------------------------
// CacheError
// ---------------------------------------------------------------------------

/// Error type for cache operations.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("database error: {0}")]
    Database(String),

    #[error("cache database corrupt: {0}")]
    Corrupt(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}
