//! 離線 SQLite 漏洞資料庫 — 儲存與查詢 CVE advisories。

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection};

use crate::{Advisory, Dependency, Ecosystem, ScaError};

// ---------------------------------------------------------------------------
// VulnDatabase
// ---------------------------------------------------------------------------

/// 離線漏洞資料庫，基於 SQLite。
pub struct VulnDatabase {
    conn: Connection,
}

/// 資料庫 metadata。
#[derive(Debug, Clone)]
pub struct DatabaseMetadata {
    /// Advisory 總數。
    pub advisory_count: u64,
    /// 最後更新時間（ISO 8601）。
    pub last_updated: Option<String>,
}

impl VulnDatabase {
    /// 開啟既有的漏洞資料庫。
    pub fn open(path: &Path) -> Result<Self, ScaError> {
        let conn = Connection::open(path).map_err(|e| ScaError::Database(e.to_string()))?;
        Ok(Self { conn })
    }

    /// 建立新的漏洞資料庫（含 schema）。
    pub fn create(path: &Path) -> Result<Self, ScaError> {
        let conn = Connection::open(path).map_err(|e| ScaError::Database(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS advisories (
                id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                affected_range TEXT NOT NULL,
                fixed_version TEXT,
                cvss_score REAL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                advisory_url TEXT,
                published_at TEXT,
                PRIMARY KEY (id, ecosystem, package_name)
            );
            CREATE INDEX IF NOT EXISTS idx_ecosystem_package
                ON advisories (ecosystem, package_name);
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )
        .map_err(|e| ScaError::Database(e.to_string()))?;
        Ok(Self { conn })
    }

    /// 查詢指定生態系和套件名稱的所有 advisories。
    pub fn query_advisories(
        &self,
        ecosystem: Ecosystem,
        package_name: &str,
    ) -> Result<Vec<Advisory>, ScaError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ecosystem, package_name, affected_range, fixed_version,
                        cvss_score, severity, description, advisory_url
                 FROM advisories
                 WHERE ecosystem = ?1 AND package_name = ?2",
            )
            .map_err(|e| ScaError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![ecosystem.to_string(), package_name], |row| {
                Ok(Advisory {
                    id: row.get(0)?,
                    ecosystem: parse_ecosystem(&row.get::<_, String>(1)?),
                    package_name: row.get(2)?,
                    affected_range: row.get(3)?,
                    fixed_version: row.get(4)?,
                    cvss_score: row.get(5)?,
                    severity: row.get(6)?,
                    description: row.get(7)?,
                    advisory_url: row.get(8)?,
                })
            })
            .map_err(|e| ScaError::Database(e.to_string()))?;

        let mut advisories = Vec::new();
        for row in rows {
            advisories.push(row.map_err(|e| ScaError::Database(e.to_string()))?);
        }

        Ok(advisories)
    }

    /// 批次查詢多個依賴的 advisories。
    ///
    /// 回傳以 (ecosystem, package_name) 為 key 的 map。
    pub fn query_batch(
        &self,
        deps: &[Dependency],
    ) -> Result<HashMap<(Ecosystem, String), Vec<Advisory>>, ScaError> {
        let mut result: HashMap<(Ecosystem, String), Vec<Advisory>> = HashMap::new();

        // 收集需要查詢的 unique (ecosystem, package_name) 組合
        let mut queries: HashMap<(Ecosystem, String), ()> = HashMap::new();
        for dep in deps {
            queries.insert((dep.ecosystem, dep.name.clone()), ());
        }

        for (ecosystem, package_name) in queries.keys() {
            let advisories = self.query_advisories(*ecosystem, package_name)?;
            if !advisories.is_empty() {
                result.insert((*ecosystem, package_name.clone()), advisories);
            }
        }

        Ok(result)
    }

    /// 查詢資料庫 metadata。
    pub fn metadata(&self) -> Result<DatabaseMetadata, ScaError> {
        let advisory_count: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM advisories", [], |row| row.get::<_, i64>(0).map(|v| v as u64))
            .map_err(|e| ScaError::Database(e.to_string()))?;

        let last_updated: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'last_updated'",
                [],
                |row| row.get(0),
            )
            .ok();

        Ok(DatabaseMetadata {
            advisory_count,
            last_updated,
        })
    }

    /// 插入一筆 advisory（用於測試和資料庫建構）。
    pub fn insert_advisory(&self, advisory: &Advisory) -> Result<(), ScaError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO advisories
                 (id, ecosystem, package_name, affected_range, fixed_version,
                  cvss_score, severity, description, advisory_url)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    advisory.id,
                    advisory.ecosystem.to_string(),
                    advisory.package_name,
                    advisory.affected_range,
                    advisory.fixed_version,
                    advisory.cvss_score,
                    advisory.severity,
                    advisory.description,
                    advisory.advisory_url,
                ],
            )
            .map_err(|e| ScaError::Database(e.to_string()))?;
        Ok(())
    }

    /// 檢查資料庫是否超過指定天數未更新。
    ///
    /// 若 `last_updated` 不存在或格式無法解析，視為過期。
    pub fn is_stale(&self, max_age_days: u32) -> bool {
        let Ok(meta) = self.metadata() else {
            return true;
        };
        let Some(ref updated) = meta.last_updated else {
            return true;
        };
        // 支援 ISO 8601 格式：「2026-02-10T00:00:00Z」或「2026-02-10」
        let date_str = updated.split('T').next().unwrap_or(updated);
        let Ok(updated_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") else {
            return true;
        };
        let today = chrono::Utc::now().date_naive();
        let age = today.signed_duration_since(updated_date).num_days();
        age > i64::from(max_age_days)
    }

    /// 設定 metadata。
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), ScaError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| ScaError::Database(e.to_string()))?;
        Ok(())
    }
}

/// 將字串轉為 Ecosystem enum。
fn parse_ecosystem(s: &str) -> Ecosystem {
    match s {
        "npm" => Ecosystem::Npm,
        "cargo" => Ecosystem::Cargo,
        "maven" => Ecosystem::Maven,
        "go" => Ecosystem::Go,
        "pypi" => Ecosystem::PyPI,
        "nuget" => Ecosystem::NuGet,
        _ => Ecosystem::Npm, // fallback
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_advisory() -> Advisory {
        Advisory {
            id: "CVE-2021-23337".to_string(),
            ecosystem: Ecosystem::Npm,
            package_name: "lodash".to_string(),
            affected_range: "< 4.17.21".to_string(),
            fixed_version: Some("4.17.21".to_string()),
            cvss_score: Some(7.2),
            severity: "high".to_string(),
            description: "Prototype pollution in lodash".to_string(),
            advisory_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()),
        }
    }

    #[test]
    fn create_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = VulnDatabase::create(&db_path).unwrap();
        db.insert_advisory(&test_advisory()).unwrap();

        let results = db.query_advisories(Ecosystem::Npm, "lodash").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "CVE-2021-23337");
        assert_eq!(results[0].cvss_score, Some(7.2));
    }

    #[test]
    fn query_nonexistent_package() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = VulnDatabase::create(&db_path).unwrap();
        let results = db.query_advisories(Ecosystem::Npm, "nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn batch_query() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = VulnDatabase::create(&db_path).unwrap();
        db.insert_advisory(&test_advisory()).unwrap();

        let deps = vec![
            Dependency {
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                ecosystem: Ecosystem::Npm,
                lockfile_path: "package-lock.json".to_string(),
                line: 0,
            },
            Dependency {
                name: "express".to_string(),
                version: "4.18.2".to_string(),
                ecosystem: Ecosystem::Npm,
                lockfile_path: "package-lock.json".to_string(),
                line: 0,
            },
        ];

        let result = db.query_batch(&deps).unwrap();
        assert_eq!(result.len(), 1); // 只有 lodash 有 advisory
        assert!(result.contains_key(&(Ecosystem::Npm, "lodash".to_string())));
    }

    #[test]
    fn metadata_operations() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = VulnDatabase::create(&db_path).unwrap();
        db.insert_advisory(&test_advisory()).unwrap();
        db.set_metadata("last_updated", "2026-02-10T00:00:00Z")
            .unwrap();

        let meta = db.metadata().unwrap();
        assert_eq!(meta.advisory_count, 1);
        assert_eq!(
            meta.last_updated,
            Some("2026-02-10T00:00:00Z".to_string())
        );
    }

    #[test]
    fn empty_database_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let db = VulnDatabase::create(&db_path).unwrap();
        let meta = db.metadata().unwrap();
        assert_eq!(meta.advisory_count, 0);
        assert_eq!(meta.last_updated, None);
    }

    #[test]
    fn is_stale_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let db = VulnDatabase::create(&dir.path().join("test.db")).unwrap();
        // 無 last_updated metadata → 視為過期
        assert!(db.is_stale(30));
    }

    #[test]
    fn is_stale_recent_update() {
        let dir = tempfile::tempdir().unwrap();
        let db = VulnDatabase::create(&dir.path().join("test.db")).unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        db.set_metadata("last_updated", &today).unwrap();
        // 今天更新 → 不過期
        assert!(!db.is_stale(30));
    }

    #[test]
    fn is_stale_old_update() {
        let dir = tempfile::tempdir().unwrap();
        let db = VulnDatabase::create(&dir.path().join("test.db")).unwrap();
        // 設定 60 天前的日期
        let old_date = (chrono::Utc::now() - chrono::Duration::days(60))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        db.set_metadata("last_updated", &old_date).unwrap();
        assert!(db.is_stale(30));
    }
}
