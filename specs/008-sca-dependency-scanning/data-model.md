# Data Model: SCA Dependency Scanning

**Feature**: 008-sca-dependency-scanning
**Created**: 2026-02-08
**Purpose**: Define the dependency, vulnerability, and SCA finding data models, plus the database schema.

## 1. Dependency

A parsed third-party package from a lockfile.

### Rust Type

```rust
/// A third-party dependency parsed from a lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Package name (e.g., "lodash", "serde", "flask").
    pub name: String,
    /// Exact installed version (e.g., "4.17.20").
    pub version: String,
    /// Package ecosystem.
    pub ecosystem: Ecosystem,
    /// Path to the lockfile this dependency was parsed from.
    pub lockfile_path: String,
}

/// Package manager ecosystem identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Maven,
    Go,
    Pypi,
    Nuget,
}
```

### Lockfile to Ecosystem Mapping

| Lockfile | Ecosystem | Parser Module |
|----------|-----------|--------------|
| `package-lock.json` | `npm` | `lockfile::npm` |
| `Cargo.lock` | `cargo` | `lockfile::cargo` |
| `pom.xml`, `gradle.lockfile` | `maven` | `lockfile::maven` |
| `go.sum` | `go` | `lockfile::go` |
| `requirements.txt`, `Pipfile.lock` | `pypi` | `lockfile::python` |
| `packages.lock.json` | `nuget` | `lockfile::nuget` |

## 2. Vulnerability (Database Entry)

A known CVE stored in the local SQLite database.

### Rust Type

```rust
/// A known vulnerability advisory from the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE identifier (e.g., "CVE-2021-23337").
    pub cve_id: String,
    /// Affected package ecosystem.
    pub ecosystem: Ecosystem,
    /// Affected package name.
    pub package_name: String,
    /// Affected version range (semver range string, e.g., "< 4.17.21").
    pub affected_versions: String,
    /// Fixed version (if known), e.g., "4.17.21".
    pub fixed_version: Option<String>,
    /// CVSS v3 base score (0.0 – 10.0).
    pub cvss_score: Option<f64>,
    /// Derived severity.
    pub severity: Severity,
    /// Short description of the vulnerability.
    pub description: String,
    /// URL to the advisory.
    pub advisory_url: Option<String>,
    /// Date the advisory was published (ISO 8601).
    pub published_date: Option<String>,
}
```

### CVSS to Severity Mapping

| CVSS v3 Score | Atlas Severity |
|--------------|---------------|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.1 – 3.9 | Low |
| None / 0.0 | Medium (default) |

## 3. SQLite Database Schema

### Tables

```sql
CREATE TABLE advisories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,  -- 'npm', 'cargo', 'maven', 'go', 'pypi', 'nuget'
    package     TEXT NOT NULL,
    affected    TEXT NOT NULL,  -- semver range: "< 4.17.21" or ">= 1.0, < 1.5.3"
    fixed       TEXT,           -- fixed version (nullable)
    cvss        REAL,           -- CVSS v3 base score (nullable)
    severity    TEXT NOT NULL,  -- 'critical', 'high', 'medium', 'low'
    description TEXT NOT NULL,
    url         TEXT,           -- advisory URL
    published   TEXT,           -- ISO 8601 date
    UNIQUE(cve_id, ecosystem, package)
);

CREATE INDEX idx_advisories_ecosystem_package ON advisories(ecosystem, package);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- metadata rows: 'last_updated', 'advisory_count', 'schema_version'
```

### Query Pattern

```sql
-- Find vulnerabilities for a specific dependency
SELECT * FROM advisories
WHERE ecosystem = ?1
  AND package = ?2
ORDER BY cvss DESC;
```

Version range matching is performed in Rust (not SQL) after fetching all advisories for a package, using the `semver` crate to check if the installed version falls within the `affected` range.

## 4. SCA Finding

SCA findings use the standard `Finding` struct with SCA-specific metadata.

### JSON Example

```json
{
  "fingerprint": "sca-abc123...",
  "rule_id": "atlas/sca/npm/CVE-2021-23337",
  "severity": "high",
  "category": "sca",
  "cwe_id": "CWE-1321",
  "file_path": "package-lock.json",
  "line_range": {
    "start_line": 1,
    "start_col": 1,
    "end_line": 1,
    "end_col": 1
  },
  "snippet": "\"lodash\": \"4.17.20\"",
  "description": "lodash 4.17.20 is affected by CVE-2021-23337: Prototype Pollution in lodash. CVSS: 7.2 (High). Fixed in 4.17.21.",
  "remediation": "Upgrade lodash to version 4.17.21 or later.",
  "analysis_level": "L1",
  "confidence": "high",
  "metadata": {
    "cve_id": "CVE-2021-23337",
    "cvss_score": 7.2,
    "package_name": "lodash",
    "ecosystem": "npm",
    "installed_version": "4.17.20",
    "fixed_version": "4.17.21",
    "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
  }
}
```

### SARIF Example

```json
{
  "ruleId": "atlas/sca/npm/CVE-2021-23337",
  "level": "error",
  "message": {
    "text": "lodash 4.17.20 is affected by CVE-2021-23337: Prototype Pollution. Fixed in 4.17.21."
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "package-lock.json" },
      "region": { "startLine": 1 }
    }
  }],
  "properties": {
    "category": "sca",
    "cve_id": "CVE-2021-23337",
    "cvss_score": 7.2,
    "package_name": "lodash",
    "ecosystem": "npm",
    "installed_version": "4.17.20",
    "fixed_version": "4.17.21"
  }
}
```

## 5. Database Update Bundle

### Bundle Format

```
+---------------------------+
| Bundle Header (JSON)      |  { "version": 1, "advisory_count": 15000,
|                           |    "created": "2026-02-08T00:00:00Z" }
+---------------------------+
| SQLite Database (binary)  |  The complete vuln.db file
+---------------------------+
| Ed25519 Signature (64 B)  |  Signature over header + database
+---------------------------+
```

### Rust Types

```rust
/// Metadata for a vulnerability database bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleHeader {
    /// Bundle format version.
    pub version: u32,
    /// Number of advisories in the database.
    pub advisory_count: usize,
    /// When the bundle was created.
    pub created: String,
}

/// The local vulnerability database state.
pub struct VulnDatabase {
    /// Path to the SQLite database file.
    pub path: PathBuf,
    /// Database connection.
    pub conn: rusqlite::Connection,
    /// Number of advisories in the database.
    pub advisory_count: usize,
    /// When the database was last updated.
    pub last_updated: String,
}
```

### Update Verification Flow

```
atlas sca update-db ./bundle.db
  │
  ├─ Read bundle header (first N bytes)
  ├─ Read SQLite database (middle bytes)
  ├─ Read Ed25519 signature (last 64 bytes)
  │
  ├─ Verify: ed25519_verify(public_key, header + db_bytes, signature)
  │   ├─ Valid → Replace ~/.atlas/vuln.db with new database
  │   └─ Invalid → Error: "Invalid database signature"
  │
  └─ Print: "Updated vulnerability database: 15,000 advisories (2026-02-08)"
```

## 6. Lockfile Parsing Examples

### npm (package-lock.json v3)

```json
{
  "name": "my-app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    }
  }
}
```

Parsed to:
```rust
vec![
    Dependency { name: "lodash", version: "4.17.20", ecosystem: Npm, lockfile_path: "package-lock.json" },
    Dependency { name: "express", version: "4.18.2", ecosystem: Npm, lockfile_path: "package-lock.json" },
]
```

### Cargo.lock

```toml
[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.35.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
```

Parsed to:
```rust
vec![
    Dependency { name: "serde", version: "1.0.193", ecosystem: Cargo, lockfile_path: "Cargo.lock" },
    Dependency { name: "tokio", version: "1.35.1", ecosystem: Cargo, lockfile_path: "Cargo.lock" },
]
```

### requirements.txt (Python)

```
flask==2.3.2
requests==2.31.0
django==4.2.7
```

Parsed to:
```rust
vec![
    Dependency { name: "flask", version: "2.3.2", ecosystem: Pypi, lockfile_path: "requirements.txt" },
    Dependency { name: "requests", version: "2.31.0", ecosystem: Pypi, lockfile_path: "requirements.txt" },
    Dependency { name: "django", version: "4.2.7", ecosystem: Pypi, lockfile_path: "requirements.txt" },
]
```

## 7. Scan Pipeline Integration

```
atlas scan ./project
  │
  ├─ File Discovery
  │   ├─ Source files → SAST (L1/L2/L3)
  │   └─ Lockfiles → SCA
  │       ├─ package-lock.json → npm parser
  │       ├─ Cargo.lock → cargo parser
  │       ├─ requirements.txt → python parser
  │       └─ ...
  │
  ├─ SCA Analysis
  │   ├─ Parse lockfiles → Vec<Dependency>
  │   ├─ For each dependency:
  │   │   └─ Query vuln.db → Vec<Vulnerability>
  │   ├─ For each matched vulnerability:
  │   │   └─ Build SCA Finding
  │   └─ Collect all SCA findings
  │
  ├─ Merge SAST + SCA findings
  │
  ├─ Gate Evaluation (category_overrides.sca)
  │
  └─ Report Output (JSON/SARIF/JSONL)
```
