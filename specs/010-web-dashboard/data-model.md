# Data Model: Web Dashboard

**Feature**: 010-web-dashboard
**Created**: 2026-02-08
**Purpose**: Define the dashboard database schema, import model, and view data structures.

## 1. Dashboard Database Schema

### Entity Relationship

```
┌─────────────┐      ┌────────────────┐      ┌──────────────────┐
│  projects    │ 1──N │    scans       │ 1──N │   findings       │
│             │      │                │      │                  │
│ name (PK)   │      │ id (PK)        │      │ id (PK)          │
│ first_scan  │      │ project_name   │──FK  │ scan_id          │──FK
│ latest_scan │      │ scan_date      │      │ fingerprint      │
│ scan_count  │      │ total_findings │      │ rule_id          │
└─────────────┘      │ *_count        │      │ severity         │
                     │ gate_result    │      │ category         │
                     │ report_hash    │      │ file_path        │
                     └────────────────┘      │ start_line       │
                                             │ description      │
                                             │ metadata_json    │
                                             └──────────────────┘
```

### SQL Schema

```sql
CREATE TABLE projects (
    name TEXT PRIMARY KEY,
    first_scan_date TEXT NOT NULL,
    latest_scan_date TEXT NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL REFERENCES projects(name),
    scan_date TEXT NOT NULL,
    total_findings INTEGER NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    gate_result TEXT,
    report_hash TEXT NOT NULL UNIQUE,
    imported_at TEXT NOT NULL
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    snippet TEXT,
    description TEXT NOT NULL,
    remediation TEXT,
    confidence TEXT,
    analysis_level TEXT,
    metadata_json TEXT
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_scans_project ON scans(project_name);
```

## 2. Rust Types

### Project

```rust
/// A project in the dashboard (grouping of scans).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Project name (derived from scan metadata).
    pub name: String,
    /// Date of the first scan imported.
    pub first_scan_date: String,
    /// Date of the most recent scan.
    pub latest_scan_date: String,
    /// Total number of scans imported.
    pub scan_count: usize,
    /// Finding count trend direction.
    pub trend: TrendDirection,
    /// Latest scan summary.
    pub latest_summary: ScanSummary,
}

/// Direction of finding count change between recent scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrendDirection {
    /// Finding count is decreasing.
    Improving,
    /// Finding count is increasing.
    Worsening,
    /// Finding count is unchanged.
    Stable,
    /// Not enough data (fewer than 2 scans).
    Insufficient,
}
```

### Scan Record

```rust
/// A stored scan record in the dashboard database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    /// Database auto-increment ID.
    pub id: i64,
    /// Project name.
    pub project_name: String,
    /// Scan timestamp.
    pub scan_date: String,
    /// Total finding count.
    pub total_findings: usize,
    /// Finding counts by severity.
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    /// Gate result: PASS, FAIL, or WARN.
    pub gate_result: Option<String>,
    /// SHA-256 hash of the report file (deduplication key).
    pub report_hash: String,
    /// When the report was imported.
    pub imported_at: String,
}

/// Summary statistics for a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub gate_result: Option<String>,
}
```

### Dashboard Finding

```rust
/// A finding stored in the dashboard database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardFinding {
    /// Database auto-increment ID.
    pub id: i64,
    /// Reference to the scan this finding belongs to.
    pub scan_id: i64,
    /// Stable fingerprint for cross-scan matching.
    pub fingerprint: String,
    /// Rule identifier.
    pub rule_id: String,
    /// Severity level.
    pub severity: String,
    /// Category (security, quality, sca, iac, metrics).
    pub category: String,
    /// File path.
    pub file_path: String,
    /// Start line number.
    pub start_line: usize,
    /// End line number.
    pub end_line: usize,
    /// Code snippet.
    pub snippet: Option<String>,
    /// Finding description.
    pub description: String,
    /// Remediation guidance.
    pub remediation: Option<String>,
    /// Confidence level.
    pub confidence: Option<String>,
    /// Analysis level (L1, L2, L3).
    pub analysis_level: Option<String>,
    /// All metadata as a JSON string.
    pub metadata_json: Option<String>,
}
```

## 3. Import Model

### Report Import Flow

```
JSON Report File
  │
  ├─ Read file content
  ├─ Compute SHA-256 hash
  │   └─ Check: hash exists in scans.report_hash?
  │       ├─ Yes → Skip (already imported)
  │       └─ No → Continue import
  │
  ├─ Parse JSON → Atlas Report struct
  │   ├─ scan_metadata → project_name, scan_date
  │   ├─ findings[] → DashboardFinding rows
  │   └─ gate_result → gate_result string
  │
  ├─ Upsert into projects table
  ├─ Insert into scans table
  └─ Insert into findings table (batch)
```

### Import Rust Type

```rust
/// Represents a report file to be imported.
pub struct ReportImport {
    /// Path to the JSON report file.
    pub file_path: PathBuf,
    /// SHA-256 hash of the file contents.
    pub file_hash: String,
    /// Parsed report data.
    pub report: AtlasReport,
}

/// Parsed Atlas report (matches the JSON output format).
pub struct AtlasReport {
    pub scan_metadata: ScanMetadata,
    pub findings: Vec<Finding>,
    pub gate_result: Option<GateResult>,
}

pub struct ScanMetadata {
    pub project_root: String,
    pub timestamp: String,
    pub scanned_files: usize,
    pub total_rules: usize,
}
```

## 4. View Data Models

### Project List View

```rust
/// Data for the project list page.
pub struct ProjectListView {
    pub projects: Vec<ProjectRow>,
    pub total_projects: usize,
}

pub struct ProjectRow {
    pub name: String,
    pub latest_scan_date: String,
    pub scan_count: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub gate_result: Option<String>,
    pub trend: TrendDirection,
}
```

### Scan Detail View (Finding List)

```rust
/// Data for the scan detail / finding list page.
pub struct ScanDetailView {
    pub scan: ScanRecord,
    pub findings: Vec<DashboardFinding>,
    pub total_findings: usize,
    pub page: usize,
    pub total_pages: usize,
    pub filters: FindingFilters,
}

/// Active filters on the finding list.
pub struct FindingFilters {
    pub severity: Option<String>,
    pub category: Option<String>,
    pub file_path: Option<String>,
    pub search: Option<String>,
}
```

### Trend View

```rust
/// Data for the trend chart page.
pub struct TrendView {
    pub project_name: String,
    pub data_points: Vec<TrendDataPoint>,
}

/// A single data point in the trend chart.
pub struct TrendDataPoint {
    pub scan_date: String,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}
```

### Scan Comparison View

```rust
/// Data for the scan comparison page.
pub struct ComparisonView {
    pub scan_a: ScanRecord,
    pub scan_b: ScanRecord,
    pub new_findings: Vec<DashboardFinding>,
    pub resolved_findings: Vec<DashboardFinding>,
    pub unchanged_findings: Vec<DashboardFinding>,
    pub summary: ComparisonSummary,
}

pub struct ComparisonSummary {
    pub new_count: usize,
    pub resolved_count: usize,
    pub unchanged_count: usize,
    pub net_change: i64,  // positive = more findings, negative = fewer
}
```

### Comparison Algorithm

```
function compare_scans(scan_a, scan_b):
    fingerprints_a = set(f.fingerprint for f in scan_a.findings)
    fingerprints_b = set(f.fingerprint for f in scan_b.findings)

    new_findings = fingerprints_b - fingerprints_a       // In B but not A
    resolved_findings = fingerprints_a - fingerprints_b   // In A but not B
    unchanged_findings = fingerprints_a & fingerprints_b  // In both

    return ComparisonView {
        new: findings from scan_b where fingerprint in new_findings,
        resolved: findings from scan_a where fingerprint in resolved_findings,
        unchanged: findings from scan_b where fingerprint in unchanged_findings,
    }
```

## 5. CLI Interface

```
atlas dashboard [OPTIONS]

Options:
    --port <PORT>           HTTP server port [default: 8080]
    --data-dir <DIR>        Directory containing Atlas JSON reports [default: ./reports/]
    --db-path <PATH>        SQLite database path [default: {data-dir}/atlas-dashboard.db]
    --auth <USER:PASSWORD>  Enable HTTP Basic Authentication
    --open                  Open dashboard in default browser after starting
```

## 6. Dashboard Configuration

### Rust Type

```rust
/// Configuration for the dashboard server.
pub struct DashboardConfig {
    /// HTTP port to listen on.
    pub port: u16,
    /// Directory containing Atlas JSON report files.
    pub data_dir: PathBuf,
    /// Path to the SQLite database file.
    pub db_path: PathBuf,
    /// Optional basic auth credentials.
    pub auth: Option<AuthConfig>,
    /// Whether to open the browser automatically.
    pub open_browser: bool,
}

pub struct AuthConfig {
    pub username: String,
    /// bcrypt hash of the password.
    pub password_hash: String,
}
```

## 7. htmx Interaction Model

### Page Flow

```
┌──────────────┐    GET /              ┌──────────────┐
│              │ ──────────────────→   │              │
│   Browser    │    GET /projects      │   axum       │
│   (htmx)    │ ──────────────────→   │   server     │
│              │    HTML fragment      │              │
│              │ ←──────────────────   │    ↕ SQLite  │
│              │                       │              │
│              │    GET /scans/5       │              │
│              │ ──────────────────→   │              │
│              │    HTML fragment      │              │
│              │ ←──────────────────   │              │
└──────────────┘                       └──────────────┘
```

### htmx Attributes Used

| Attribute | Usage |
|-----------|-------|
| `hx-get` | Load finding list, scan detail, trend data |
| `hx-target` | Replace content area without full page reload |
| `hx-trigger` | Filter changes, pagination clicks |
| `hx-swap` | innerHTML for content updates |
| `hx-push-url` | Update browser URL for back-button support |
| `hx-indicator` | Loading spinner during AJAX requests |

### Example Template (finding list)

```html
<!-- templates/scan_detail.html -->
<div id="findings-container">
  <div class="filters">
    <select name="severity" hx-get="/scans/{{ scan_id }}/findings"
            hx-target="#findings-list" hx-trigger="change">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
    </select>
  </div>

  <div id="findings-list" hx-get="/scans/{{ scan_id }}/findings"
       hx-trigger="load" hx-indicator="#spinner">
    <!-- Replaced by htmx with finding rows -->
  </div>

  <div id="spinner" class="htmx-indicator">Loading...</div>
</div>
```

## 8. Trend Chart Data API

### Endpoint

```
GET /api/trends/{project_name}?period=30d
```

### Response (JSON for Chart.js)

```json
{
  "labels": ["2026-01-10", "2026-01-17", "2026-01-24", "2026-01-31", "2026-02-07"],
  "datasets": [
    {
      "label": "Critical",
      "data": [5, 3, 2, 1, 0],
      "borderColor": "#dc2626"
    },
    {
      "label": "High",
      "data": [12, 10, 8, 7, 5],
      "borderColor": "#ea580c"
    },
    {
      "label": "Medium",
      "data": [30, 28, 25, 22, 20],
      "borderColor": "#ca8a04"
    },
    {
      "label": "Low",
      "data": [15, 15, 14, 14, 13],
      "borderColor": "#2563eb"
    }
  ]
}
```

Chart.js is embedded in the binary as a minified JavaScript file (~60 KB) to maintain offline capability.
