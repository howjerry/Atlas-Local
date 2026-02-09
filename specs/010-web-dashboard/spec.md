# Feature Specification: Atlas Local — Web Dashboard

**Feature Branch**: `010-web-dashboard`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, JSON report format)

## Overview & Scope

Atlas-Local produces JSON reports that are consumed via CLI or CI logs. For ongoing quality and security management, teams need a visual interface to browse findings, track trends over time, compare scans, and prioritise remediation. This specification adds a self-hosted web dashboard that reads Atlas report files, stores them in a local SQLite database, and serves an htmx-powered web interface.

**Purpose**: Provide a zero-dependency web dashboard for visualising Atlas scan results, tracking finding trends, comparing scans across time, and managing technical debt — all running locally without external services.

**Scope**: Rust backend (axum), htmx frontend (no Node.js build step), SQLite persistence, and a Cargo feature flag for optional compilation. Reads Atlas Findings JSON v1.0.0 files.

**Exclusions** (deferred to future specs):
- Multi-tenant SaaS deployment (this is a local/self-hosted tool)
- Real-time scan progress (dashboard only reads completed reports)
- Finding assignment/workflow (Jira/GitHub issue integration)
- Custom dashboard widgets or plugins
- API for third-party integrations (the dashboard is a consumer, not a provider)
- Mobile-responsive layout (desktop-first)
- Finding auto-grouping by root cause

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Browses Findings in a Web Interface (Priority: P1)

A developer runs `atlas dashboard --port 8080 --data-dir ./reports/` and opens `http://localhost:8080` in their browser. They see a list of projects with scan summaries, click into a project, and browse findings with filtering by severity, category, and file path.

**Why this priority**: The web interface is the core value proposition. Without it, the dashboard feature has no utility.

**Independent Test**: Start the dashboard with a directory containing Atlas JSON reports, open the browser, verify the project list loads, click into a project, and confirm findings are displayed with correct severity, category, and file path.

**Acceptance Scenarios**:

1. **Given** a `reports/` directory containing 3 Atlas JSON report files, **When** `atlas dashboard --data-dir ./reports/` starts and the user opens the web page, **Then** 3 projects (or scans) are listed with scan date, finding counts by severity, and gate result.
2. **Given** a project with 50 findings, **When** the user filters by `severity: critical`, **Then** only critical findings are displayed.
3. **Given** a finding in the list, **When** the user clicks on it, **Then** a detail view shows: rule ID, description, file path, line number, code snippet, remediation guidance, and metadata.

---

### User Story 2 — Manager Tracks Finding Trends Over Time (Priority: P1)

A manager opens the dashboard and views a trend chart showing how finding counts have changed across the last 10 scans. The chart clearly shows whether the team is making progress on reducing security debt.

**Why this priority**: Trend visualisation is the key differentiator between the dashboard and raw CLI output. It enables data-driven quality management.

**Independent Test**: Import 10 scan reports with decreasing finding counts, open the trend view, and verify the chart shows a downward trend.

**Acceptance Scenarios**:

1. **Given** 10 historical scan reports for a project, **When** the trend view is opened, **Then** a line chart shows finding count per severity level over time (x-axis: scan date, y-axis: count).
2. **Given** a trend where critical findings decreased from 5 to 0 over 8 scans, **When** the trend chart is viewed, **Then** the critical line shows a clear downward trend.
3. **Given** a single scan (no history), **When** the trend view is opened, **Then** a message indicates "Not enough data for trend analysis. At least 2 scans required."

---

### User Story 3 — Team Compares Two Scans (Priority: P2)

A team lead selects two scans and compares them to see which findings are new, resolved, or unchanged. This helps assess the impact of a remediation sprint.

**Why this priority**: Scan comparison provides actionable insight for remediation planning, but requires the basic dashboard (US1) and multiple scan imports.

**Independent Test**: Import two scans where 3 findings are resolved and 2 are new, open the comparison view, and verify the diff is correct.

**Acceptance Scenarios**:

1. **Given** scan A with findings [F1, F2, F3, F4] and scan B with findings [F1, F2, F5, F6], **When** comparing A to B, **Then** the comparison shows: F3, F4 as "Resolved", F5, F6 as "New", and F1, F2 as "Unchanged".
2. **Given** a comparison view, **When** the user filters to "New only", **Then** only newly introduced findings are shown.

---

### User Story 4 — Team Uses Authentication for Shared Dashboard (Priority: P2)

A team deploys the dashboard on a shared server with basic authentication enabled. Only authenticated users can access the dashboard.

**Why this priority**: Shared deployments need minimal access control, but local (single-user) mode must remain the default.

**Independent Test**: Start the dashboard with `--auth user:password`, attempt to access without credentials (expect 401), then with correct credentials (expect 200).

**Acceptance Scenarios**:

1. **Given** `atlas dashboard --auth admin:secret`, **When** accessing without credentials, **Then** a 401 response with WWW-Authenticate header is returned.
2. **Given** correct basic auth credentials, **When** accessing the dashboard, **Then** the full interface is served.
3. **Given** no `--auth` flag, **When** accessing locally, **Then** no authentication is required (default for local use).

---

### Edge Cases

- What happens when a report file is malformed? The file is skipped with a warning log. Other reports are imported normally.
- What happens when the data directory is empty? The dashboard starts successfully and shows "No scan data found. Run `atlas scan` and place reports in the data directory."
- What happens when the SQLite database exceeds available disk space? An error is returned to the user suggesting cleanup or a larger disk.
- What happens with very large reports (10,000+ findings)? The finding list uses pagination (50 findings per page) to maintain performance.
- What happens if two reports have the same project name and timestamp? They are treated as separate scans, distinguished by report fingerprint.

## Requirements *(mandatory)*

### Functional Requirements

**Dashboard Server**

- **FR-W01**: Atlas MUST provide an `atlas dashboard` subcommand that starts an HTTP server on a configurable port (default: 8080).
- **FR-W02**: The `--data-dir` flag MUST specify the directory containing Atlas JSON report files to import.
- **FR-W03**: The dashboard MUST store imported report data in a local SQLite database (default: `{data-dir}/atlas-dashboard.db`).
- **FR-W04**: New report files added to the data directory MUST be automatically imported on the next page load or via a manual "Refresh" action.

**Web Interface**

- **FR-W05**: The web interface MUST be built with htmx (no React/Vue/Angular, no Node.js build step) to maintain zero frontend dependencies.
- **FR-W06**: HTML templates and static assets MUST be embedded in the binary at compile time (no external file serving required).
- **FR-W07**: The dashboard MUST use server-rendered HTML with htmx for partial page updates (AJAX-like interaction without full page reloads).

**Views & Navigation**

- **FR-W08**: Project List view MUST show all imported projects with: project name, latest scan date, finding counts by severity, gate result, and trend direction (up/down/flat).
- **FR-W09**: Scan Detail view MUST show all findings for a scan with: filtering by severity, category, and file path; sorting by severity, file, or line; and pagination (50 per page).
- **FR-W10**: Finding Detail view MUST show: rule ID, description, severity, category, file path, line range, code snippet, remediation, confidence, and all metadata.
- **FR-W11**: Trend view MUST show a line chart of finding counts over time (per severity level) for a selected project.
- **FR-W12**: Scan Comparison view MUST show a diff between two selected scans: new findings, resolved findings, and unchanged findings (matched by fingerprint).

**Data Import**

- **FR-W13**: The dashboard MUST import Atlas Findings JSON v1.0.0 report files (the same format produced by `atlas scan --format json`).
- **FR-W14**: Import MUST extract: scan metadata, all findings, and gate result from each report file.
- **FR-W15**: Duplicate report imports (same file imported twice) MUST be idempotent — no duplicate entries.

**Authentication**

- **FR-W16**: Authentication MUST be optional, disabled by default for local use.
- **FR-W17**: When enabled via `--auth <user:password>`, the dashboard MUST use HTTP Basic Authentication.
- **FR-W18**: Passwords MUST be hashed (bcrypt) when stored — never stored in plaintext.

**Build Configuration**

- **FR-W19**: The dashboard MUST be gated behind a Cargo feature flag `dashboard` to avoid pulling axum and web dependencies for users who do not need it.
- **FR-W20**: When the `dashboard` feature is disabled, the `atlas dashboard` subcommand MUST not be available.

### Key Entities

- **Project**: A grouping of scans by project name. Key attributes: `name`, `scan_count`, `latest_scan_date`, `trend_direction`.
- **ScanRecord**: A stored scan imported from a JSON report. Key attributes: `id`, `project_name`, `scan_date`, `finding_count`, `gate_result`, `report_hash`.
- **DashboardFinding**: A finding stored in the dashboard database. Key attributes: `fingerprint`, `scan_id`, `rule_id`, `severity`, `category`, `file_path`, `line`, `description`, `metadata`.
- **TrendDirection**: The direction of finding count change. Values: `Improving` (decreasing), `Worsening` (increasing), `Stable` (unchanged).
- **DashboardConfig**: Configuration for the dashboard server. Key attributes: `port`, `data_dir`, `db_path`, `auth`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-W01**: The dashboard imports and correctly displays findings from 10 Atlas JSON reports without data loss.
- **SC-W02**: Finding filtering by severity, category, and file path returns correct results in < 200ms for a scan with 1,000 findings.
- **SC-W03**: Trend charts correctly reflect finding count changes across 10+ scans for a project.
- **SC-W04**: Scan comparison correctly identifies new, resolved, and unchanged findings by fingerprint matching, with 100% accuracy on a test corpus of 5 scan pairs.
- **SC-W05**: The dashboard starts and serves the first page in < 2 seconds (including SQLite initialization and report import).
- **SC-W06**: Basic authentication correctly blocks unauthenticated requests when enabled.
- **SC-W07**: The `dashboard` Cargo feature flag correctly excludes all web dependencies when disabled (verified by `cargo build` without the feature).
- **SC-W08**: HTML pages load correctly without any external CDN requests (all assets embedded).

## Assumptions

- axum is a suitable HTTP framework for the Rust backend (lightweight, async, well-maintained).
- htmx provides sufficient interactivity for the dashboard use case without requiring a JavaScript SPA framework.
- SQLite is sufficient for the dashboard's storage needs (single-user or small-team, not high-concurrency).
- Atlas JSON report format is stable and versioned, allowing reliable import.
- Chart rendering can be done with a lightweight JavaScript charting library embedded in the binary (e.g., Chart.js minified).

## Scope Boundaries

**In Scope**:
- `atlas dashboard` CLI subcommand
- axum HTTP server with configurable port
- htmx-based web interface (no Node.js build)
- Embedded HTML templates and static assets
- SQLite database for report storage
- Project list, scan detail, finding detail, trend, and comparison views
- Finding filtering, sorting, and pagination
- JSON report import
- Optional HTTP Basic Authentication
- `dashboard` Cargo feature flag
- Offline operation (no external network requests)

**Out of Scope**:
- Multi-tenant SaaS deployment
- Real-time scan progress tracking
- Issue tracker integration (Jira, GitHub Issues)
- Custom widgets or plugins
- REST API for third-party consumers
- Mobile-responsive layout
- Finding auto-grouping
- User roles/permissions beyond basic auth

## Implementation Notes

### Crate Structure

A new `atlas-dashboard` crate in the workspace:

```
crates/atlas-dashboard/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API
│   ├── server.rs        # axum server setup
│   ├── routes/          # Route handlers
│   │   ├── mod.rs
│   │   ├── projects.rs  # Project list
│   │   ├── scans.rs     # Scan detail
│   │   ├── findings.rs  # Finding detail + list
│   │   ├── trends.rs    # Trend charts
│   │   └── compare.rs   # Scan comparison
│   ├── db.rs            # SQLite schema + queries
│   ├── import.rs        # JSON report importer
│   └── auth.rs          # Basic auth middleware
├── templates/           # HTML templates (embedded)
│   ├── base.html
│   ├── projects.html
│   ├── scan_detail.html
│   ├── finding_detail.html
│   ├── trends.html
│   └── compare.html
└── static/              # CSS + JS (embedded)
    ├── style.css
    ├── htmx.min.js
    └── chart.min.js
```

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-cli/src/main.rs` | Register `dashboard` subcommand (behind feature flag) |
| `crates/atlas-cli/Cargo.toml` | Add `dashboard` feature depending on `atlas-dashboard` |
| `Cargo.toml` (workspace) | Add `atlas-dashboard` to workspace members |

### Technical Decisions

**htmx over SPA frameworks**: htmx is chosen because:
1. No Node.js toolchain required (Rust-only build pipeline)
2. Server-rendered HTML with partial updates provides good UX
3. All assets can be embedded in the binary (~20 KB for htmx minified)
4. Offline-capable (no CDN dependencies)

**SQLite over PostgreSQL**: SQLite is chosen because:
1. Zero setup (no external database server)
2. File-based (easy backup, migration, deletion)
3. Sufficient for single-user / small-team dashboard workloads
4. `rusqlite` is already a dependency in the project

### Dashboard SQLite Schema

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
    gate_result TEXT,  -- 'PASS', 'FAIL', 'WARN'
    report_hash TEXT NOT NULL UNIQUE,  -- SHA-256 of report file
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
    metadata_json TEXT  -- JSON blob for all metadata
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_scans_project ON scans(project_name);
```

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification and report format |
| [axum](https://docs.rs/axum/) | Rust web framework |
| [htmx](https://htmx.org/) | HTML-over-the-wire frontend library |
| [Chart.js](https://www.chartjs.org/) | Lightweight JavaScript charting library |
| [rusqlite](https://docs.rs/rusqlite/) | SQLite bindings for Rust |
| [OWASP DefectDojo](https://defectdojo.github.io/django-DefectDojo/) | Industry reference for vulnerability management dashboards |
