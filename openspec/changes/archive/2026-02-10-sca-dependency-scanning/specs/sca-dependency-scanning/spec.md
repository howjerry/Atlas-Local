## ADDED Requirements

### Requirement: npm lockfile parsing
The system SHALL parse `package-lock.json` (npm v2 and v3 format) to extract dependency names and exact pinned versions.

#### Scenario: Parse npm v3 lockfile
- **WHEN** a `package-lock.json` with `lockfileVersion: 3` containing `lodash@4.17.20` is discovered during scan
- **THEN** a `Dependency` record is produced with `name: "lodash"`, `version: "4.17.20"`, `ecosystem: "npm"`, `lockfile_path` pointing to the file

#### Scenario: Parse npm v2 lockfile
- **WHEN** a `package-lock.json` with `lockfileVersion: 2` is discovered
- **THEN** dependencies are extracted from the `packages` field (v2 format)

#### Scenario: Malformed npm lockfile
- **WHEN** a `package-lock.json` contains invalid JSON
- **THEN** a warning is logged and scanning continues with other lockfiles

### Requirement: Cargo lockfile parsing
The system SHALL parse `Cargo.lock` (Rust) to extract crate names and versions.

#### Scenario: Parse Cargo.lock
- **WHEN** a `Cargo.lock` containing `serde 1.0.193` is discovered during scan
- **THEN** a `Dependency` record is produced with `name: "serde"`, `version: "1.0.193"`, `ecosystem: "cargo"`

#### Scenario: Malformed Cargo.lock
- **WHEN** a `Cargo.lock` contains invalid TOML
- **THEN** a warning is logged and scanning continues with other lockfiles

### Requirement: Maven and Gradle lockfile parsing
The system SHALL parse `pom.xml` and `gradle.lockfile` (Java/Kotlin) to extract artifact coordinates and versions.

#### Scenario: Parse pom.xml dependencies
- **WHEN** a `pom.xml` containing `<dependency>` elements with `groupId`, `artifactId`, and `version` is discovered
- **THEN** a `Dependency` record is produced with `name: "groupId:artifactId"`, the resolved version, and `ecosystem: "maven"`

#### Scenario: Parse gradle.lockfile
- **WHEN** a `gradle.lockfile` is discovered
- **THEN** dependencies are extracted with `ecosystem: "maven"` (shared ecosystem)

### Requirement: Go module lockfile parsing
The system SHALL parse `go.sum` (Go) to extract module paths and versions.

#### Scenario: Parse go.sum
- **WHEN** a `go.sum` containing `golang.org/x/text v0.14.0 h1:...` is discovered
- **THEN** a `Dependency` record is produced with `name: "golang.org/x/text"`, `version: "0.14.0"` (v prefix stripped), `ecosystem: "go"`

#### Scenario: Deduplicate go.sum entries
- **WHEN** a `go.sum` contains both `h1:` and `go.mod h1:` entries for the same module version
- **THEN** only one `Dependency` record is produced per unique module+version

### Requirement: Python lockfile parsing
The system SHALL parse `requirements.txt` and `Pipfile.lock` (Python) to extract package names and pinned versions.

#### Scenario: Parse requirements.txt with pinned versions
- **WHEN** a `requirements.txt` containing `requests==2.31.0` is discovered
- **THEN** a `Dependency` record is produced with `name: "requests"`, `version: "2.31.0"`, `ecosystem: "pypi"`

#### Scenario: Skip unpinned requirements
- **WHEN** a `requirements.txt` contains `requests>=2.0` (range, not pinned)
- **THEN** the dependency is still extracted with the lower bound version for advisory matching

#### Scenario: Parse Pipfile.lock
- **WHEN** a `Pipfile.lock` is discovered
- **THEN** dependencies are extracted from the `default` and `develop` sections with `ecosystem: "pypi"`

### Requirement: NuGet lockfile parsing
The system SHALL parse `packages.lock.json` (NuGet/.NET) to extract package names and versions.

#### Scenario: Parse NuGet packages.lock.json
- **WHEN** a `packages.lock.json` containing a dependency with `"resolved": "6.0.0"` is discovered
- **THEN** a `Dependency` record is produced with the package name, `version: "6.0.0"`, `ecosystem: "nuget"`

### Requirement: Automatic lockfile discovery
The system SHALL automatically discover lockfiles in the scan target directory (recursively) and trigger SCA analysis without a separate command.

#### Scenario: Automatic discovery during scan
- **WHEN** `atlas scan ./` is run on a directory containing `package-lock.json` in a subdirectory
- **THEN** the lockfile is discovered and SCA analysis is performed automatically

#### Scenario: No lockfile found
- **WHEN** `atlas scan ./` is run on a directory with no lockfiles
- **THEN** no SCA analysis is performed and a debug-level log indicates "No lockfile found; skipping SCA"

#### Scenario: Multiple lockfiles in project
- **WHEN** a project contains `package-lock.json`, `Cargo.lock`, and `requirements.txt`
- **THEN** all three lockfiles are parsed and dependencies from all ecosystems are analysed

### Requirement: Offline SQLite vulnerability database
The system SHALL store vulnerability advisories in a local SQLite database at a configurable path (default: `~/.atlas/vuln.db`).

#### Scenario: Database contains advisory entries
- **WHEN** the vulnerability database is queried for ecosystem "npm" and package "lodash"
- **THEN** all matching advisory records are returned, each containing: CVE ID, affected version range, fixed version, CVSS score, severity, description

#### Scenario: Database path is configurable
- **WHEN** a scan config specifies `vuln_db_path: "/custom/path/vuln.db"`
- **THEN** the database is loaded from the custom path instead of the default

#### Scenario: Database missing
- **WHEN** no vulnerability database exists at the configured path
- **THEN** a warning is logged: "Vulnerability database not found; SCA findings will be empty. Run `atlas sca update-db` to install."

### Requirement: Database update with signature verification
The system SHALL provide `atlas sca update-db <path>` to replace the local database after verifying the bundle's Ed25519 signature.

#### Scenario: Successful database update
- **WHEN** `atlas sca update-db ./vuln-db.bundle` is run with a valid signed bundle
- **THEN** the local database is replaced, and a success message shows the new advisory count and last-updated timestamp

#### Scenario: Tampered bundle rejected
- **WHEN** `atlas sca update-db ./tampered.bundle` is run with an invalid signature
- **THEN** the update is rejected with error: "Invalid database signature"

#### Scenario: Bundle replaces existing database
- **WHEN** `atlas sca update-db` is run and a database already exists
- **THEN** the existing database is atomically replaced (write to temp file, then rename)

### Requirement: Vulnerability matching by version range
For each parsed dependency, the system SHALL query the database for CVEs matching the ecosystem, package name, and installed version against affected version ranges.

#### Scenario: Version falls within affected range
- **WHEN** dependency `lodash@4.17.20` is checked against advisory `CVE-2021-23337` with affected range `< 4.17.21`
- **THEN** a match is found and a finding is produced

#### Scenario: Version outside affected range
- **WHEN** dependency `lodash@4.17.21` is checked against advisory `CVE-2021-23337` with affected range `< 4.17.21`
- **THEN** no match is found

#### Scenario: Ecosystem-specific version comparison
- **WHEN** npm/Cargo/NuGet versions are compared, the `semver` crate's `VersionReq::matches` SHALL be used
- **THEN** semver semantics (including pre-release ordering) are correctly applied

#### Scenario: Multiple CVEs for same package
- **WHEN** a package has 3 matching CVEs in the database
- **THEN** 3 separate findings are produced, each with a distinct `cve_id`

### Requirement: SCA finding model with Category::Sca
The system SHALL add a `Category::Sca` enum variant. Each matched CVE SHALL produce a `Finding` with `category: Sca`.

#### Scenario: SCA finding metadata
- **WHEN** a CVE match is found for `lodash@4.17.20`
- **THEN** the finding includes metadata: `cve_id`, `cvss_score`, `package_name`, `ecosystem`, `installed_version`, `fixed_version`, `advisory_url`

#### Scenario: Severity derived from CVSS
- **WHEN** a CVE has CVSS score 9.1
- **THEN** the finding severity is `Critical` (9.0–10.0)

#### Scenario: Severity derived from CVSS High
- **WHEN** a CVE has CVSS score 7.5
- **THEN** the finding severity is `High` (7.0–8.9)

#### Scenario: Severity derived from CVSS Medium
- **WHEN** a CVE has CVSS score 5.3
- **THEN** the finding severity is `Medium` (4.0–6.9)

#### Scenario: Severity derived from CVSS Low
- **WHEN** a CVE has CVSS score 2.1
- **THEN** the finding severity is `Low` (0.1–3.9)

#### Scenario: Missing CVSS score defaults to Medium
- **WHEN** a CVE has no CVSS score (null)
- **THEN** the finding severity defaults to `Medium`

### Requirement: SCA findings participate in gate evaluation
SCA findings SHALL participate in gate evaluation under `category_overrides.sca`. Without category overrides, SCA findings SHALL be evaluated against global `fail_on` thresholds.

#### Scenario: Gate fails on critical SCA finding
- **WHEN** policy has `category_overrides: { sca: { critical: 0 } }` and a Critical CVE is found
- **THEN** the gate result is `FAIL`

#### Scenario: Gate passes with low severity only
- **WHEN** policy has `category_overrides: { sca: { critical: 0 } }` and only Low severity CVEs are found
- **THEN** the gate result is `PASS`

#### Scenario: Global thresholds apply without category override
- **WHEN** policy has `fail_on: { critical: 0 }` and no `category_overrides.sca`, and a Critical SCA finding exists
- **THEN** the gate result is `FAIL` (global thresholds apply)

### Requirement: SCA findings in report output
SCA findings SHALL appear in JSON, SARIF, and JSONL report formats with the same structure as SAST findings, differentiated by `category: "sca"`.

#### Scenario: SCA findings in JSON report
- **WHEN** a scan produces SCA findings and JSON output is requested
- **THEN** SCA findings appear in the `findings` array with `category: "sca"` and all SCA metadata fields

#### Scenario: SCA findings in SARIF report
- **WHEN** a scan produces SCA findings and SARIF output is requested
- **THEN** SCA findings appear as SARIF `result` entries with `ruleId` prefixed `atlas/sca/`

#### Scenario: SCA findings in JSONL report
- **WHEN** a scan produces SCA findings and JSONL output is requested
- **THEN** each SCA finding is emitted as a separate JSON line

### Requirement: Database staleness warning
The system SHALL warn when the vulnerability database is older than 30 days.

#### Scenario: Database is stale
- **WHEN** a scan is performed and the database `last_updated` timestamp is more than 30 days ago
- **THEN** a warning is logged: "Vulnerability database is N days old. Run `atlas sca update-db` to update."

#### Scenario: Database is fresh
- **WHEN** a scan is performed and the database was updated within the last 30 days
- **THEN** no staleness warning is logged

### Requirement: SCA scan performance
SCA scanning of a project with 500 dependencies SHALL complete in under 3 seconds (lockfile parsing + database queries combined).

#### Scenario: Performance within budget
- **WHEN** a project with 500 dependencies across multiple lockfiles is scanned
- **THEN** the SCA phase (lockfile parsing + vulnerability matching) completes in under 3 seconds
