# Data Model: SBOM Generation

**Feature**: 009-sbom-generation
**Created**: 2026-02-08
**Purpose**: Define the CycloneDX and SPDX output structures, purl generation, and SBOM data model.

## 1. SBOM Document

### Rust Type

```rust
/// An SBOM document ready for serialisation.
pub struct SbomDocument {
    /// The output format.
    pub format: SbomFormat,
    /// Project metadata.
    pub project_name: String,
    /// Project version (if detectable from lockfile).
    pub project_version: Option<String>,
    /// Components (dependencies).
    pub components: Vec<SbomComponent>,
    /// Known vulnerabilities (from SCA database).
    pub vulnerabilities: Vec<SbomVulnerability>,
    /// Generation timestamp.
    pub timestamp: String,
}

/// SBOM output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDxJson,
    SpdxJson,
}
```

## 2. SBOM Component

### Rust Type

```rust
/// A dependency component in the SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Package name.
    pub name: String,
    /// Exact version.
    pub version: String,
    /// Package URL (purl) following the purl specification.
    pub purl: String,
    /// Package ecosystem.
    pub ecosystem: Ecosystem,
    /// Component type (always "library" for dependencies).
    pub component_type: String,
    /// Lockfile this dependency was parsed from.
    pub lockfile_path: String,
}
```

### Package URL (purl) Format

| Ecosystem | purl Format | Example |
|-----------|------------|---------|
| npm | `pkg:npm/{name}@{version}` | `pkg:npm/express@4.18.2` |
| Cargo | `pkg:cargo/{name}@{version}` | `pkg:cargo/serde@1.0.193` |
| Maven | `pkg:maven/{group}/{artifact}@{version}` | `pkg:maven/org.springframework/spring-core@6.1.2` |
| Go | `pkg:golang/{module}@{version}` | `pkg:golang/github.com/gin-gonic/gin@v1.9.1` |
| PyPI | `pkg:pypi/{name}@{version}` | `pkg:pypi/flask@2.3.2` |
| NuGet | `pkg:nuget/{name}@{version}` | `pkg:nuget/Newtonsoft.Json@13.0.3` |

### purl Generation

```rust
fn generate_purl(dep: &Dependency) -> String {
    match dep.ecosystem {
        Ecosystem::Npm => format!("pkg:npm/{}@{}", dep.name, dep.version),
        Ecosystem::Cargo => format!("pkg:cargo/{}@{}", dep.name, dep.version),
        Ecosystem::Maven => {
            // Maven deps have group:artifact format
            let parts: Vec<&str> = dep.name.splitn(2, ':').collect();
            if parts.len() == 2 {
                format!("pkg:maven/{}/{}@{}", parts[0], parts[1], dep.version)
            } else {
                format!("pkg:maven/{}@{}", dep.name, dep.version)
            }
        },
        Ecosystem::Go => format!("pkg:golang/{}@{}", dep.name, dep.version),
        Ecosystem::Pypi => format!("pkg:pypi/{}@{}", dep.name, dep.version),
        Ecosystem::Nuget => format!("pkg:nuget/{}@{}", dep.name, dep.version),
    }
}
```

## 3. CycloneDX v1.5 Output

### JSON Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-02-08T12:00:00Z",
    "tools": [{
      "vendor": "Atlas",
      "name": "Atlas Local",
      "version": "0.1.0"
    }],
    "component": {
      "type": "application",
      "name": "my-project",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "bom-ref": "pkg:npm/express@4.18.2"
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "bom-ref": "pkg:npm/lodash@4.17.20"
    }
  ],
  "dependencies": [
    {
      "ref": "my-project",
      "dependsOn": [
        "pkg:npm/express@4.18.2",
        "pkg:npm/lodash@4.17.20"
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/"
      },
      "ratings": [{
        "score": 7.2,
        "severity": "high",
        "method": "CVSSv3"
      }],
      "description": "Prototype Pollution in lodash",
      "affects": [{
        "ref": "pkg:npm/lodash@4.17.20"
      }],
      "recommendation": "Upgrade to lodash 4.17.21 or later"
    }
  ]
}
```

## 4. SPDX v2.3 Output

### JSON Structure

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-project",
  "documentNamespace": "https://atlas.dev/spdx/my-project/2026-02-08T12:00:00Z",
  "creationInfo": {
    "created": "2026-02-08T12:00:00Z",
    "creators": [
      "Tool: Atlas Local-0.1.0"
    ],
    "licenseListVersion": "3.22"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-npm-express-4.18.2",
      "name": "express",
      "versionInfo": "4.18.2",
      "downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "filesAnalyzed": false,
      "externalRefs": [{
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": "pkg:npm/express@4.18.2"
      }],
      "primaryPackagePurpose": "LIBRARY"
    },
    {
      "SPDXID": "SPDXRef-Package-npm-lodash-4.17.20",
      "name": "lodash",
      "versionInfo": "4.17.20",
      "downloadLocation": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
      "filesAnalyzed": false,
      "externalRefs": [{
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": "pkg:npm/lodash@4.17.20"
      }],
      "primaryPackagePurpose": "LIBRARY"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-npm-express-4.18.2",
      "relationshipType": "DEPENDS_ON"
    },
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-npm-lodash-4.17.20",
      "relationshipType": "DEPENDS_ON"
    }
  ]
}
```

## 5. SPDX ID Generation

```rust
/// Generate a deterministic SPDX ID for a dependency.
fn spdx_id(dep: &Dependency) -> String {
    let ecosystem = match dep.ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Maven => "maven",
        Ecosystem::Go => "go",
        Ecosystem::Pypi => "pypi",
        Ecosystem::Nuget => "nuget",
    };
    // Replace non-alphanumeric characters with hyphens for SPDX compliance
    let safe_name = dep.name.replace(|c: char| !c.is_alphanumeric(), "-");
    let safe_version = dep.version.replace(|c: char| !c.is_alphanumeric(), "-");
    format!("SPDXRef-Package-{}-{}-{}", ecosystem, safe_name, safe_version)
}
```

## 6. SBOM Vulnerability (CycloneDX only)

```rust
/// A known vulnerability included in a CycloneDX SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomVulnerability {
    /// CVE identifier.
    pub id: String,
    /// Advisory source.
    pub source_name: String,
    pub source_url: String,
    /// CVSS ratings.
    pub ratings: Vec<SbomRating>,
    /// Short description.
    pub description: String,
    /// Affected component purl references.
    pub affects: Vec<String>,
    /// Upgrade recommendation.
    pub recommendation: Option<String>,
}

/// A CVSS rating for a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomRating {
    pub score: f64,
    pub severity: String,
    pub method: String,  // "CVSSv3"
}
```

## 7. CLI Interface

```
atlas sbom generate [OPTIONS]

Options:
    --format <FORMAT>     Output format [default: cyclonedx-json]
                          [possible values: cyclonedx-json, spdx-json]
    --output <FILE>       Output file path (stdout if omitted)
    --project-name <NAME> Project name for SBOM metadata
                          [default: directory name]
    --include-vulns       Include known vulnerabilities in SBOM
                          [default: true if database exists]
```

## 8. Generation Pipeline

```
atlas sbom generate --format cyclonedx-json --output sbom.json
  │
  ├─ Reuse SCA lockfile parsers
  │   └─ Parse all lockfiles → Vec<Dependency>
  │
  ├─ Generate purl for each dependency
  │
  ├─ (Optional) Query vulnerability database
  │   └─ For each dependency → Vec<Vulnerability>
  │
  ├─ Build SbomDocument
  │   ├─ Components from dependencies
  │   ├─ Vulnerabilities from database matches
  │   └─ Metadata (tool info, timestamp, project)
  │
  ├─ Serialise to chosen format
  │   ├─ cyclonedx-json → CycloneDX v1.5 JSON
  │   └─ spdx-json → SPDX v2.3 JSON
  │
  └─ Write to file or stdout
```
