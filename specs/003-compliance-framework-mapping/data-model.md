# Data Model: Compliance Framework Mapping

**Feature**: 003-compliance-framework-mapping
**Created**: 2026-02-08
**Purpose**: Define the compliance metadata schema, framework definitions, and coverage reporting data model.

## 1. Compliance Mapping in Rule YAML

Security rules gain an optional `metadata.compliance` array that maps the rule to one or more compliance framework requirements.

### Schema

```yaml
metadata:
  compliance:
    - framework: owasp-top-10-2021
      requirement: "A03:2021"
      description: "Injection"
    - framework: pci-dss-4.0
      requirement: "6.2.4"
      description: "Software engineering techniques prevent common coding vulnerabilities"
    - framework: nist-800-53
      requirement: "SI-10"
      description: "Information Input Validation"
```

### Example: SQL Injection Rule with Compliance

```yaml
id: atlas/security/typescript/sql-injection
name: SQL Injection
description: >
  Detects string concatenation in SQL query construction, which may allow
  SQL injection attacks.
severity: critical
category: security
language: TypeScript
cwe_id: CWE-89
pattern: |
  (call_expression
    function: (member_access_expression
      name: (property_identifier) @fn_name)
    arguments: (arguments
      (template_string) @query))
  (#match? @fn_name "^(query|execute|raw)$")
  @match
remediation: >
  Use parameterised queries or prepared statements instead of string
  concatenation for SQL queries.
references:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://owasp.org/Top10/A03_2021-Injection/
tags:
  - owasp-top-10
  - injection
  - sql
version: 1.0.0
confidence: high
metadata:
  compliance:
    - framework: owasp-top-10-2021
      requirement: "A03:2021"
      description: "Injection"
    - framework: pci-dss-4.0
      requirement: "6.2.4"
      description: "Software engineering techniques prevent common coding vulnerabilities"
    - framework: nist-800-53
      requirement: "SI-10"
      description: "Information Input Validation"
    - framework: hipaa-security
      requirement: "164.312(a)(2)(iv)"
      description: "Encryption and Decryption — protect against injection in data flows"
```

## 2. Compliance Framework Definition Schema

Each framework is defined as a YAML file in `rules/compliance/`. These are embedded in the Atlas binary at compile time.

### Schema

```yaml
id: owasp-top-10-2021
name: "OWASP Top 10 2021"
version: "2021"
url: "https://owasp.org/Top10/"
categories:
  - id: "A01:2021"
    title: "Broken Access Control"
    description: "Restrictions on what authenticated users can do are not properly enforced."
  - id: "A02:2021"
    title: "Cryptographic Failures"
    description: "Failures related to cryptography which often lead to sensitive data exposure."
  # ... remaining categories
```

### Full OWASP Top 10 2021 Definition

```yaml
id: owasp-top-10-2021
name: "OWASP Top 10 2021"
version: "2021"
url: "https://owasp.org/Top10/"
categories:
  - id: "A01:2021"
    title: "Broken Access Control"
    description: "Restrictions on what authenticated users can do are not properly enforced."
  - id: "A02:2021"
    title: "Cryptographic Failures"
    description: "Failures related to cryptography which often lead to sensitive data exposure."
  - id: "A03:2021"
    title: "Injection"
    description: "User-supplied data is not validated, filtered, or sanitised by the application."
  - id: "A04:2021"
    title: "Insecure Design"
    description: "Missing or ineffective control design, as distinguished from implementation flaws."
  - id: "A05:2021"
    title: "Security Misconfiguration"
    description: "Missing or incorrect security hardening across the application stack."
  - id: "A06:2021"
    title: "Vulnerable and Outdated Components"
    description: "Using components with known vulnerabilities."
  - id: "A07:2021"
    title: "Identification and Authentication Failures"
    description: "Weaknesses in authentication and session management."
  - id: "A08:2021"
    title: "Software and Data Integrity Failures"
    description: "Code and infrastructure that does not protect against integrity violations."
  - id: "A09:2021"
    title: "Security Logging and Monitoring Failures"
    description: "Insufficient logging, detection, monitoring, and active response."
  - id: "A10:2021"
    title: "Server-Side Request Forgery (SSRF)"
    description: "Web application fetches a remote resource without validating the user-supplied URL."
```

### PCI DSS 4.0 Definition (Requirement 6 subset)

```yaml
id: pci-dss-4.0
name: "PCI DSS 4.0"
version: "4.0"
url: "https://www.pcisecuritystandards.org/"
categories:
  - id: "6.2.1"
    title: "Secure Development Lifecycle"
    description: "Bespoke and custom software is developed securely."
  - id: "6.2.2"
    title: "Software Development Training"
    description: "Software development personnel are trained in secure development practices."
  - id: "6.2.3"
    title: "Code Review"
    description: "Bespoke and custom software is reviewed prior to release."
  - id: "6.2.4"
    title: "Common Coding Vulnerabilities"
    description: "Software engineering techniques prevent common coding vulnerabilities."
  - id: "6.3.1"
    title: "Vulnerability Identification"
    description: "Security vulnerabilities are identified and managed."
  - id: "6.3.2"
    title: "Software Inventory"
    description: "An inventory of bespoke and custom software and third-party components is maintained."
  - id: "6.5.1"
    title: "Change Management"
    description: "Changes to system components in production are managed."
```

## 3. Compliance Summary in Reports

### JSON Report Structure

```json
{
  "scan_metadata": { "..." : "..." },
  "findings": [ "..." ],
  "gate_result": { "..." : "..." },
  "compliance_summary": {
    "frameworks": [
      {
        "framework": "owasp-top-10-2021",
        "name": "OWASP Top 10 2021",
        "coverage_percentage": 70.0,
        "covered_categories": 7,
        "total_categories": 10,
        "categories": [
          {
            "id": "A01:2021",
            "title": "Broken Access Control",
            "mapped_rules": 2,
            "finding_count": 5,
            "status": "covered"
          },
          {
            "id": "A04:2021",
            "title": "Insecure Design",
            "mapped_rules": 0,
            "finding_count": 0,
            "status": "no_coverage"
          }
        ]
      }
    ]
  }
}
```

### CLI Coverage Output (Table Format)

```
OWASP Top 10 2021 — Coverage Report
═══════════════════════════════════════════════════════════════════
 Category     Title                              Rules  Findings  Status
─────────────────────────────────────────────────────────────────
 A01:2021     Broken Access Control                 2         5  ✓ Covered
 A02:2021     Cryptographic Failures                3         2  ✓ Covered
 A03:2021     Injection                             4        12  ✓ Covered
 A04:2021     Insecure Design                       0         0  ✗ No Coverage
 A05:2021     Security Misconfiguration             1         0  ✓ Covered
 A06:2021     Vulnerable and Outdated Components    0         0  ✗ No Coverage
 A07:2021     Identification and Authentication     2         3  ✓ Covered
 A08:2021     Software and Data Integrity           0         0  ✗ No Coverage
 A09:2021     Security Logging and Monitoring       1         1  ✓ Covered
 A10:2021     Server-Side Request Forgery           1         0  ✓ Covered
═══════════════════════════════════════════════════════════════════
 Coverage: 7/10 categories (70.0%)  |  Total rules mapped: 14
```

### CLI Coverage Output (JSON Format)

```json
{
  "framework": "owasp-top-10-2021",
  "name": "OWASP Top 10 2021",
  "coverage_percentage": 70.0,
  "covered_categories": 7,
  "total_categories": 10,
  "total_mapped_rules": 14,
  "categories": [
    {
      "id": "A01:2021",
      "title": "Broken Access Control",
      "mapped_rules": 2,
      "finding_count": 5,
      "status": "covered"
    }
  ]
}
```

## 4. Rust Type Definitions

### ComplianceMapping (in Rule metadata)

Stored as `serde_json::Value` in `Rule.metadata["compliance"]`, but logically:

```rust
/// A single compliance framework mapping on a rule.
struct ComplianceMapping {
    framework: String,      // e.g., "owasp-top-10-2021"
    requirement: String,    // e.g., "A03:2021"
    description: String,    // e.g., "Injection"
}
```

### ComplianceFramework (embedded definition)

```rust
/// An embedded compliance framework definition.
struct ComplianceFramework {
    id: String,             // e.g., "owasp-top-10-2021"
    name: String,           // e.g., "OWASP Top 10 2021"
    version: String,        // e.g., "2021"
    url: String,            // e.g., "https://owasp.org/Top10/"
    categories: Vec<ComplianceCategory>,
}

/// A category within a compliance framework.
struct ComplianceCategory {
    id: String,             // e.g., "A03:2021"
    title: String,          // e.g., "Injection"
    description: String,
}
```

### ComplianceSummary (report output)

```rust
/// Compliance coverage summary for a scan report.
struct ComplianceSummary {
    frameworks: Vec<FrameworkCoverage>,
}

/// Coverage details for a single compliance framework.
struct FrameworkCoverage {
    framework: String,
    name: String,
    coverage_percentage: f64,
    covered_categories: usize,
    total_categories: usize,
    total_mapped_rules: usize,
    categories: Vec<CategoryCoverage>,
}

/// Coverage details for a single framework category.
struct CategoryCoverage {
    id: String,
    title: String,
    mapped_rules: usize,
    finding_count: usize,
    status: CoverageStatus,     // Covered | NoCoverage
}

enum CoverageStatus {
    Covered,
    NoCoverage,
}
```

## 5. CWE to Framework Mapping Reference

The following table shows how existing Atlas CWE mappings relate to compliance frameworks. This guides the backfill of compliance metadata.

| CWE | OWASP 2021 | PCI DSS 4.0 | NIST 800-53 | HIPAA |
|-----|-----------|-------------|-------------|-------|
| CWE-78 (OS Command Injection) | A03 Injection | 6.2.4 | SI-10 | 164.312(a)(1) |
| CWE-79 (XSS) | A03 Injection | 6.2.4 | SI-10 | — |
| CWE-89 (SQL Injection) | A03 Injection | 6.2.4 | SI-10 | 164.312(a)(2)(iv) |
| CWE-90 (LDAP Injection) | A03 Injection | 6.2.4 | SI-10 | — |
| CWE-22 (Path Traversal) | A01 Broken Access Control | 6.2.4 | AC-3 | 164.312(a)(1) |
| CWE-502 (Deserialization) | A08 Software Integrity | 6.2.4 | SI-10 | — |
| CWE-918 (SSRF) | A10 SSRF | 6.2.4 | SC-7 | — |
| CWE-327 (Weak Crypto) | A02 Cryptographic Failures | 6.2.4 | SC-13 | 164.312(a)(2)(iv) |
| CWE-798 (Hardcoded Credentials) | A07 Auth Failures | 6.2.4, 6.3.2 | IA-5 | 164.312(d) |
| CWE-200 (Information Exposure) | A01 Broken Access Control | 6.2.4 | AC-4 | 164.312(a)(1) |

## 6. Finding Metadata Flow

Compliance metadata flows through the system as follows:

```
Rule YAML                  Rule Struct               Finding                 Report
─────────                  ───────────               ───────                 ──────
metadata:                  metadata: {               metadata: {             compliance_summary: {
  compliance:                "compliance": [           "compliance": [         frameworks: [{
    - framework: owasp       { framework: ...,          { framework: ...,       coverage: 70%,
      requirement: A03         requirement: ...,          requirement: ...,     categories: [...]
      description: ...         description: ...  }        description: ...}   }]
                             ]                          ]                    }
                           }                          }
```

The propagation happens automatically because:
1. `Rule.metadata` already stores `BTreeMap<String, serde_json::Value>`
2. The L1 engine copies `Rule.metadata` → `Finding.metadata` at match time (FR-C14)
3. Report formatters read `Finding.metadata` for output
4. The new `compliance_summary` is computed by aggregating `Finding.metadata["compliance"]` across all findings and cross-referencing with embedded framework definitions
