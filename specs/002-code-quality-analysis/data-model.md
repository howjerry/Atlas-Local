# Data Model: Quality Finding Metadata Schema

**Feature**: 002-code-quality-analysis
**Created**: 2026-02-08
**Purpose**: Define the metadata schema for quality findings, quality domain taxonomy, and metrics model.

## 1. Quality Finding Structure

Quality findings use the same `Finding` struct as security findings (`crates/atlas-analysis/src/finding.rs`). No structural changes are needed. The differences are:

| Field | Security Finding | Quality Finding |
|-------|-----------------|-----------------|
| `rule_id` | `atlas/security/{lang}/{name}` | `atlas/quality/{lang}/{name}` |
| `category` | `"security"` | `"quality"` |
| `cwe_id` | Present (e.g., `"CWE-89"`) | `null` |
| `severity` | Typically Critical/High | Typically Medium/Low/Info |
| `confidence` | Typically High | Varies (High/Medium/Low) |
| `metadata` | `source`, `sink` (for taint rules) | `quality_domain` (mandatory) |
| `tags` | `owasp-top-10`, `injection`, etc. | `code-quality`, domain tags |

### Example Quality Finding (JSON)

```json
{
  "fingerprint": "a1b2c3d4e5f6...",
  "rule_id": "atlas/quality/typescript/empty-catch-block",
  "severity": "medium",
  "category": "quality",
  "cwe_id": null,
  "file_path": "src/services/user-service.ts",
  "line_range": {
    "start_line": 42,
    "start_col": 5,
    "end_line": 42,
    "end_col": 32
  },
  "snippet": "} catch (e) { }",
  "description": "Empty catch block silently swallows the error. This can hide bugs and make debugging difficult.",
  "remediation": "Log the error, re-throw it, or handle it explicitly. If intentionally ignoring the error, add a comment explaining why.",
  "analysis_level": "L1",
  "confidence": "high",
  "metadata": {
    "quality_domain": "error-handling"
  }
}
```

### Example Quality Finding (SARIF)

```json
{
  "ruleId": "atlas/quality/typescript/empty-catch-block",
  "level": "warning",
  "message": {
    "text": "Empty catch block silently swallows the error. This can hide bugs and make debugging difficult."
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/services/user-service.ts" },
      "region": {
        "startLine": 42,
        "startColumn": 5,
        "endLine": 42,
        "endColumn": 32
      }
    }
  }],
  "properties": {
    "category": "quality",
    "confidence": "high",
    "quality_domain": "error-handling"
  }
}
```

**SARIF `level` mapping for quality findings**:

| Atlas Severity | SARIF Level |
|---------------|-------------|
| Critical | `error` |
| High | `error` |
| Medium | `warning` |
| Low | `note` |
| Info | `note` |

## 2. Quality Domain Taxonomy

Quality domains group rules by the type of code quality concern they address. Each rule belongs to exactly one domain.

### Domain Definitions

| Domain | Description | Example Rules |
|--------|-------------|---------------|
| `error-handling` | Improper error handling: swallowed exceptions, bare catches, unchecked errors | `empty-catch-block`, `bare-except`, `pass-in-except`, `empty-error-check`, `unchecked-error` |
| `debug-residual` | Debug/development code left in production: console output, print statements | `console-log`, `system-out-println`, `print-statement`, `fmt-println`, `console-writeline` |
| `type-safety` | Weak or absent type usage undermining type system benefits | `any-type-usage`, `raw-type-usage`, `object-type-usage` |
| `best-practices` | Language idiom violations and common anti-patterns | `loose-equality`, `var-declaration`, `non-null-assertion`, `redundant-boolean`, `mutable-default-arg` |
| `performance` | Patterns with known performance implications | `string-concat-in-loop`, `defer-in-loop` |
| `maintainability` | Code that is harder to understand, extend, or debug | `empty-function-body`, `empty-method-body`, `excessive-parameters`, `todo-comment`, `magic-number` |

### Domain-to-Rule Mapping (Complete)

| Rule ID | Domain |
|---------|--------|
| `typescript/empty-catch-block` | `error-handling` |
| `typescript/console-log` | `debug-residual` |
| `typescript/any-type-usage` | `type-safety` |
| `typescript/loose-equality` | `best-practices` |
| `typescript/var-declaration` | `best-practices` |
| `typescript/non-null-assertion` | `best-practices` |
| `typescript/todo-comment` | `maintainability` |
| `typescript/empty-function-body` | `maintainability` |
| `typescript/redundant-boolean` | `best-practices` |
| `typescript/excessive-parameters` | `maintainability` |
| `java/empty-catch-block` | `error-handling` |
| `java/system-out-println` | `debug-residual` |
| `java/todo-comment` | `maintainability` |
| `java/empty-method-body` | `maintainability` |
| `java/redundant-boolean` | `best-practices` |
| `java/string-concat-in-loop` | `performance` |
| `java/raw-type-usage` | `type-safety` |
| `python/bare-except` | `error-handling` |
| `python/print-statement` | `debug-residual` |
| `python/pass-in-except` | `error-handling` |
| `python/mutable-default-arg` | `best-practices` |
| `python/todo-comment` | `maintainability` |
| `python/empty-function-body` | `maintainability` |
| `python/magic-number` | `maintainability` |
| `go/empty-error-check` | `error-handling` |
| `go/fmt-println` | `debug-residual` |
| `go/defer-in-loop` | `performance` |
| `go/unchecked-error` | `error-handling` |
| `go/todo-comment` | `maintainability` |
| `go/empty-function-body` | `maintainability` |
| `csharp/empty-catch-block` | `error-handling` |
| `csharp/console-writeline` | `debug-residual` |
| `csharp/todo-comment` | `maintainability` |
| `csharp/empty-method-body` | `maintainability` |
| `csharp/redundant-boolean` | `best-practices` |
| `csharp/object-type-usage` | `type-safety` |

### Domain Statistics

| Domain | Rule Count | Languages |
|--------|-----------|-----------|
| `error-handling` | 7 | TS, Java, Python, Go, C# |
| `debug-residual` | 5 | TS, Java, Python, Go, C# |
| `type-safety` | 3 | TS, Java, C# |
| `best-practices` | 7 | TS, Java, Python, C# |
| `performance` | 2 | Java, Go |
| `maintainability` | 12 | TS, Java, Python, Go, C# |
| **Total** | **36** | **5** |

## 3. Quality Rule YAML Schema

Quality rules follow the same YAML schema as security rules. The key differences are annotated below:

```yaml
# Required fields (same as security rules)
id: atlas/quality/{language}/{rule-name}
name: Human-readable rule name
description: >
  Detailed explanation of what the rule detects and why it matters.
severity: medium          # Typically: medium, low, or info
category: quality         # MUST be "quality" (not "security" or "secrets")
language: TypeScript      # One of: TypeScript, Java, Python, Go, CSharp
pattern: |
  (tree_sitter_query) @match

# Quality-specific: no cwe_id field (or explicitly null)
# cwe_id: null           # Omitted entirely — field is optional in schema

remediation: >
  Actionable guidance on how to fix the detected issue.

references:
  - https://example.com/best-practices-guide
  # No CWE or OWASP links — instead link to language best-practice docs

tags:
  - code-quality           # MUST include "code-quality"
  - error-handling         # Domain-specific tag matching quality_domain
version: 1.0.0

# Optional (uses serde defaults if omitted)
confidence: high           # high | medium | low
```

### Example: `empty-catch-block` (TypeScript)

```yaml
id: atlas/quality/typescript/empty-catch-block
name: Empty Catch Block
description: >
  Detects try-catch blocks where the catch clause has an empty body. Empty
  catch blocks silently swallow exceptions, hiding errors that could indicate
  bugs, security issues, or operational problems. This makes debugging
  significantly harder and can mask critical failures.
severity: medium
category: quality
language: TypeScript
pattern: |
  (catch_clause
    body: (statement_block
      .
      "}"))
  @match
remediation: >
  Handle the caught exception explicitly. Options include: (1) Log the error
  with context using a structured logger. (2) Re-throw the error if it
  cannot be handled at this level. (3) Return an error value or default.
  If the empty catch is intentional (e.g., optional cleanup), add a comment
  explaining why the error is being ignored.
references:
  - https://eslint.org/docs/latest/rules/no-empty
  - https://typescript-eslint.io/rules/no-empty-function
tags:
  - code-quality
  - error-handling
version: 1.0.0
confidence: high
```

## 4. Metadata Schema for `Finding.metadata`

Quality findings use the `metadata: BTreeMap<String, serde_json::Value>` field on the `Finding` struct to carry quality-specific information.

### Required Metadata Keys

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| `quality_domain` | `string` | The quality domain this finding belongs to | `"error-handling"` |

### Optional Metadata Keys (Future)

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| `auto_fixable` | `boolean` | Whether this finding can be auto-fixed | `true` |
| `fix_suggestion` | `string` | Suggested code replacement | `"=== null"` |
| `related_rule` | `string` | Related rule in another tool | `"eslint/no-empty"` |

### Setting Metadata in Rule YAML

The `quality_domain` metadata is **not** set in the YAML rule file — it is derived from the rule's tags at load time. The declarative rule loader maps the domain-specific tag to `metadata.quality_domain`:

| Tag Present | `quality_domain` Value |
|-------------|----------------------|
| `error-handling` | `"error-handling"` |
| `debug-residual` | `"debug-residual"` |
| `type-safety` | `"type-safety"` |
| `best-practices` | `"best-practices"` |
| `performance` | `"performance"` |
| `maintainability` | `"maintainability"` |

**Implementation note**: The current L1 engine does not automatically populate `quality_domain` from tags. Two approaches:

1. **Tag-based derivation** (preferred): Add logic in the finding builder to extract `quality_domain` from the rule's tags when `category == quality`. Requires a small code change in the analysis crate.
2. **Explicit metadata in YAML**: Add a `metadata` section to each rule YAML. This avoids code changes but duplicates information already present in tags.

For the initial implementation, **approach 2** (explicit metadata in YAML) is recommended to maintain the "zero code changes" constraint. Each rule YAML includes:

```yaml
metadata:
  quality_domain: "error-handling"
```

The Rule YAML schema already supports arbitrary metadata via `metadata: BTreeMap` in the `Rule` struct. This field just needs to be plumbed through to the Finding at match time.

**Verification**: Check if `Rule` struct has a `metadata` field and if the L1 engine copies it to `Finding.metadata`. If not, approach 1 (tag-based derivation in the engine) may require a small code change, which would be tracked as a separate task.

## 5. Policy Configuration Examples

### Strict Quality Policy (New Projects)

```yaml
name: strict-quality
description: Zero-tolerance quality policy for new projects
fail_on:
  critical: 0
  high: 0
category_overrides:
  quality:
    critical: 0
    high: 0
    medium: 0
    low: null
    info: null
```

### Lenient Quality Policy (Legacy Adoption)

```yaml
name: lenient-quality
description: Gradual quality adoption for legacy codebases
fail_on:
  critical: 0
category_overrides:
  quality:
    critical: 0
    high: 10
    medium: 50
    low: null
    info: null
warn_on:
  quality:
    high: 5
    medium: 20
```

### Security-Only Policy (Quality Informational)

```yaml
name: security-only
description: Only gate on security findings, report quality as informational
fail_on:
  critical: 0
  high: 0
category_overrides:
  quality:
    critical: null
    high: null
    medium: null
    low: null
    info: null
```

Setting all quality thresholds to `null` means quality findings are reported but never cause gate failures.

## 6. Report Integration

### Atlas Findings JSON

Quality findings appear in the same `findings` array as security findings, distinguished by `category`:

```json
{
  "scan_metadata": { ... },
  "findings": [
    { "category": "security", "rule_id": "atlas/security/typescript/sql-injection", ... },
    { "category": "quality", "rule_id": "atlas/quality/typescript/empty-catch-block", ... }
  ],
  "gate_result": {
    "result": "FAIL",
    "breached_thresholds": [
      {
        "severity": "medium",
        "category": "quality",
        "threshold": 5,
        "actual": 12,
        "level": "fail"
      }
    ]
  }
}
```

### SARIF

Quality rules appear as separate entries in `tool.driver.rules` with appropriate `defaultConfiguration.level`:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Atlas",
        "rules": [
          {
            "id": "atlas/quality/typescript/empty-catch-block",
            "shortDescription": { "text": "Empty Catch Block" },
            "defaultConfiguration": { "level": "warning" },
            "properties": {
              "category": "quality",
              "quality_domain": "error-handling",
              "tags": ["code-quality", "error-handling"]
            }
          }
        ]
      }
    },
    "results": [ ... ]
  }]
}
```

### JSONL Events

Quality findings produce the same event structure as security findings:

```json
{"event_type":"finding","timestamp":"2026-02-08T12:00:00Z","correlation_id":"scan-abc","rule_id":"atlas/quality/typescript/empty-catch-block","category":"quality","severity":"medium","file_path":"src/services/user-service.ts","line":42}
```
