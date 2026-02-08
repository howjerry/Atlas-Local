# Feature Specification: Atlas Local — Code Quality Analysis Rules

**Feature Branch**: `002-code-quality-analysis`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, L1 pattern engine, policy gating, report formats)

## Overview & Scope

Atlas-Local currently provides 27 security rules and 6 secrets detection rules across 5 languages. This specification adds **36 code quality rules** that detect common code smells, error-handling anti-patterns, and maintainability issues using the same L1 declarative engine (tree-sitter S-expression queries).

**Purpose**: Enable development teams to detect and manage code quality issues alongside security findings within a single tool, with independent policy gating and reporting.

**Scope**: L1 declarative rules only — each rule is a YAML file with a tree-sitter pattern, requiring zero engine modifications.

**Exclusions** (deferred to future specs):
- L2/L3 analysis (data flow, control flow)
- Naming convention enforcement (requires configurable regex patterns)
- Unused import detection (requires L2 scope analysis)
- Unreachable code detection (requires L2 control flow)
- Code duplication detection (requires L3 cross-file analysis)
- Cyclomatic / cognitive complexity metrics (requires AST traversal counters)
- `--category` CLI filter (engine change, tracked separately)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Runs a Quality-Focused Scan (Priority: P1)

A developer wants to check their code for quality issues before committing. They run `atlas scan ./src` and the report includes both security and quality findings, clearly separated by category. They can filter the report output to focus on quality issues only.

**Why this priority**: This is the core use case — without quality findings appearing in scan results, all other quality features are moot.

**Independent Test**: Scan a project containing known quality anti-patterns (empty catch blocks, console.log statements, bare except clauses) and verify quality findings appear in the report with `category: "quality"`, no `cwe_id`, and correct severity levels.

**Acceptance Scenarios**:

1. **Given** a TypeScript file containing an empty `catch {}` block, **When** `atlas scan ./src` is run, **Then** a finding is produced with `rule_id: "atlas/quality/typescript/empty-catch-block"`, `category: "quality"`, `severity: "medium"`, `cwe_id: null`, and actionable remediation text.
2. **Given** a scan produces both security and quality findings, **When** the user inspects the report, **Then** security findings have `category: "security"` and quality findings have `category: "quality"`, and both are sorted by file path and line number.
3. **Given** a project with no quality issues, **When** scanned, **Then** zero quality findings are produced and existing security detection is unaffected.

---

### User Story 2 — Security Team Separates Quality and Security Gates (Priority: P1)

A security team lead configures separate policy thresholds for security and quality categories. Security findings have a zero-tolerance policy for Critical severity, while quality findings have a more lenient threshold allowing gradual improvement.

**Why this priority**: Without independent gating, quality findings could inadvertently block deployments that have no security issues, or quality gates could be drowned out by security-focused thresholds.

**Independent Test**: Create a policy YAML with different `category_overrides` for `security` and `quality`, scan a project with findings in both categories, and verify each category is evaluated against its own thresholds independently.

**Acceptance Scenarios**:

1. **Given** a policy with `fail_on: { critical: 0 }` and `category_overrides: { quality: { medium: 20 } }`, **When** a scan produces 0 critical security findings and 15 medium quality findings, **Then** the gate result is `PASS` because neither threshold is breached.
2. **Given** a policy with `category_overrides: { quality: { medium: 5 } }`, **When** a scan produces 10 medium quality findings, **Then** the gate result is `FAIL` with a breached threshold referencing the quality category.
3. **Given** a policy with no `category_overrides` for quality, **When** quality findings are produced, **Then** they are evaluated against the global `fail_on` thresholds (same behavior as security).

---

### User Story 3 — Team Uses Baseline for Gradual Quality Adoption (Priority: P2)

A team adopting quality rules on a legacy codebase creates a baseline to avoid failing CI on pre-existing quality issues. Only new quality findings introduced after the baseline count against the quality gate.

**Why this priority**: Legacy codebases may have hundreds of quality issues. Without baseline support, quality rules would be impractical to adopt incrementally.

**Independent Test**: Scan a legacy project, create a baseline, introduce a new quality issue, re-scan with the baseline, and verify only the new issue counts against the quality gate.

**Acceptance Scenarios**:

1. **Given** a project with 100 existing quality findings and a baseline capturing all 100, **When** a new empty catch block is added and the project is re-scanned with the baseline, **Then** only the 1 new finding counts against quality gate thresholds.
2. **Given** a baseline containing quality findings, **When** one of the baselined issues is fixed, **Then** the diff summary shows it as "resolved".
3. **Given** a baseline containing both security and quality findings, **When** re-scanned, **Then** baseline matching works correctly for both categories based on fingerprint comparison.

---

### User Story 4 — Developer Suppresses Known Quality False Positives (Priority: P2)

A developer encounters a quality finding that is intentional (e.g., a deliberately empty catch block with a comment explaining why). They suppress it using an inline annotation or policy-level suppression, and it no longer appears in future scans.

**Why this priority**: False positives erode trust in the tool. Suppression mechanisms are critical for adoption, but the existing suppression infrastructure already handles this — no new mechanism is needed.

**Independent Test**: Add an `atlas-ignore` annotation above a known quality pattern, re-scan, and verify the finding is suppressed.

**Acceptance Scenarios**:

1. **Given** an empty catch block preceded by `// atlas-ignore: atlas/quality/typescript/empty-catch-block`, **When** scanned, **Then** no finding is produced for that location.
2. **Given** a policy-level suppression for a specific rule ID, **When** scanned, **Then** all findings from that rule are suppressed and reported as such in the suppression summary.

---

### User Story 5 — CI/CD Pipeline Gradually Tightens Quality Thresholds (Priority: P2)

A DevOps engineer configures the CI pipeline to start with lenient quality thresholds and progressively tighten them over quarterly sprints, driving continuous quality improvement.

**Why this priority**: Gradual tightening is the recommended adoption pattern for quality rules in large codebases. The existing policy mechanism already supports this — this story validates the workflow.

**Independent Test**: Start with `quality: { medium: 50 }`, reduce to `30`, then `10` over successive scans, and verify the gate correctly transitions from PASS to FAIL as the threshold tightens below the actual count.

**Acceptance Scenarios**:

1. **Given** a policy with `category_overrides: { quality: { medium: 50 } }` and a project with 30 medium quality findings, **When** scanned, **Then** the gate passes.
2. **Given** the same project and a tightened policy `{ medium: 20 }`, **When** scanned, **Then** the gate fails with a breached threshold showing `actual: 30, threshold: 20`.
3. **Given** the team fixes 15 issues (reducing to 15) and keeps `{ medium: 20 }`, **When** scanned, **Then** the gate passes again.

---

### Edge Cases

- What happens when a quality rule matches inside a test file? Quality findings in test files should be reported normally; teams can use `.atlasignore` patterns to exclude test directories if desired.
- What happens when a TODO comment contains a security-related keyword? The `todo-comment` rule detects all TODO/FIXME comments regardless of content; security implications are detected by separate security rules.
- What happens when `console.log` is used inside a debug utility module? It is still flagged — suppression via inline annotation or `.atlasignore` is the correct mechanism.
- What happens when a language file has syntax errors that prevent tree-sitter parsing? The existing behavior applies: the file is skipped with a warning, and quality rules for other valid files still produce findings.
- What happens when both a security finding and a quality finding exist on the same line? Both findings are produced independently with their respective categories. They do not interfere with each other.

## Quality Rule Catalog

### Naming Convention

All quality rules follow the pattern: `atlas/quality/{language}/{rule-name}`

### Quality vs. Security Differentiation

| Aspect | Security Rules | Quality Rules |
|--------|---------------|---------------|
| `category` field | `security` | `quality` |
| `cwe_id` | Present (e.g., `CWE-89`) | `null` |
| Severity range | Typically Critical / High | Typically Medium / Low / Info |
| SARIF `level` mapping | Typically `error` | Typically `warning` / `note` |
| Gate behavior | Zero-tolerance recommended | Gradual improvement recommended |
| `tags` examples | `owasp-top-10`, `injection` | `code-quality`, `error-handling` |
| `metadata` keys | `source`, `sink` | `quality_domain` |

### TypeScript / JavaScript (10 rules)

| # | Rule ID | Name | Severity | Confidence | Priority |
|---|---------|------|----------|------------|----------|
| 1 | `atlas/quality/typescript/empty-catch-block` | Empty catch block | Medium | High | P1 |
| 2 | `atlas/quality/typescript/console-log` | console.log residual | Low | High | P1 |
| 3 | `atlas/quality/typescript/any-type-usage` | TypeScript `any` type annotation | Low | High | P1 |
| 4 | `atlas/quality/typescript/loose-equality` | `==` instead of `===` | Medium | High | P1 |
| 5 | `atlas/quality/typescript/var-declaration` | `var` instead of `let`/`const` | Low | High | P1 |
| 6 | `atlas/quality/typescript/non-null-assertion` | Non-null assertion `!` abuse | Info | Medium | P2 |
| 7 | `atlas/quality/typescript/todo-comment` | TODO / FIXME comment | Info | High | P2 |
| 8 | `atlas/quality/typescript/empty-function-body` | Empty function body | Low | Medium | P2 |
| 9 | `atlas/quality/typescript/redundant-boolean` | Redundant boolean comparison | Low | High | P2 |
| 10 | `atlas/quality/typescript/excessive-parameters` | More than 5 function parameters | Medium | High | P2 |

### Java (7 rules)

| # | Rule ID | Name | Severity | Confidence | Priority |
|---|---------|------|----------|------------|----------|
| 1 | `atlas/quality/java/empty-catch-block` | Empty catch block | Medium | High | P1 |
| 2 | `atlas/quality/java/system-out-println` | System.out.println residual | Low | High | P1 |
| 3 | `atlas/quality/java/todo-comment` | TODO / FIXME comment | Info | High | P2 |
| 4 | `atlas/quality/java/empty-method-body` | Empty method body | Low | Medium | P2 |
| 5 | `atlas/quality/java/redundant-boolean` | Redundant boolean comparison | Low | High | P2 |
| 6 | `atlas/quality/java/string-concat-in-loop` | String concatenation in loop | Medium | High | P2 |
| 7 | `atlas/quality/java/raw-type-usage` | Raw generic type usage | Low | Medium | P3 |

### Python (7 rules)

| # | Rule ID | Name | Severity | Confidence | Priority |
|---|---------|------|----------|------------|----------|
| 1 | `atlas/quality/python/bare-except` | Bare `except:` clause | Medium | High | P1 |
| 2 | `atlas/quality/python/print-statement` | `print()` residual | Low | High | P1 |
| 3 | `atlas/quality/python/pass-in-except` | `except` with only `pass` | Medium | High | P1 |
| 4 | `atlas/quality/python/mutable-default-arg` | Mutable default argument | Medium | High | P1 |
| 5 | `atlas/quality/python/todo-comment` | TODO / FIXME comment | Info | High | P2 |
| 6 | `atlas/quality/python/empty-function-body` | Empty function body (only `pass`) | Low | Medium | P2 |
| 7 | `atlas/quality/python/magic-number` | Magic number literal | Low | Low | P3 |

### Go (6 rules)

| # | Rule ID | Name | Severity | Confidence | Priority |
|---|---------|------|----------|------------|----------|
| 1 | `atlas/quality/go/empty-error-check` | Empty error check (`if err != nil {}`) | Medium | High | P1 |
| 2 | `atlas/quality/go/fmt-println` | `fmt.Println` residual | Low | High | P1 |
| 3 | `atlas/quality/go/defer-in-loop` | `defer` inside a loop | Medium | High | P1 |
| 4 | `atlas/quality/go/unchecked-error` | Unchecked error return value | High | Medium | P2 |
| 5 | `atlas/quality/go/todo-comment` | TODO / FIXME comment | Info | High | P2 |
| 6 | `atlas/quality/go/empty-function-body` | Empty function body | Low | Medium | P2 |

### C# (6 rules)

| # | Rule ID | Name | Severity | Confidence | Priority |
|---|---------|------|----------|------------|----------|
| 1 | `atlas/quality/csharp/empty-catch-block` | Empty catch block | Medium | High | P1 |
| 2 | `atlas/quality/csharp/console-writeline` | `Console.WriteLine` residual | Low | High | P1 |
| 3 | `atlas/quality/csharp/todo-comment` | TODO / FIXME comment | Info | High | P2 |
| 4 | `atlas/quality/csharp/empty-method-body` | Empty method body | Low | Medium | P2 |
| 5 | `atlas/quality/csharp/redundant-boolean` | Redundant boolean comparison | Low | High | P2 |
| 6 | `atlas/quality/csharp/object-type-usage` | `object` instead of generics | Low | Low | P3 |

**Rule Statistics**: P1 = 16 / P2 = 17 / P3 = 3 / Total = 36

## Quality Gate Strategy

### Recommended Default Policy

```yaml
# Quality-specific gate thresholds (lenient, for gradual adoption)
category_overrides:
  quality:
    critical: 0    # Quality rules rarely produce critical — treat as error
    high: 5        # Allow some high-severity quality issues
    medium: 20     # Lenient medium threshold for initial adoption
    low: null      # No limit on low-severity quality issues
    info: null     # No limit on informational quality issues
```

### Progressive Tightening Schedule (Recommended)

| Quarter | `high` | `medium` | Goal |
|---------|--------|----------|------|
| Q1 (Adoption) | 10 | 50 | Establish baseline, fix critical patterns |
| Q2 (Improvement) | 5 | 20 | Systematic reduction |
| Q3 (Maturity) | 2 | 10 | Near-zero for new code |
| Q4 (Strict) | 0 | 5 | Production-ready quality bar |

## Requirements *(mandatory)*

### Functional Requirements

**Quality Rule Engine Integration**

- **FR-Q01**: Each quality rule MUST be defined as a YAML file in `rules/builtin/{language}/` following the existing declarative rule schema, with `category: quality` and no `cwe_id` field.
- **FR-Q02**: Quality findings produced by the L1 engine MUST have `category: "quality"` in the Finding model, distinguishing them from security and secrets findings.
- **FR-Q03**: Quality findings MUST have `cwe_id: null` in all output formats (JSON, SARIF, JSONL).

**Policy & Gate Integration**

- **FR-Q04**: Quality findings MUST participate in `category_overrides.quality` gate evaluation as defined in the existing gate engine (`crates/atlas-policy/src/gate.rs`).
- **FR-Q05**: When no `category_overrides.quality` is configured, quality findings MUST fall back to global `fail_on` / `warn_on` thresholds (existing behavior).
- **FR-Q06**: Quality and security gate evaluations MUST be independent — a quality gate breach does not affect security gate evaluation and vice versa.

**Baseline & Suppression**

- **FR-Q07**: Quality findings MUST be included in baseline files and MUST be matchable by fingerprint across scans (same fingerprint stability guarantees as security findings).
- **FR-Q08**: Quality findings MUST support the same suppression mechanisms as security findings (inline annotations and policy-level suppression).

**Reporting**

- **FR-Q09**: Quality findings in SARIF output MUST use `level: "warning"` for Medium severity and `level: "note"` for Low/Info severity (not `level: "error"` which is reserved for High+ security findings).
- **FR-Q10**: Quality findings MUST include a `quality_domain` key in the `metadata` field identifying the quality domain (e.g., `"error-handling"`, `"debug-residual"`, `"type-safety"`).

**Rule Metadata**

- **FR-Q11**: Each quality rule MUST include `tags` with at least `code-quality` and one domain-specific tag (e.g., `error-handling`, `debug-residual`, `type-safety`, `best-practices`).
- **FR-Q12**: Each quality rule MUST specify a `confidence` level (High, Medium, or Low) reflecting the likelihood that a match is a true positive.
- **FR-Q13**: Each quality rule MUST include a `remediation` field with actionable guidance on how to fix the detected issue.

**Non-Regression**

- **FR-Q14**: Adding quality rules MUST NOT modify any existing Rust source code in the engine, analysis, or policy crates — only new YAML rule files and test fixtures are added.
- **FR-Q15**: All 27 existing security rules and 6 existing secrets rules MUST continue to pass their test fixtures without modification.

### Key Entities

- **Quality Finding**: A detected code quality issue. Identical structure to security findings but with `category: "quality"`, `cwe_id: null`, and `metadata.quality_domain` identifying the quality domain. Uses the same fingerprinting algorithm for baseline stability.
- **Quality Rule**: A declarative YAML rule with `category: quality`. Identical schema to security rules except: no `cwe_id` field, references point to best-practice guides instead of CWE/OWASP, and tags include `code-quality`.
- **Quality Domain**: A classification of quality issues into functional groups: `error-handling`, `debug-residual`, `type-safety`, `best-practices`, `performance`, `maintainability`. Used for filtering and reporting.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-Q01**: 100% of the 36 quality rules pass their corresponding `fail.{ext}` and `pass.{ext}` test fixtures with zero false negatives on fail fixtures and zero false positives on pass fixtures.
- **SC-Q02**: Quality findings are fully separated from security findings — running a scan on a mixed project produces findings with correct `category` values, and quality findings never appear with `cwe_id` values.
- **SC-Q03**: All 27 existing security rules and 6 existing secrets rules continue to pass their test fixtures (zero regression).
- **SC-Q04**: `category_overrides.quality` in a policy YAML correctly gates quality findings independently — a policy with `quality: { medium: 0 }` fails when medium quality findings exist, even if security findings pass.
- **SC-Q05**: Quality finding fingerprints remain stable across consecutive scans of unchanged code (same fingerprint = same finding).
- **SC-Q06**: A full scan of a 100,000-line polyglot project with all 63 rules (27 security + 6 secrets + 36 quality) completes within 40 seconds on a 4-core machine (< 30% increase over the 30-second baseline with 33 rules).
- **SC-Q07**: P1 quality rules achieve < 10% false positive rate when tested against 5 mainstream open-source projects (e.g., expressjs/express, spring-projects/spring-boot, pallets/flask, gin-gonic/gin, dotnet/aspnetcore).

## Assumptions

- Tree-sitter grammars for all 5 target languages (TypeScript, Java, Python, Go, C#) produce consistent AST node types for the patterns targeted by quality rules.
- The L1 pattern engine handles `#match?` regex predicates and basic tree-sitter query features (alternation, field names, wildcards) as needed by quality rules.
- The existing YAML rule schema supports all fields needed for quality rules (no schema extension required — `cwe_id` is already optional).
- Quality rules are simple enough to express as single-pattern L1 queries without requiring L2 data flow or cross-function analysis.

## Scope Boundaries

**In Scope**:
- 36 declarative YAML quality rules across TypeScript, Java, Python, Go, and C#
- 72 test fixtures (fail + pass for each rule)
- Tree-sitter S-expression pattern research for each rule
- Quality metadata schema definition (`quality_domain` in finding metadata)
- Quality gate policy recommendations and examples
- SARIF level mapping for quality severity levels

**Out of Scope**:
- `--category` CLI filter flag (separate engine enhancement)
- L2 complexity metrics (cyclomatic, cognitive complexity — requires AST traversal counters, not pattern matching)
- Naming convention rules (requires configurable regex patterns per project)
- Unused import detection (requires L2 scope analysis)
- Unreachable code detection (requires L2 control flow graph)
- Code duplication detection (requires L3 cross-file analysis)
- File-level or function-level metrics aggregation framework
- `FindingsSummary.by_category` report field (separate enhancement)
- Custom quality rule authoring documentation

## Implementation Notes

### Files to Create (per rule)

| File | Purpose |
|------|---------|
| `rules/builtin/{language}/{rule-name}.yaml` | Rule definition with tree-sitter pattern |
| `rules/builtin/{language}/tests/{rule-name}/fail.{ext}` | Source file that MUST trigger the rule |
| `rules/builtin/{language}/tests/{rule-name}/pass.{ext}` | Source file that MUST NOT trigger the rule |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-rules/src/declarative.rs` | Update rule count assertions in `load_builtin_{lang}_rules_from_disk()` tests |

### Files NOT Modified

| File | Reason |
|------|--------|
| `crates/atlas-rules/src/lib.rs` | `Category::Quality` already exists |
| `crates/atlas-analysis/src/finding.rs` | Finding model already supports `category: quality` and optional `cwe_id` |
| `crates/atlas-analysis/src/l1_pattern.rs` | L1 engine is category-agnostic |
| `crates/atlas-core/src/engine.rs` | Auto-loads all YAML rules from `rules/builtin/` |
| `crates/atlas-policy/src/gate.rs` | Already supports `category_overrides.quality` |

### Total Deliverables

| Type | Count |
|------|-------|
| YAML rule files | 36 |
| Fail test fixtures | 36 |
| Pass test fixtures | 36 |
| Test assertion updates | 5 (one per language) |
| **Total files created** | **108** |
| **Total files modified** | **1** |

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `specs/002-code-quality-analysis/research.md` | Tree-sitter AST pattern research |
| `specs/002-code-quality-analysis/data-model.md` | Quality metadata schema |
| [SonarQube Rules](https://rules.sonarsource.com/) | Industry reference for quality rules |
| [ESLint Rules](https://eslint.org/docs/latest/rules/) | TypeScript/JavaScript quality rules reference |
| [Pylint Messages](https://pylint.readthedocs.io/en/stable/user_guide/messages/) | Python quality rules reference |
| [go vet](https://pkg.go.dev/cmd/vet) | Go quality rules reference |
| [Roslyn Analyzers](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/) | C# quality rules reference |
