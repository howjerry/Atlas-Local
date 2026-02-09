# Feature Specification: Atlas Local — Code Quality Metrics

**Feature Branch**: `007-code-quality-metrics`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, tree-sitter AST parsing)

## Overview & Scope

Atlas-Local detects discrete code issues (security vulnerabilities, quality smells) but does not measure aggregate code quality characteristics like complexity, duplication, and size. This specification adds quantitative code metrics — cyclomatic complexity, cognitive complexity, code duplication detection, and lines-of-code statistics — that provide a holistic view of code health beyond individual findings.

**Purpose**: Enable development teams to measure and track code complexity, identify overly complex functions, detect duplicated code blocks, and set thresholds that produce findings when limits are exceeded.

**Scope**: AST-based complexity computation, token-based duplication detection, and LOC statistics. Reuses already-parsed tree-sitter ASTs for zero-cost parsing.

**Exclusions** (deferred to future specs):
- Dependency metrics (afferent/efferent coupling — requires cross-module analysis)
- Test coverage metrics (requires runtime instrumentation)
- Churn/change frequency metrics (requires git history analysis beyond diff)
- Halstead metrics (theoretical, limited practical value)
- Maintainability Index (composite metric — can be derived from primitives)
- Metric trend tracking over time (requires 010 Web Dashboard)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Identifies Overly Complex Functions (Priority: P1)

A developer runs `atlas scan --metrics ./src` and the report includes per-function cyclomatic and cognitive complexity scores. Functions exceeding configurable thresholds produce findings with severity proportional to how far they exceed the threshold.

**Why this priority**: Complexity is the single most impactful code metric for maintainability. Functions with high complexity are statistically more likely to contain bugs and be harder to modify.

**Independent Test**: Create a file with functions of known complexity (simple function = 1, function with 5 if/else branches = 6, deeply nested function = high cognitive), run with `--metrics`, and verify computed scores match expected values.

**Acceptance Scenarios**:

1. **Given** a function with 3 if statements, 1 for loop, and 1 while loop, **When** scanned with `--metrics`, **Then** the cyclomatic complexity is 6 (1 base + 5 decision points) and a `complexity` metric is reported for this function.
2. **Given** a function with deeply nested if/for/while (4 levels deep), **When** cognitive complexity is computed, **Then** the score reflects nesting penalties (each nesting level adds an increment to the penalty) and is higher than the cyclomatic score.
3. **Given** a threshold of `cyclomatic_max: 10`, **When** a function has cyclomatic complexity 15, **Then** a finding is produced with `rule_id: "atlas/metrics/*/cyclomatic-complexity"`, `severity: "medium"`, and `metadata.complexity: 15`.

---

### User Story 2 — Team Detects Copy-Paste Code (Priority: P1)

A team lead wants to identify duplicated code blocks that increase maintenance burden. They run `atlas scan --metrics ./src` and the report lists duplicated token sequences of 100+ tokens with their locations, enabling targeted refactoring.

**Why this priority**: Code duplication is a primary driver of maintenance cost and inconsistency bugs. Detecting it early enables refactoring before it compounds.

**Independent Test**: Create two files with an identical 120-token function body. Run with `--metrics` and verify the duplication is detected with both file locations reported.

**Acceptance Scenarios**:

1. **Given** two files containing identical 150-token code blocks, **When** scanned with `--metrics`, **Then** a duplication finding is produced listing both locations and the duplicated token count.
2. **Given** code blocks that differ only in variable names (Type II clones), **When** scanned, **Then** they are detected as duplicates (token-based comparison normalises identifiers).
3. **Given** a duplication threshold of `min_tokens: 100`, **When** a 90-token block is duplicated, **Then** no finding is produced.

---

### User Story 3 — CI Pipeline Enforces Complexity Limits (Priority: P2)

A DevSecOps engineer configures CI to fail if any function exceeds a cyclomatic complexity of 20 or cognitive complexity of 30. This is enforced through the existing policy gate mechanism using `category_overrides.metrics`.

**Why this priority**: Enforcement in CI prevents complexity from accumulating, but requires the metrics engine (US1) to work first.

**Independent Test**: Set complexity thresholds in policy, scan a project with a function exceeding the threshold, and verify the gate fails.

**Acceptance Scenarios**:

1. **Given** a policy with `category_overrides: { metrics: { medium: 0 } }`, **When** a scan produces a cyclomatic complexity finding (medium severity), **Then** the gate fails.
2. **Given** `--metrics` is not specified, **When** a scan runs, **Then** no metrics findings are produced and the gate evaluates only security/quality findings.

---

### User Story 4 — Manager Reviews Project LOC Statistics (Priority: P2)

A project manager wants an overview of project size (total lines of code, lines per language, average function size). They run `atlas scan --metrics ./src` and the report includes a `metrics` section with project-level aggregates.

**Why this priority**: LOC statistics provide context for other metrics (e.g., duplication percentage is meaningful only relative to total LOC). However, LOC alone drives no actionable changes.

**Independent Test**: Scan a multi-language project and verify the `metrics` section reports total LOC, LOC per language, file count, and average function length.

**Acceptance Scenarios**:

1. **Given** a project with TypeScript (5000 LOC), Java (3000 LOC), and Python (2000 LOC), **When** scanned with `--metrics`, **Then** the report includes `metrics.project.total_loc: 10000` and per-language breakdowns.
2. **Given** a project with 50 functions, **When** scanned, **Then** `metrics.project.avg_function_loc` is computed as total function LOC / 50.

---

### Edge Cases

- What happens when a function has unreachable code after a return? All branches are counted for cyclomatic complexity (same as other tools — complexity measures code structure, not execution paths).
- What happens with switch/case statements? Each `case` adds 1 to cyclomatic complexity. Fall-through does not add extra complexity.
- What happens with ternary operators? Each ternary (`? :`) adds 1 to cyclomatic and cognitive complexity.
- What happens when duplication spans multiple functions? The duplication detector works at the token level, not the AST level. Cross-function token sequences are detected.
- What happens with generated code (e.g., protobuf output)? Generated files are scanned unless excluded via `.atlasignore`. Teams should exclude generated directories.

## Requirements *(mandatory)*

### Functional Requirements

**Cyclomatic Complexity**

- **FR-M01**: The metrics engine MUST compute McCabe cyclomatic complexity for every function/method in scanned files.
- **FR-M02**: Cyclomatic complexity MUST count: `if`, `else if`/`elif`, `for`, `while`, `do-while`, `case`, `catch`, `&&`, `||`, and ternary `? :` operators. The base complexity is 1.
- **FR-M03**: Functions exceeding the configurable `cyclomatic_max` threshold (default: 15) MUST produce a finding with `category: "metrics"`, `severity: "medium"`, and `metadata.cyclomatic_complexity` containing the score.

**Cognitive Complexity**

- **FR-M04**: The metrics engine MUST compute cognitive complexity following the SonarSource specification (structural increment + nesting penalty).
- **FR-M05**: Cognitive complexity increments MUST include: `if`, `else if`, `else`, `for`, `while`, `catch`, `switch`, `&&`, `||`, ternary, and recursion. Each nesting level adds +1 to the increment.
- **FR-M06**: Functions exceeding the configurable `cognitive_max` threshold (default: 25) MUST produce a finding with `severity: "medium"` and `metadata.cognitive_complexity` containing the score.

**Code Duplication**

- **FR-M07**: The duplication detector MUST use token-based comparison with identifier normalisation (Type I + Type II clones).
- **FR-M08**: Duplicated blocks MUST be at least `min_tokens` tokens long (default: 100).
- **FR-M09**: Each duplicate pair MUST produce a finding with `severity: "low"` listing both locations and the duplicated token count.
- **FR-M10**: The duplication percentage MUST be reported at the project level: `(duplicated_lines / total_lines) * 100`.

**LOC Statistics**

- **FR-M11**: The metrics engine MUST compute: total lines, code lines (excluding blanks and comments), blank lines, and comment lines per file and per project.
- **FR-M12**: Per-language LOC breakdowns MUST be included in the project metrics.

**Metrics Reporting**

- **FR-M13**: A `metrics` section MUST be added to JSON reports containing: per-function metrics, per-file metrics, and project-level aggregates.
- **FR-M14**: Metrics computation MUST be opt-in via `--metrics` flag. Default scans MUST NOT compute metrics.
- **FR-M15**: Metrics findings (complexity/duplication above thresholds) MUST participate in gate evaluation under `category_overrides.metrics`.

**Performance**

- **FR-M16**: Metrics computation MUST reuse already-parsed tree-sitter ASTs from the L1 scan pass. No files should be re-parsed.
- **FR-M17**: Metrics computation for a 100,000-line project MUST complete in < 10 seconds (excluding AST parse time).

### Key Entities

- **FunctionMetrics**: Per-function metrics. Key attributes: `name`, `file_path`, `start_line`, `end_line`, `loc`, `cyclomatic_complexity`, `cognitive_complexity`, `parameter_count`.
- **FileMetrics**: Per-file metrics. Key attributes: `path`, `total_lines`, `code_lines`, `blank_lines`, `comment_lines`, `functions[]`, `max_cyclomatic`, `max_cognitive`.
- **ProjectMetrics**: Project-level aggregates. Key attributes: `total_files`, `total_loc`, `loc_by_language`, `avg_function_loc`, `duplication_percentage`, `duplicate_blocks[]`.
- **DuplicationBlock**: A pair of duplicated code regions. Key attributes: `file_a`, `line_range_a`, `file_b`, `line_range_b`, `token_count`, `line_count`.
- **MetricsConfig**: Configuration for metrics thresholds. Key attributes: `cyclomatic_max`, `cognitive_max`, `min_tokens`, `enabled`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-M01**: Cyclomatic complexity scores match manual calculation on a test corpus of 20 functions across 5 languages, with 100% accuracy.
- **SC-M02**: Cognitive complexity scores match the SonarSource reference implementation on a test corpus of 20 functions, with no more than 5% deviation.
- **SC-M03**: Duplication detection identifies 100% of Type I clones (exact duplicates) and at least 90% of Type II clones (variable-renamed duplicates) in a 50-case test corpus.
- **SC-M04**: Complexity findings are produced for functions exceeding thresholds, with correct severity and metadata.
- **SC-M05**: Metrics computation for a 100,000-line project completes in < 10 seconds (reusing parsed ASTs).
- **SC-M06**: LOC statistics match `wc -l` for total lines and manual counts for code/blank/comment lines on a 10-file test corpus.
- **SC-M07**: All existing scan, gate, and report tests pass without modification (zero regression).

## Assumptions

- Tree-sitter ASTs provide sufficient structure to identify all decision points for complexity computation (if/for/while/switch/catch nodes exist in all 5 language grammars).
- Token-based duplication detection is sufficient for practical use. AST-based (Type III) clone detection is out of scope.
- The SonarSource cognitive complexity specification is the industry standard and is publicly documented.
- Metrics computation is CPU-bound (AST traversal) and benefits from rayon parallelism across files.

## Scope Boundaries

**In Scope**:
- Cyclomatic complexity (McCabe) per function
- Cognitive complexity (SonarSource spec) per function
- Token-based code duplication detection (Type I + II)
- LOC statistics (total, code, blank, comment, per language)
- `--metrics` CLI flag
- Metrics findings for threshold violations
- `metrics` section in JSON reports
- `category_overrides.metrics` in policy gate

**Out of Scope**:
- Dependency/coupling metrics
- Test coverage metrics
- Change frequency / churn metrics
- Halstead metrics
- Maintainability Index
- Metric trend tracking (requires 010 Web Dashboard)
- AST-based Type III clone detection

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `crates/atlas-analysis/src/metrics.rs` | Cyclomatic + cognitive complexity computation |
| `crates/atlas-analysis/src/duplication.rs` | Token-based duplication detection |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-rules/src/lib.rs` | Add `Category::Metrics` variant |
| `crates/atlas-core/src/engine.rs` | Integrate metrics computation after L1 scan |
| `crates/atlas-cli/src/commands/scan.rs` | Add `--metrics` flag |
| `crates/atlas-report/src/json.rs` | Add `metrics` section to JSON reports |
| `crates/atlas-policy/src/gate.rs` | Support `category_overrides.metrics` |

### Technical Decision: Token-based vs AST-based Duplication

Using token-based comparison because:
1. Token sequences are language-agnostic after lexing (same algorithm for all 5 languages)
2. Identifier normalisation catches Type II clones (renamed variables)
3. Rabin-Karp rolling hash makes O(n) comparison feasible for large projects
4. AST-based clone detection (Type III) is significantly more complex and better suited for dedicated tools

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `specs/002-code-quality-analysis/spec.md` | Quality domain reference |
| [McCabe Cyclomatic Complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) | Algorithm reference |
| [SonarSource Cognitive Complexity](https://www.sonarsource.com/docs/CognitiveComplexity.pdf) | Cognitive complexity specification |
| [PMD CPD](https://pmd.github.io/latest/pmd_userdocs_cpd.html) | Token-based duplication detection reference |
