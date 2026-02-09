# Feature Specification: Atlas Local — L2 Data Flow Analysis

**Feature Branch**: `005-l2-data-flow-analysis`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, L1 pattern engine, analysis levels, Rhai scripting)

## Overview & Scope

Atlas-Local's L1 engine detects vulnerabilities through syntactic pattern matching (tree-sitter queries). While effective for many bug classes, pattern matching cannot track data flow — it cannot determine whether user input reaches a dangerous sink through variable assignments, function parameters, or conditional branches. This specification activates L2 intra-procedural data flow analysis, enabling Atlas to detect vulnerabilities that require tracking how data flows from sources to sinks within a single function.

**Purpose**: Enable detection of source-to-sink vulnerabilities within function boundaries by building scope graphs, tracking variable definitions and uses, and propagating taint through assignments and function arguments.

**Scope**: Intra-procedural (single-function) data flow analysis. Leverages existing scaffold types (`VarDef`, `VarUse`, `ScopeGraph`, `DataFlowPath`) in the `atlas-analysis` crate. L2 rules are defined using Rhai scripts (existing `RuleType::Scripted`).

**Exclusions** (deferred to future specs):
- Inter-procedural (cross-function) taint tracking (see 011-l3-taint-tracking)
- Cross-file analysis
- Pointer/reference aliasing
- SSA (Static Single Assignment) form or phi-node insertion
- Custom sanitiser definitions by end users (hardcoded sanitiser lists for now)
- Field-sensitive tracking (e.g., `obj.field` treated same as `obj`)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Detects SQL Injection via Variable Assignment (Priority: P1)

A developer writes code where user input is assigned to a variable, which is later used in a SQL query. The L1 engine cannot detect this because the source and sink are on different lines. The L2 engine traces the data flow from `req.body` through the variable to `db.query()` and produces a finding with the full data flow path.

**Why this priority**: Variable-mediated injection is the most common real-world pattern that L1 misses. Without L2, Atlas has a significant detection gap for injection vulnerabilities.

**Independent Test**: Create a TypeScript function where `req.body.username` is assigned to `let name = ...` and then used in `` db.query(`SELECT * FROM users WHERE name = '${name}'`) ``. Verify the L2 engine produces a finding with a data flow path showing the source, intermediate variable, and sink.

**Acceptance Scenarios**:

1. **Given** a function where `let query = "SELECT * FROM users WHERE name = '" + req.body.name + "'"` followed by `db.query(query)`, **When** scanned at L2, **Then** a finding is produced with `analysis_level: "L2"`, `rule_id: "atlas/security/*/l2-sql-injection"`, and `metadata.data_flow` containing steps: [source: `req.body.name`, assign: `query`, sink: `db.query(query)`].
2. **Given** the same pattern but with a parameterised query (`db.query("SELECT ...", [name])`), **When** scanned at L2, **Then** no finding is produced (parameterised queries are recognised as safe sinks).
3. **Given** a function where user input is assigned but never reaches a dangerous sink, **When** scanned at L2, **Then** no finding is produced.

---

### User Story 2 — Security Engineer Runs L2 Analysis on Demand (Priority: P1)

A security engineer suspects deeper vulnerabilities exist beyond L1 patterns. They run `atlas scan --analysis-level L2 ./src` to enable data flow analysis. L2 analysis runs in addition to L1 (not replacing it), and the report clearly distinguishes L1 and L2 findings.

**Why this priority**: Opt-in L2 analysis prevents performance overhead for users who only need pattern matching, while giving security engineers deeper analysis when needed.

**Independent Test**: Run the same project at L1 and L2, compare findings, and verify L2 produces additional findings that L1 missed, all marked with `analysis_level: "L2"`.

**Acceptance Scenarios**:

1. **Given** a project scanned at L1, **When** the same project is scanned at `--analysis-level L2`, **Then** all L1 findings are still present plus additional L2-only findings.
2. **Given** L2 analysis is enabled, **When** the scan completes, **Then** L2 findings have `analysis_level: "L2"` and L1 findings have `analysis_level: "L1"`.
3. **Given** `--analysis-level L1` (default), **When** the scan runs, **Then** no L2 analysis is performed and no L2 findings are produced.

---

### User Story 3 — Developer Sees Data Flow Path in Finding (Priority: P2)

A developer receives an L2 finding and wants to understand how user input reaches the dangerous sink. The finding metadata includes a `data_flow` array showing each step in the data flow path with file, line, and description.

**Why this priority**: Actionable findings require developers to understand the flow. Without the path, L2 findings are no more useful than L1 findings.

**Independent Test**: Produce an L2 finding with a 3-step data flow (source → variable → sink) and verify the `metadata.data_flow` array contains all 3 steps with correct line numbers.

**Acceptance Scenarios**:

1. **Given** an L2 SQL injection finding, **When** the finding metadata is inspected, **Then** `metadata.data_flow` is an array of step objects, each with `type` (source/propagation/sink), `line`, `column`, `expression`, and `description`.
2. **Given** a data flow path with 5 intermediate steps, **When** serialised to JSON, **Then** all steps are preserved in order from source to sink.

---

### User Story 4 — CI Pipeline Uses L2 for High-Risk Directories (Priority: P2)

A DevSecOps engineer configures CI to run L2 analysis only on high-risk directories (e.g., `src/api/`, `src/auth/`) while using L1 for the rest of the project, balancing thoroughness with scan speed.

**Why this priority**: L2 analysis is more expensive than L1. Selective application is needed for practical CI integration.

**Independent Test**: Configure an Atlas policy that enables L2 for specific paths, scan a project, and verify L2 runs only for matching paths while L1 covers everything.

**Acceptance Scenarios**:

1. **Given** a configuration with `analysis_level: L2` and `l2_paths: ["src/api/**", "src/auth/**"]`, **When** scanned, **Then** L2 analysis runs on files in those directories and L1 analysis runs on all files.
2. **Given** `--analysis-level L2` without path restrictions, **When** scanned, **Then** L2 analysis runs on all files.

---

### Edge Cases

- What happens when a function has no taint sources? L2 analysis produces no findings for that function (no source, no flow).
- What happens when a variable is reassigned multiple times? The most recent assignment overwrites the taint state. `let x = req.body; x = "safe";` clears the taint on `x`.
- What happens in try/catch blocks? Data flow analysis is path-insensitive (all paths are considered reachable). A tainted variable inside a catch block is still tainted.
- What happens with destructuring assignments? `const { name } = req.body` propagates taint to `name` as if `name = req.body.name`.
- What happens with closures/arrow functions? Closures within the same function are analysed. Closures returned or passed to other functions are treated as function boundaries (L3 territory).

## Requirements *(mandatory)*

### Functional Requirements

**Scope Graph Construction**

- **FR-L201**: For each function in a scanned file, the L2 engine MUST build a `ScopeGraph` from the tree-sitter AST, tracking variable definitions (`VarDef`) and variable uses (`VarUse`).
- **FR-L202**: The scope graph MUST support lexical scoping (block scope for `let`/`const`, function scope for `var` in JS/TS, method scope for Java/C#).
- **FR-L203**: The scope graph MUST resolve variable references to their definitions using reaching-definitions analysis.

**Taint Source/Sink Configuration**

- **FR-L204**: Taint sources MUST be configurable per language as a list of patterns (e.g., `req.body`, `req.params`, `req.query` for TypeScript; `request.getParameter` for Java).
- **FR-L205**: Taint sinks MUST be configurable per language as a list of function names and argument positions (e.g., `db.query(arg0)` — argument 0 is the query string).
- **FR-L206**: Taint sanitisers MUST be configurable as functions that clear taint (e.g., `escapeHtml()`, `parseInt()`, parameterised query binding).
- **FR-L207**: Source/sink/sanitiser configurations MUST be shipped as embedded YAML files, one per language.

**Taint Propagation**

- **FR-L208**: Taint MUST propagate through: direct assignment (`let x = tainted`), string concatenation (`tainted + "str"`), template literals (`` `${tainted}` ``), and function argument passing.
- **FR-L209**: Taint MUST be cleared when a variable is reassigned to a non-tainted value or passes through a sanitiser.
- **FR-L210**: The taint engine MUST use a reaching-definitions worklist algorithm, iterating until a fixed point is reached.

**L2 Rule Definition**

- **FR-L211**: L2 rules MUST be defined as Rhai scripts using the existing `RuleType::Scripted` mechanism.
- **FR-L212**: At least 5 L2 rules MUST be implemented: SQL injection, XSS, command injection, path traversal, and SSRF.
- **FR-L213**: Each L2 rule MUST specify its source patterns, sink patterns, and sanitiser patterns.

**Finding Output**

- **FR-L214**: L2 findings MUST include `analysis_level: "L2"` to distinguish them from L1 findings.
- **FR-L215**: L2 findings MUST include `metadata.data_flow` as an ordered array of flow steps from source to sink.
- **FR-L216**: Each flow step MUST include: `type` (source/propagation/sink), `line`, `column`, `expression`, and `description`.

**Engine Integration**

- **FR-L217**: L2 analysis MUST be opt-in via `--analysis-level L2` flag. The default MUST remain L1.
- **FR-L218**: L2 analysis MUST run after L1 analysis. L1 findings are always produced; L2 findings are additive.
- **FR-L219**: L2 analysis SHOULD support path-scoped execution via `l2_paths` configuration to limit performance impact.

### Key Entities

- **VarDef** (extended): A variable definition in the scope graph. Key attributes: `name`, `scope_id`, `line`, `taint_state` (tainted/clean/unknown).
- **VarUse**: A variable reference/use. Key attributes: `name`, `scope_id`, `line`, `resolved_def`.
- **ScopeGraph** (extended): A tree of scopes within a function. Key attributes: `scopes[]`, `var_defs[]`, `var_uses[]`, `parent_scope`.
- **TaintSource**: A pattern that introduces taint. Key attributes: `pattern`, `language`, `label`.
- **TaintSink**: A dangerous function that should not receive tainted data. Key attributes: `function_pattern`, `tainted_arg_positions[]`, `language`, `vulnerability_type`.
- **TaintSanitiser**: A function that removes taint. Key attributes: `function_pattern`, `language`.
- **DataFlowStep**: A single step in a data flow path. Key attributes: `type`, `line`, `column`, `expression`, `description`.
- **L2RuleConfig**: Configuration for an L2 rule. Key attributes: `id`, `sources[]`, `sinks[]`, `sanitisers[]`, `vulnerability_type`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-L201**: L2 engine detects SQL injection via variable assignment in all 5 supported languages with 100% recall on a curated test corpus of 20 test cases.
- **SC-L202**: L2 engine produces zero false positives on parameterised queries / prepared statements across all 5 languages.
- **SC-L203**: At least 5 L2 rules are implemented and pass their test fixtures: SQL injection, XSS, command injection, path traversal, SSRF.
- **SC-L204**: L2 findings include correct `data_flow` metadata showing source → [propagation steps] → sink, verified against 20 manually traced test cases.
- **SC-L205**: L2 analysis of a function with 100 lines completes in < 10ms (scope graph construction + taint propagation).
- **SC-L206**: L2 analysis adds < 50% overhead to total scan time when applied to all files (compared to L1-only scan).
- **SC-L207**: All existing L1 rules and tests pass without modification (zero regression).

## Assumptions

- The existing `VarDef`, `VarUse`, `ScopeGraph`, and `DataFlowPath` scaffold types in `atlas-analysis` provide a usable starting point.
- Rhai scripts can access the scope graph API through the existing scripting bindings.
- Intra-procedural analysis (single function) is sufficient to detect the majority of simple injection patterns. Complex multi-function patterns require L3 (spec 011).
- Tree-sitter ASTs provide sufficient structure to identify variable definitions, assignments, and function calls for all 5 languages.

## Scope Boundaries

**In Scope**:
- Intra-procedural (single-function) data flow analysis
- Scope graph construction from tree-sitter AST
- Reaching-definitions taint propagation
- Configurable source/sink/sanitiser definitions (per language)
- 5 L2 rules (SQL injection, XSS, command injection, path traversal, SSRF)
- `--analysis-level L2` CLI flag
- Data flow path metadata in findings
- Path-scoped L2 analysis configuration

**Out of Scope**:
- Inter-procedural (cross-function) taint tracking (spec 011)
- Cross-file data flow
- Pointer/reference aliasing
- SSA form or phi nodes
- User-defined custom sanitisers (hardcoded lists)
- Field-sensitive tracking (`obj.field` treated as `obj`)
- Control-flow-sensitive analysis (path sensitivity)

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `crates/atlas-analysis/src/l2_builder.rs` | ScopeGraph construction from tree-sitter AST |
| `crates/atlas-analysis/src/l2_engine.rs` | Taint propagation engine (reaching-definitions) |
| `rules/l2/typescript/sources.yaml` | TypeScript taint sources |
| `rules/l2/typescript/sinks.yaml` | TypeScript taint sinks |
| `rules/l2/typescript/sanitisers.yaml` | TypeScript taint sanitisers |
| `rules/l2/{lang}/sources.yaml` | Per-language source configs (×5) |
| `rules/l2/{lang}/sinks.yaml` | Per-language sink configs (×5) |
| `rules/l2/{lang}/sanitisers.yaml` | Per-language sanitiser configs (×5) |
| `rules/l2/rules/l2-sql-injection.rhai` | L2 SQL injection rule |
| `rules/l2/rules/l2-xss.rhai` | L2 XSS rule |
| `rules/l2/rules/l2-command-injection.rhai` | L2 command injection rule |
| `rules/l2/rules/l2-path-traversal.rhai` | L2 path traversal rule |
| `rules/l2/rules/l2-ssrf.rhai` | L2 SSRF rule |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-analysis/src/scope.rs` | Extend existing VarDef/ScopeGraph with taint state |
| `crates/atlas-core/src/engine.rs` | Integrate L2 engine after L1 in scan pipeline |
| `crates/atlas-cli/src/commands/scan.rs` | Add `--analysis-level` flag handling for L2 |
| `crates/atlas-analysis/src/finding.rs` | Ensure data_flow metadata is populated |

### Technical Decision: Reaching-Definitions vs SSA

Using reaching-definitions worklist algorithm instead of SSA because:
1. SSA requires phi-node insertion at control flow merge points — complex for tree-sitter ASTs
2. Reaching-definitions is simpler, well-understood, and sufficient for intra-procedural analysis
3. The performance cost of worklist iteration is negligible for single-function scope
4. If SSA is needed later (for L3), it can be added as an optimisation layer

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `specs/011-l3-taint-tracking/spec.md` | Future inter-procedural extension |
| `crates/atlas-analysis/src/scope.rs` | Existing scope graph scaffold |
| `crates/atlas-analysis/src/data_flow.rs` | Existing data flow path scaffold |
| [Reaching Definitions Analysis](https://en.wikipedia.org/wiki/Reaching_definition) | Algorithm reference |
| [SonarQube Taint Analysis](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/languages/overview/) | Industry reference for taint analysis |
