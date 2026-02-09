# Feature Specification: Atlas Local — L3 Taint Tracking

**Feature Branch**: `011-l3-taint-tracking`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 005-l2-data-flow-analysis (scope graph, taint propagation, reaching-definitions engine)

## Overview & Scope

Atlas-Local's L2 analysis (spec 005) tracks data flow within a single function. However, real-world vulnerabilities often span multiple functions — user input enters in a controller, passes through service methods, and reaches a dangerous sink in a data access layer. L3 taint tracking extends L2 by building a cross-function call graph and propagating taint across function boundaries.

**Purpose**: Enable detection of inter-procedural source-to-sink vulnerabilities by building a call graph from the tree-sitter AST and propagating taint across function calls within a single file or across files in the same project.

**Scope**: Inter-procedural (cross-function, cross-file) taint analysis. Builds on L2's scope graph and taint propagation. Call graph construction from tree-sitter AST. Configurable depth limiting. At least 3 L3 rules.

**Exclusions** (deferred to future specs):
- Dynamic dispatch resolution (virtual methods, interface implementations)
- Reflection-based call resolution
- Third-party library function modelling (only project-internal calls)
- Interprocedural alias analysis
- Concurrency-aware analysis (goroutines, async/await)
- Whole-program analysis (bounded by max_depth)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Security Engineer Detects Cross-Function SQL Injection (Priority: P1)

A security engineer scans a web application where user input from `req.body` in a controller is passed to a `userService.findByName(name)` function, which internally constructs a SQL query using string concatenation. L2 cannot detect this because the source and sink are in different functions. L3 traces the taint across the function call boundary and produces a finding with the complete cross-function data flow path.

**Why this priority**: Cross-function injection is the most common real-world vulnerability pattern that L2 misses. Without L3, Atlas has a significant detection gap for enterprise applications with layered architectures.

**Independent Test**: Create a controller that passes `req.body.name` to a service method that concatenates it into a SQL query. Run at L3 and verify the finding traces taint through the function call.

**Acceptance Scenarios**:

1. **Given** a controller calling `userService.findByName(req.body.name)` and a service method `findByName(name)` that runs `db.query("SELECT * FROM users WHERE name = '" + name + "'")`, **When** scanned at L3, **Then** a finding is produced with `analysis_level: "L3"` and `metadata.data_flow` showing the path: source (req.body.name) → call (findByName) → sink (db.query).
2. **Given** the same pattern but `findByName` uses a parameterised query, **When** scanned at L3, **Then** no finding is produced (sanitised path).
3. **Given** a function call chain deeper than `max_depth` (default 5), **When** scanned at L3, **Then** analysis stops at the depth limit and does not produce findings for deeper paths.

---

### User Story 2 — Analyst Runs L3 on High-Risk Code Paths (Priority: P1)

A security analyst runs `atlas scan --analysis-level L3 ./src` to perform deep taint analysis. L3 runs on top of L1 and L2, producing additional findings that require cross-function tracking. The report clearly distinguishes L1, L2, and L3 findings.

**Why this priority**: L3 is significantly more expensive than L1/L2. Opt-in activation with clear level differentiation is essential for practical use.

**Independent Test**: Run the same project at L1, L2, and L3. Verify that each level produces its findings and L3 findings are additive.

**Acceptance Scenarios**:

1. **Given** `--analysis-level L3`, **When** scanned, **Then** L1 + L2 + L3 findings are all produced, each with the correct `analysis_level`.
2. **Given** `--analysis-level L2`, **When** scanned, **Then** only L1 + L2 findings are produced (no L3).
3. **Given** L3 is enabled, **When** the call graph is built, **Then** the scan completes within the configured depth limit without exponential blowup.

---

### User Story 3 — Developer Reviews Cross-File Taint Path (Priority: P2)

A developer receives an L3 finding that spans 3 files (controller → service → repository). The finding metadata includes a complete taint path with file, function, and line number for each step, enabling them to trace the vulnerability through the codebase.

**Why this priority**: Actionable cross-file findings require detailed path information. Without it, developers cannot verify or fix the issue.

**Independent Test**: Produce an L3 finding spanning 3 files and verify the `metadata.data_flow` array contains steps in all 3 files.

**Acceptance Scenarios**:

1. **Given** an L3 finding spanning `controller.ts`, `service.ts`, and `repository.ts`, **When** the finding metadata is inspected, **Then** `metadata.data_flow` contains steps in all 3 files with correct function names and line numbers.
2. **Given** a taint path with 4 intermediate functions, **When** serialised, **Then** all steps are preserved in order from source to sink.

---

### User Story 4 — Team Configures Custom Sources and Sinks (Priority: P2)

A team using a custom web framework configures additional taint sources (e.g., `ctx.request.body`) and sinks (e.g., `orm.rawQuery()`) in the L3 taint configuration. The L3 engine uses these custom definitions alongside the built-in ones.

**Why this priority**: Enterprise frameworks have non-standard APIs. Custom configuration extends L3's applicability beyond popular frameworks.

**Independent Test**: Add a custom source and sink to the taint configuration, write code using them, and verify L3 detects the taint path.

**Acceptance Scenarios**:

1. **Given** a custom taint config with `source: "ctx.request.body"` and `sink: "orm.rawQuery"`, **When** code uses these patterns, **Then** L3 detects the taint flow.
2. **Given** a custom sanitiser added to the config, **When** the sanitiser is applied in the data flow, **Then** taint is cleared and no finding is produced.

---

### Edge Cases

- What happens with recursive function calls? Recursion is detected via cycle detection in the call graph. Recursive calls are skipped to prevent infinite loops.
- What happens with callbacks/higher-order functions? L3 does not resolve dynamic callback targets. Only statically resolvable function calls are followed.
- What happens when a function is called multiple times? Each call site is analysed independently. If tainted input flows through one call but not another, only the tainted call produces a finding.
- What happens with class method calls? Method calls on known types (e.g., `this.service.method()`) are resolved if the class definition is in the scan scope.
- What happens with cross-language calls? Not supported. L3 only tracks taint within a single language.

## Requirements *(mandatory)*

### Functional Requirements

**Call Graph Construction**

- **FR-T01**: The L3 engine MUST build a call graph from tree-sitter ASTs by resolving function/method call expressions to their definitions.
- **FR-T02**: Call graph resolution MUST support: module-level function calls, class method calls (within the same file), and cross-file function imports/exports.
- **FR-T03**: The call graph MUST be limited to `max_depth` levels (default: 5, configurable) to prevent exponential blowup.
- **FR-T04**: Cycle detection MUST prevent infinite recursion in the call graph traversal.

**Cross-Function Taint Propagation**

- **FR-T05**: When a tainted value is passed as an argument to a function call, the corresponding parameter in the callee MUST be marked as tainted.
- **FR-T06**: When a function returns a tainted value, the variable receiving the return value at the call site MUST be marked as tainted.
- **FR-T07**: Taint propagation across function boundaries MUST use the L2 scope graph for each callee function (scope graph is built on-demand).
- **FR-T08**: Sanitiser functions at any level of the call chain MUST clear taint (a sanitiser between source and sink prevents a finding).

**L3 Rule Definition**

- **FR-T09**: At least 3 L3 rules MUST be implemented: cross-function SQL injection, cross-function XSS, and cross-function command injection.
- **FR-T10**: L3 rules MUST use the same source/sink/sanitiser configuration as L2 rules (shared taint config).
- **FR-T11**: L3 findings MUST include `analysis_level: "L3"`.

**Source/Sink/Sanitiser Configuration**

- **FR-T12**: Taint configuration MUST be loadable from YAML files (extending L2's configuration).
- **FR-T13**: Users MUST be able to add custom sources, sinks, and sanitisers via a project-level `atlas-taint.yaml` file.
- **FR-T14**: Custom taint configuration MUST be merged with the built-in defaults (custom entries add to, not replace, defaults).

**Finding Output**

- **FR-T15**: L3 findings MUST include `metadata.data_flow` as an ordered array of steps spanning multiple files and functions.
- **FR-T16**: Each step in the data flow MUST include: `step_type`, `file`, `function`, `line`, `column`, `expression`, and `description`.
- **FR-T17**: L3 findings MUST include `metadata.call_depth` indicating the number of function call boundaries crossed.

**Performance**

- **FR-T18**: L3 analysis MUST complete within O(n * d) time where n is the number of functions and d is max_depth.
- **FR-T19**: L3 analysis SHOULD support parallel processing of independent call chains via rayon.

### Key Entities

- **CallGraph**: A directed graph of function call relationships. Key attributes: `functions[]`, `edges[]`, `root_functions[]`.
- **CallGraphNode**: A function in the call graph. Key attributes: `name`, `file`, `line`, `parameters`, `return_type`.
- **CallGraphEdge**: A function call relationship. Key attributes: `caller`, `callee`, `call_site_line`, `argument_mapping`.
- **TaintConfig**: User-customisable taint source/sink/sanitiser definitions. Key attributes: `sources[]`, `sinks[]`, `sanitisers[]`, `max_depth`.
- **L3Finding**: An L3 taint tracking finding. Extends `Finding` with cross-function data flow path.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-T01**: L3 engine detects cross-function SQL injection across 2-function call chains in all 5 languages with 100% recall on a curated test corpus of 15 test cases.
- **SC-T02**: L3 engine correctly handles sanitisers in the middle of a call chain (taint cleared), with 100% accuracy on 10 test cases with sanitised paths.
- **SC-T03**: At least 3 L3 rules pass their test fixtures: cross-function SQL injection, XSS, and command injection.
- **SC-T04**: L3 data flow paths correctly identify all files, functions, and line numbers in the taint path, verified against 10 manually traced test cases.
- **SC-T05**: L3 analysis of a project with 500 functions and max_depth=5 completes in < 30 seconds.
- **SC-T06**: Cycle detection prevents infinite loops on recursive call patterns (tested with 5 recursive test cases).
- **SC-T07**: All existing L1 and L2 tests pass without modification (zero regression).

## Assumptions

- L2 scope graph construction (spec 005) is available and produces correct VarDef/VarUse data.
- Tree-sitter ASTs provide sufficient information to resolve static function calls to their definitions.
- Call graph construction does not require type inference — only syntactic name resolution is needed.
- Dynamic dispatch (virtual methods, interface calls) is out of scope. Only statically resolvable calls are tracked.
- Cross-file resolution requires an index of function definitions built during the file discovery phase.

## Scope Boundaries

**In Scope**:
- Call graph construction from tree-sitter ASTs
- Cross-function taint propagation (parameter → argument, return → call site)
- Cross-file function resolution (imports/exports)
- `--analysis-level L3` CLI flag
- Depth-limited traversal (max_depth configurable)
- Cycle detection for recursive calls
- 3 L3 rules (SQL injection, XSS, command injection)
- Custom taint configuration via `atlas-taint.yaml`
- Multi-file data flow paths in findings

**Out of Scope**:
- Dynamic dispatch / virtual method resolution
- Reflection-based call resolution
- Third-party library function modelling
- Alias analysis
- Concurrency-aware taint tracking
- Whole-program analysis (unbounded depth)
- Cross-language taint tracking

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `crates/atlas-analysis/src/call_graph.rs` | Call graph construction from tree-sitter AST |
| `crates/atlas-analysis/src/l3_engine.rs` | Cross-function taint propagation engine |
| `crates/atlas-analysis/src/taint_config.rs` | Taint source/sink/sanitiser config loader |
| `rules/l3/rules/l3-sql-injection.rhai` | L3 SQL injection rule |
| `rules/l3/rules/l3-xss.rhai` | L3 XSS rule |
| `rules/l3/rules/l3-command-injection.rhai` | L3 command injection rule |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-core/src/engine.rs` | Integrate L3 engine after L2 in scan pipeline |
| `crates/atlas-cli/src/commands/scan.rs` | Handle `--analysis-level L3` |

### Technical Decision: Worklist + Depth Limiting

Using a worklist algorithm with depth limiting instead of full context-sensitive analysis because:
1. Context-sensitive analysis is exponential in the worst case
2. Depth limiting (default 5) bounds the analysis to a practical level
3. Most real-world injection vulnerabilities are within 3-4 call levels
4. The worklist approach is well-suited for incremental analysis

## References

| Resource | Purpose |
|----------|---------|
| `specs/005-l2-data-flow-analysis/spec.md` | L2 data flow foundation |
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `crates/atlas-analysis/src/scope.rs` | Existing scope graph types |
| `crates/atlas-analysis/src/data_flow.rs` | Existing data flow path types |
| [FlowDroid](https://github.com/secure-software-engineering/FlowDroid) | Android taint analysis reference |
| [Semgrep Interfile Analysis](https://semgrep.dev/docs/writing-rules/data-flow/interfile-analysis/) | Industry reference for cross-file taint |
