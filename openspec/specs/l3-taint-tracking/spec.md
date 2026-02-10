## ADDED Requirements

### Requirement: Call graph construction from tree-sitter AST
The system SHALL build a directed call graph by traversing tree-sitter ASTs of all scanned files. For each file, the system SHALL extract function definitions (name, parameters, file path, line number) and call sites (callee name, argument expressions, caller function). Function definitions SHALL be registered in a project-wide function index keyed by `file_path::function_name`. Call sites SHALL be resolved to registered function definitions using syntactic name resolution.

#### Scenario: Extract function definitions from single file
- **WHEN** a TypeScript file contains `function handleRequest(req) {}` and `function queryDb(sql) {}`
- **THEN** the call graph contains two `FunctionRef` entries with correct names, file paths, and line numbers

#### Scenario: Extract call sites and resolve to definitions
- **WHEN** `handleRequest` contains `queryDb(userInput)` and `queryDb` is defined in the same file
- **THEN** a `CallSite` edge links `handleRequest` → `queryDb` with argument index mapping `[0 → 0]`

#### Scenario: Unresolvable call site is skipped
- **WHEN** a function calls `externalLib.doSomething()` with no matching definition in the project
- **THEN** the call site is NOT added to the call graph (conservative approach)

#### Scenario: Class method calls resolved within same file
- **WHEN** a class method `this.processData(input)` is called and `processData` is defined in the same class
- **THEN** the call site is resolved to the `processData` method definition

### Requirement: Cross-file import/export resolution
The system SHALL extract import/export declarations from ASTs and build an `ImportIndex` mapping `(file, imported_name)` to `(source_file, exported_name)`. The call graph SHALL use this index to resolve cross-file function calls. V1 SHALL support static import resolution for TypeScript (`import { fn } from './module'`) and Python (`from module import fn`). Java, Go, and C# SHALL support same-file cross-function resolution only.

#### Scenario: TypeScript named import resolved
- **WHEN** `controller.ts` has `import { findUser } from './userService'` and `userService.ts` exports `function findUser(name)`
- **THEN** a call to `findUser(input)` in `controller.ts` resolves to `userService.ts::findUser` in the call graph

#### Scenario: Python from-import resolved
- **WHEN** `views.py` has `from services import process_data` and `services.py` defines `def process_data(data)`
- **THEN** a call to `process_data(user_input)` in `views.py` resolves to `services.py::process_data`

#### Scenario: Dynamic import not resolved
- **WHEN** a file uses dynamic module loading (e.g., runtime require or importlib)
- **THEN** the import is NOT resolved (dynamic imports are out of scope)

#### Scenario: Java same-file method call resolved
- **WHEN** a Java class has methods `handleRequest()` calling `queryDb()` in the same file
- **THEN** the call site is resolved within the same file without cross-file import resolution

### Requirement: Depth-limited call graph traversal
The system SHALL traverse the call graph using BFS with a configurable `max_depth` parameter (default: 5). Traversal SHALL stop at functions that exceed the depth limit. The default `max_depth` SHALL be overridable via the `atlas-taint.yaml` configuration file.

#### Scenario: Traversal within depth limit
- **WHEN** a taint path spans functions A → B → C (depth 2) with max_depth=5
- **THEN** all three functions are analyzed and the taint path is fully resolved

#### Scenario: Traversal stopped at depth limit
- **WHEN** a call chain spans 6 functions with max_depth=5
- **THEN** analysis stops at the 5th function and does not enter the 6th

#### Scenario: Custom max_depth configuration
- **WHEN** `atlas-taint.yaml` contains `max_depth: 3`
- **THEN** the L3 engine uses max_depth=3 instead of the default 5

### Requirement: Cycle detection in call graph
The system SHALL detect recursive and cyclic call patterns using a `visited` set during call graph traversal. When a function is encountered that has already been visited in the current traversal path, it SHALL be skipped to prevent infinite loops.

#### Scenario: Direct recursion detected
- **WHEN** function `factorial(n)` calls itself recursively
- **THEN** the recursive call is skipped after the first visit (no infinite loop)

#### Scenario: Indirect cycle detected
- **WHEN** function A calls B, B calls C, and C calls A
- **THEN** the cycle is detected and the second visit to A is skipped

#### Scenario: Diamond pattern handled correctly
- **WHEN** A calls B and C, both B and C call D
- **THEN** D is analyzed once (first encounter), the second encounter is skipped

### Requirement: Cross-function taint propagation — forward
The system SHALL propagate taint from caller to callee when a tainted value is passed as an argument. The corresponding parameter in the callee function SHALL be marked as `Tainted` in the callee's scope graph. The system SHALL build the callee's scope graph on-demand using the L2 `ScopeGraphBuilder`, then execute reaching-definitions within the callee with the tainted parameter as the initial taint source.

#### Scenario: Tainted argument propagates to callee parameter
- **WHEN** caller passes `userInput` (tainted from `req.body`) as argument 0 to `processData(data)`
- **THEN** the `data` parameter in `processData` is marked as `Tainted` before reaching-definitions runs

#### Scenario: Only tainted arguments propagate
- **WHEN** caller calls `process(taintedInput, "safe_literal")`
- **THEN** only parameter 0 is marked as `Tainted` in the callee; parameter 1 remains `Clean`

#### Scenario: Taint reaches sink in callee
- **WHEN** caller passes tainted data to `queryDb(sql)` and `queryDb` contains `db.execute(sql)`
- **THEN** an L3 finding is produced because taint flows from caller through callee parameter to sink

### Requirement: Cross-function taint propagation — return value
The system SHALL propagate taint from callee to caller when a callee returns a tainted value. After analyzing the callee, if the return expression is tainted, the variable receiving the return value at the call site SHALL be marked as `Tainted` in the caller's scope graph.

#### Scenario: Tainted return value propagates to caller
- **WHEN** `getData()` returns a tainted value and caller has `const result = getData()`
- **THEN** `result` in the caller is marked as `Tainted`

#### Scenario: Clean return value does not propagate taint
- **WHEN** `sanitize(input)` returns a sanitized (clean) value and caller has `const safe = sanitize(input)`
- **THEN** `safe` in the caller is NOT tainted

#### Scenario: Return value taint reaches sink in caller
- **WHEN** caller has `const data = getUnsafeInput(); db.query(data)`
- **THEN** an L3 finding is produced tracing taint through the return value to the sink

### Requirement: Sanitizer support across call boundaries
The system SHALL recognize sanitizer functions at any level of the call chain. When a tainted value passes through a configured sanitizer function (either as a direct call or within a callee), the taint SHALL be cleared and no finding SHALL be produced for paths that include the sanitizer.

#### Scenario: Sanitizer in intermediate callee clears taint
- **WHEN** call chain is `controller(input) → validate(input) → queryDb(input)` and `validate` calls `escapeHtml(input)` before returning
- **THEN** no L3 finding is produced because taint is cleared by the sanitizer

#### Scenario: Sanitizer at call boundary
- **WHEN** caller calls `db.query(parseInt(userInput))`
- **THEN** no finding is produced because `parseInt` sanitizes the tainted input before the sink

### Requirement: Three L3 security rules
The system SHALL implement at least 3 L3 detection rules driven by the L2 taint configuration:

1. **l3-sql-injection** (CWE-89, Severity: Critical): Cross-function tainted data reaching SQL query sinks
2. **l3-xss** (CWE-79, Severity: High): Cross-function tainted data reaching HTML output sinks
3. **l3-command-injection** (CWE-78, Severity: Critical): Cross-function tainted data reaching OS command execution sinks

Rule IDs SHALL follow the format `atlas/security/{lang}/l3-{vulnerability}`.

#### Scenario: L3 SQL injection detected across two functions
- **WHEN** `controller` passes `req.body.name` to `service.findByName(name)` which calls `db.query("SELECT ... " + name)`
- **THEN** a finding with rule ID `atlas/security/typescript/l3-sql-injection` and CWE-89 is produced

#### Scenario: L3 XSS detected across two functions
- **WHEN** `handler` passes user input to `render(data)` which calls `res.send(data)`
- **THEN** a finding with rule ID containing `l3-xss` and CWE-79 is produced

#### Scenario: L3 command injection detected across two functions
- **WHEN** `api` passes user input to `runCommand(cmd)` which calls a command execution function with `cmd`
- **THEN** a finding with rule ID containing `l3-command-injection` and CWE-78 is produced

#### Scenario: L3 rules use same taint config as L2
- **WHEN** the L3 engine initializes for a language
- **THEN** it loads the same `taint_config.yaml` used by L2 for that language

### Requirement: L3 finding data flow path
Each L3 finding SHALL include `metadata.data_flow` as an ordered array of steps spanning multiple files and functions. Each step SHALL contain `step_type` (source/propagation/call/return/sink), `file`, `function`, `line`, `column`, `expression`, and `description`. L3 findings SHALL also include `metadata.call_depth` indicating the number of function call boundaries crossed.

#### Scenario: Cross-function data flow path with two functions
- **WHEN** an L3 finding traces taint from `controller.ts:handleRequest` through `service.ts:findUser` to a sink
- **THEN** `metadata.data_flow` contains steps in both files with `call` step types at function boundaries and correct function names

#### Scenario: Call depth metadata is correct
- **WHEN** an L3 finding spans 3 function calls (depth 3)
- **THEN** `metadata.call_depth` equals 3

#### Scenario: Data flow steps are ordered source to sink
- **WHEN** an L3 finding is serialized
- **THEN** `metadata.data_flow` steps are ordered chronologically from the taint source to the final sink

### Requirement: L3 finding analysis level
All L3 findings SHALL include `analysis_level: "L3"` to distinguish them from L1 and L2 findings. L3 findings SHALL have `confidence: Medium`.

#### Scenario: L3 finding has correct analysis level
- **WHEN** an L3 finding is produced
- **THEN** its `analysis_level` field equals `"L3"`

#### Scenario: L3 finding has medium confidence
- **WHEN** an L3 finding is produced
- **THEN** its `confidence` field equals `"Medium"`

### Requirement: Custom taint configuration via atlas-taint.yaml
The system SHALL support an `atlas-taint.yaml` file in the project root directory for user-defined taint sources, sinks, and sanitizers. Custom definitions SHALL be merged with built-in defaults using append semantics (custom entries add to, do not replace, defaults). The file SHALL also support a `max_depth` override for L3 analysis.

#### Scenario: Custom source added
- **WHEN** `atlas-taint.yaml` contains `sources: [{pattern: "ctx.request.body", label: "Custom input"}]`
- **THEN** `ctx.request.body` is recognized as a taint source in addition to all built-in sources

#### Scenario: Custom sink added
- **WHEN** `atlas-taint.yaml` contains a custom sink definition for `orm.rawQuery`
- **THEN** `orm.rawQuery` is recognized as a taint sink with the specified vulnerability type and CWE

#### Scenario: Custom sanitizer added
- **WHEN** `atlas-taint.yaml` contains `sanitizers: [{function: "customEscape"}]`
- **THEN** `customEscape()` calls clear taint in both L2 and L3 analysis

#### Scenario: Built-in defaults not replaced
- **WHEN** `atlas-taint.yaml` adds custom sources
- **THEN** all built-in sources (e.g., `req.body`, `request.getParameter`) remain active

#### Scenario: No atlas-taint.yaml present
- **WHEN** the project root does not contain `atlas-taint.yaml`
- **THEN** the system uses only the built-in taint configurations without error

### Requirement: Scan pipeline integration for L3
The L3 engine SHALL be integrated into the scan pipeline as a post-processing phase after all per-file L1+L2 analysis completes. Phase 1 (call graph construction) SHALL execute in parallel with L1+L2 per-file processing. Phase 2 (cross-function taint propagation) SHALL execute after Phase 1 completes. L3 findings SHALL be appended to L1+L2 findings. L3 SHALL only execute when `analysis_level >= L3`.

#### Scenario: L3 runs after L1 and L2
- **WHEN** `--analysis-level L3` is specified
- **THEN** L1, L2, and L3 findings are all produced in the final result

#### Scenario: L3 does not run at L2
- **WHEN** `--analysis-level L2` is specified
- **THEN** no L3 findings are produced

#### Scenario: L3 findings are additive
- **WHEN** comparing scan results at L2 vs L3
- **THEN** all L1 and L2 findings are identical in both runs (L3 is purely additive)

#### Scenario: Phase 1 reuses parsed ASTs
- **WHEN** L3 Phase 1 extracts function definitions and call sites
- **THEN** it reuses tree-sitter ASTs already parsed during L1/L2 processing (no re-parsing)

### Requirement: L3 performance bounds
L3 analysis of a project with 500 functions and max_depth=5 SHALL complete in under 30 seconds. Phase 1 (call graph construction) SHALL be parallelized per-file using rayon. Phase 2 (taint propagation) SHALL be parallelized per-entry-point using rayon.

#### Scenario: 500-function project under 30 seconds
- **WHEN** scanning a project with 500 functions at L3 with max_depth=5
- **THEN** L3 analysis completes in under 30 seconds

#### Scenario: Phase 1 parallel execution
- **WHEN** building the call graph for a multi-file project
- **THEN** function extraction runs in parallel across files via rayon

### Requirement: Five language support for call graph
The L3 engine SHALL support call graph construction for all 5 languages that L2 supports: TypeScript, Java, Python, C#, and Go. Each language SHALL have language-specific AST node kind mappings for function definitions, call expressions, and parameter lists.

#### Scenario: TypeScript call graph construction
- **WHEN** scanning TypeScript files at L3
- **THEN** function declarations, arrow functions, method definitions, and their call sites are extracted

#### Scenario: Python call graph construction
- **WHEN** scanning Python files at L3
- **THEN** function definitions (`def`), method definitions, and their call sites are extracted

#### Scenario: All 5 languages produce call graph entries
- **WHEN** scanning a mixed-language project at L3
- **THEN** call graph entries are produced for TypeScript, Java, Python, C#, and Go files
