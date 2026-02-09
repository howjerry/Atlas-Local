## ADDED Requirements

### Requirement: Taint configuration loading
The system SHALL load per-language taint configurations (sources, sinks, sanitizers) from embedded YAML files at compile time using `include_str!`. Each language (TypeScript, Java, Python, C#, Go) SHALL have a `taint_config.yaml` file containing source patterns, sink function definitions with tainted argument positions, and sanitizer function names.

#### Scenario: Load TypeScript taint config
- **WHEN** the L2 engine initializes for TypeScript analysis
- **THEN** it loads `rules/l2/typescript/taint_config.yaml` containing at least sources (`req.body`, `req.params`, `req.query`), sinks (`db.query`, `eval`), and sanitizers (`parseInt`, `escapeHtml`)

#### Scenario: Load config for all supported languages
- **WHEN** the L2 engine initializes
- **THEN** taint configs are available for all 5 languages: TypeScript, Java, Python, C#, Go

#### Scenario: Invalid taint config format
- **WHEN** a taint config YAML file has invalid structure
- **THEN** the system SHALL return an error at compile time or during deserialization with a descriptive message

### Requirement: Scope graph construction
The system SHALL build a `ScopeGraph` for each function in a scanned file by traversing the tree-sitter AST. The scope graph SHALL track variable definitions (`VarDef`) with taint state and variable uses (`VarUse`) with resolved definitions. The system SHALL support lexical scoping (block scope for `let`/`const` in JS/TS, method scope for Java/C#/Go).

#### Scenario: Build scope graph for function with variable assignment
- **WHEN** analyzing a TypeScript function containing `const name = req.body.name; db.query(name)`
- **THEN** the scope graph contains a `VarDef` for `name` at its declaration line with `tainted: true`, and a `VarUse` for `name` at the `db.query` call line

#### Scenario: Block scoping respected
- **WHEN** a variable `x` is defined inside an `if` block and referenced outside the block
- **THEN** the scope graph does NOT resolve the outer reference to the inner definition

#### Scenario: Function with no variables
- **WHEN** analyzing an empty function or a function with only literals
- **THEN** the scope graph is empty (no definitions, no uses, no flows)

### Requirement: Taint propagation via reaching-definitions
The system SHALL implement a reaching-definitions worklist algorithm to propagate taint through variable assignments within a function. Taint SHALL propagate through direct assignment, string concatenation, and template literals. Taint SHALL be cleared when a variable is reassigned to a non-tainted value or passes through a sanitizer function.

#### Scenario: Taint propagates through assignment
- **WHEN** `const input = req.body.name` followed by `const query = "SELECT " + input`
- **THEN** both `input` and `query` are marked as tainted

#### Scenario: Taint propagates through template literal
- **WHEN** a template literal interpolates a tainted variable (e.g., `` `...${input}...` ``)
- **THEN** the resulting variable is marked as tainted

#### Scenario: Taint cleared by reassignment
- **WHEN** `let x = req.body.name` followed by `x = "safe_value"`
- **THEN** `x` is NOT tainted after the reassignment

#### Scenario: Taint cleared by sanitizer
- **WHEN** `const input = req.body.name` followed by `const safe = parseInt(input)`
- **THEN** `safe` is NOT tainted (parseInt is a configured sanitizer)

#### Scenario: Reaching-definitions converges to fixed point
- **WHEN** a function contains a loop with tainted variable assignments
- **THEN** the worklist algorithm terminates and produces correct taint state

### Requirement: L2 source-to-sink detection
The system SHALL detect when tainted data flows from a configured source to a configured sink within a single function. When a flow is detected, the system SHALL produce a `Finding` with `analysis_level: L2`, the appropriate rule ID, severity, CWE, and a `data_flow` metadata array showing the path from source to sink.

#### Scenario: Detect SQL injection via variable
- **WHEN** a function assigns user input to a variable and passes it to a SQL query function
- **THEN** a finding is produced with rule ID containing `l2-sql-injection`, CWE-89, and `metadata.data_flow` containing steps from source to sink

#### Scenario: No finding for parameterized query
- **WHEN** a function uses a parameterized query binding (e.g., `db.query("... $1", [name])`)
- **THEN** no SQL injection finding is produced (parameterized queries are safe sinks)

#### Scenario: No finding when sanitizer applied
- **WHEN** a tainted variable passes through a sanitizer before reaching a sink
- **THEN** no finding is produced because the sanitizer clears the taint

#### Scenario: No finding when source never reaches sink
- **WHEN** a function contains tainted variables but no configured sink functions
- **THEN** no L2 finding is produced

### Requirement: Data flow path metadata
Each L2 finding SHALL include a `metadata.data_flow` array of flow steps ordered from source to sink. Each step SHALL contain `type` (source/propagation/sink), `line`, `column`, `expression`, and `description`.

#### Scenario: Three-step data flow path
- **WHEN** an L2 finding is produced for a source → variable assignment → sink pattern
- **THEN** `metadata.data_flow` contains 3 steps: source, propagation, and sink with correct types

#### Scenario: Data flow path line numbers are correct
- **WHEN** an L2 finding is produced
- **THEN** each step in `metadata.data_flow` has a `line` matching the actual source code line number

### Requirement: Five L2 security rules
The system SHALL implement at least 5 L2 security detection rules as Rust-native checks driven by the taint configuration:

1. **l2-sql-injection** (CWE-89): Tainted data reaching SQL query functions
2. **l2-xss** (CWE-79): Tainted data reaching HTML output functions
3. **l2-command-injection** (CWE-78): Tainted data reaching OS command execution functions
4. **l2-path-traversal** (CWE-22): Tainted data reaching file system path functions
5. **l2-ssrf** (CWE-918): Tainted data reaching HTTP request functions

#### Scenario: SQL injection detected in TypeScript
- **WHEN** scanning TypeScript code where `req.body` reaches `db.query()` without sanitization
- **THEN** a finding with rule `atlas/security/typescript/l2-sql-injection` and CWE-89 is produced

#### Scenario: XSS detected in Java
- **WHEN** scanning Java code where `request.getParameter()` reaches HTML output without sanitization
- **THEN** a finding with rule `atlas/security/java/l2-xss` and CWE-79 is produced

#### Scenario: Command injection detected in Python
- **WHEN** scanning Python code where user input reaches a command execution function without sanitization
- **THEN** a finding with rule `atlas/security/python/l2-command-injection` and CWE-78 is produced

#### Scenario: All 5 rules have per-language configurations
- **WHEN** the taint configs are loaded for any of the 5 supported languages
- **THEN** each language has source, sink, and sanitizer entries sufficient to support all 5 rule types

### Requirement: CLI analysis-level flag
The system SHALL accept an `--analysis-level <L1|L2>` flag on the `atlas scan` command. The default SHALL be `L1`. When set to `L2`, the scan pipeline SHALL execute L2 analysis in addition to L1 analysis.

#### Scenario: Default analysis level is L1
- **WHEN** running `atlas scan ./src` without `--analysis-level`
- **THEN** only L1 analysis runs and no L2 findings are produced

#### Scenario: L2 analysis enabled via flag
- **WHEN** running `atlas scan --analysis-level L2 ./src`
- **THEN** both L1 and L2 analysis run, and L2 findings are included in the results

#### Scenario: Invalid analysis level rejected
- **WHEN** running `atlas scan --analysis-level L3 ./src`
- **THEN** the command fails with an error message indicating L3 is not yet supported

### Requirement: Scan pipeline integration
The L2 engine SHALL be integrated into the scan pipeline after L1 evaluation. L2 analysis SHALL reuse the already-parsed tree-sitter `Tree` and source bytes. L2 findings SHALL be appended to L1 findings before sorting. The L2 engine SHALL only execute when `analysis_level >= L2` in the scan options.

#### Scenario: L2 findings appear alongside L1 findings
- **WHEN** scanning a project at L2 that triggers both L1 and L2 rules
- **THEN** the result contains both L1 and L2 findings, distinguishable by `analysis_level`

#### Scenario: L2 does not re-parse files
- **WHEN** L2 analysis runs on a file
- **THEN** it receives the already-parsed tree-sitter Tree from the L1 pipeline step (no second parse call)

#### Scenario: L1 results unchanged when L2 enabled
- **WHEN** comparing scan results at L1-only vs L2
- **THEN** all L1 findings are identical in both runs (L2 is purely additive)

### Requirement: L2 language config abstraction
The system SHALL define an `L2LanguageConfig` trait to abstract language-specific AST node types for scope graph construction. Each supported language SHALL implement this trait to map its tree-sitter node kinds (function declarations, variable declarations, call expressions, assignment expressions) to the L2 engine's generic concepts.

#### Scenario: TypeScript language config maps function nodes
- **WHEN** the TypeScript L2 config is queried for function declaration node kinds
- **THEN** it returns `function_declaration`, `arrow_function`, `method_definition`

#### Scenario: Java language config maps variable nodes
- **WHEN** the Java L2 config is queried for variable declaration node kinds
- **THEN** it returns `local_variable_declaration`

#### Scenario: All 5 languages have L2 configs
- **WHEN** the L2 engine checks for language support
- **THEN** TypeScript, Java, Python, C#, and Go all have registered `L2LanguageConfig` implementations

### Requirement: Performance bounds
L2 analysis of a single function with up to 100 lines SHALL complete in under 10ms (scope graph construction + taint propagation). L2 analysis SHALL add less than 50% overhead to total scan time compared to L1-only when applied to all files.

#### Scenario: Single function analysis under 10ms
- **WHEN** analyzing a 100-line function with L2
- **THEN** scope graph construction and taint propagation complete in under 10ms

#### Scenario: Full project overhead within bounds
- **WHEN** scanning a project with 1000 files at L2
- **THEN** total scan time is less than 1.5x the L1-only scan time
