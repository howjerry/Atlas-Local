## 1. Taint Configuration Types and Loading

- [x] 1.1 Create `crates/atlas-analysis/src/l2_taint_config.rs` with `TaintConfig`, `TaintSource`, `TaintSink`, `TaintSanitizer` structs and serde deserialization
- [x] 1.2 Create `rules/l2/typescript/taint_config.yaml` with sources (req.body, req.params, req.query, req.headers), sinks (db.query, eval, innerHTML, writeFile, fetch/http.request), and sanitizers (parseInt, escapeHtml, encodeURIComponent)
- [x] 1.3 Create `rules/l2/java/taint_config.yaml` with sources (request.getParameter, request.getInputStream), sinks (Statement.executeQuery, Runtime.exec, response.getWriter), and sanitizers (Integer.parseInt, PreparedStatement)
- [x] 1.4 Create `rules/l2/python/taint_config.yaml` with sources (request.form, request.args, input), sinks (cursor.execute, subprocess.run, open), and sanitizers (int, bleach.clean)
- [x] 1.5 Create `rules/l2/csharp/taint_config.yaml` with sources (Request.Form, Request.QueryString), sinks (SqlCommand, Process.Start, Response.Write), and sanitizers (int.Parse, HtmlEncoder.Encode)
- [x] 1.6 Create `rules/l2/go/taint_config.yaml` with sources (r.URL.Query, r.FormValue, r.Body), sinks (db.Query, exec.Command, fmt.Fprintf), and sanitizers (strconv.Atoi, html.EscapeString)
- [x] 1.7 Implement `include_str!` based config loader in `l2_taint_config.rs` that returns `TaintConfig` per `Language`
- [x] 1.8 Add unit tests for YAML deserialization and config loading for all 5 languages

## 2. Scope Graph Type Extensions

- [x] 2.1 Add `TaintState` enum (Tainted/Clean/Unknown) to `l2_intraprocedural.rs`, extend `VarDef` with `taint_state: TaintState` and `scope_id: u32`
- [x] 2.2 Add `resolved_def: Option<usize>` to `VarUse` for linking to its defining `VarDef`
- [x] 2.3 Extend `ScopeGraph` with `scopes: Vec<Scope>` tree structure for lexical scoping (parent_scope, scope_level)
- [x] 2.4 Add `DataFlowStep` struct with `step_type` (Source/Propagation/Sink), `line`, `column`, `expression`, `description` fields
- [x] 2.5 Update existing `ScopeGraph` tests to remain passing with extended types (backward compatible defaults)
- [x] 2.6 Remove `#![allow(dead_code)]` from `l2_intraprocedural.rs`

## 3. L2 Language Config Trait

- [x] 3.1 Define `L2LanguageConfig` trait in `l2_builder.rs` with methods: `function_node_kinds()`, `variable_declaration_kinds()`, `call_expression_kind()`, `assignment_kinds()`, `identifier_kind()`, `string_literal_kinds()`, `template_literal_kind()`
- [x] 3.2 Implement `L2LanguageConfig` for TypeScript (function_declaration, arrow_function, method_definition, lexical_declaration, etc.)
- [x] 3.3 Implement `L2LanguageConfig` for Java (method_declaration, local_variable_declaration, method_invocation, etc.)
- [x] 3.4 Implement `L2LanguageConfig` for Python (function_definition, assignment, call, etc.)
- [x] 3.5 Implement `L2LanguageConfig` for C# (method_declaration, local_declaration_statement, invocation_expression, etc.)
- [x] 3.6 Implement `L2LanguageConfig` for Go (function_declaration, short_var_declaration, call_expression, etc.)
- [x] 3.7 Add registry function `get_l2_config(language: Language) -> Option<&dyn L2LanguageConfig>`
- [x] 3.8 Add unit tests verifying each language config returns correct node kinds

## 4. Scope Graph Builder

- [x] 4.1 Create `crates/atlas-analysis/src/l2_builder.rs` with `ScopeGraphBuilder` struct that takes a tree-sitter `Tree`, source bytes, and `L2LanguageConfig`
- [x] 4.2 Implement function extraction: find all function nodes in the AST using `L2LanguageConfig::function_node_kinds()`
- [x] 4.3 Implement variable definition extraction: walk function subtree collecting `VarDef` entries with scope tracking
- [x] 4.4 Implement variable use extraction: walk function subtree collecting `VarUse` entries
- [x] 4.5 Implement initial taint marking: match `VarDef` initializers against `TaintConfig.sources` patterns to set `taint_state`
- [x] 4.6 Implement lexical scope tree construction (nested blocks create child scopes)
- [x] 4.7 Implement variable resolution: link each `VarUse` to its reaching `VarDef` by name and scope
- [x] 4.8 Add unit tests for scope graph construction with TypeScript code snippets (simple assignment, block scope, nested functions)
- [x] 4.9 Add unit tests for scope graph construction with Java code snippets

## 5. Taint Propagation Engine

- [x] 5.1 Create `crates/atlas-analysis/src/l2_engine.rs` with `L2Engine` struct
- [x] 5.2 Implement reaching-definitions worklist algorithm: gen/kill sets, iterate statements until fixed-point
- [x] 5.3 Implement taint propagation through direct assignment (`let x = tainted`)
- [x] 5.4 Implement taint propagation through string concatenation (`tainted + "str"`)
- [x] 5.5 Implement taint propagation through template literals (`` `${tainted}` ``)
- [x] 5.6 Implement taint propagation through function argument passing
- [x] 5.7 Implement taint clearing on reassignment to non-tainted value
- [x] 5.8 Implement taint clearing through sanitizer functions (match call expression function name against `TaintConfig.sanitizers`)
- [x] 5.9 Implement sink detection: when a `VarUse` with tainted reaching-def appears as argument to a configured sink function
- [x] 5.10 Implement `DataFlowPath` construction: collect source → propagation steps → sink for each detected flow
- [x] 5.11 Add unit tests for worklist convergence (simple, loop, branching)
- [x] 5.12 Add unit tests for taint propagation (assignment, concatenation, template literal, sanitizer clearing)
- [x] 5.13 Add unit tests for sink detection with correct data flow paths

## 6. Finding Generation

- [x] 6.1 Implement `L2Engine::analyze_file()` → `Vec<Finding>`: for each function, build scope graph, run taint propagation, detect sinks, produce findings
- [x] 6.2 Set finding fields: `analysis_level: L2`, `confidence: Medium`, `severity` from taint config sink definition
- [x] 6.3 Generate rule IDs in format `atlas/security/{language}/l2-{vulnerability}` (e.g., `atlas/security/typescript/l2-sql-injection`)
- [x] 6.4 Populate `metadata.data_flow` as JSON array of `DataFlowStep` objects with type/line/column/expression/description
- [x] 6.5 Set CWE IDs from taint config sink definitions (CWE-89, CWE-79, CWE-78, CWE-22, CWE-918)
- [x] 6.6 Add unit tests for finding generation with correct metadata, rule IDs, and CWE IDs

## 7. Scan Pipeline Integration

- [x] 7.1 Add `analysis_level: AnalysisLevel` field to `ScanOptions` (default: `L1`)
- [x] 7.2 Modify `process_file()` in `crates/atlas-core/src/engine.rs`: after L1 rule loop, if `analysis_level >= L2`, call `L2Engine::analyze_file()` with the already-parsed Tree and source bytes
- [x] 7.3 Append L2 findings to L1 findings list in `process_file()` return value
- [x] 7.4 Remove the "NOT YET INTEGRATED" comment from engine.rs L2/L3 section
- [x] 7.5 Re-export `L2Engine` and `l2_taint_config` types from `atlas-analysis` lib.rs
- [x] 7.6 Add integration test: scan a temp directory with L1-only, verify no L2 findings
- [x] 7.7 Add integration test: scan same directory with L2 enabled, verify L2 findings appear alongside L1

## 8. CLI Flag

- [x] 8.1 Add `--analysis-level <L1|L2>` argument to scan command in `crates/atlas-cli/src/commands/scan.rs`
- [x] 8.2 Parse and validate the flag value, reject L3 with descriptive error
- [x] 8.3 Pass the parsed `AnalysisLevel` to `ScanOptions.analysis_level`
- [x] 8.4 Add CLI test: verify `--analysis-level L2` is accepted and `--analysis-level L3` is rejected

## 9. L2 Security Rule Test Fixtures

- [x] 9.1 Create TypeScript test fixtures: `rules/l2/typescript/tests/l2-sql-injection/fail.ts` and `pass.ts`
- [x] 9.2 Create TypeScript test fixtures for l2-xss, l2-command-injection, l2-path-traversal, l2-ssrf
- [x] 9.3 Create Java test fixtures for all 5 L2 rules (fail + pass pairs)
- [x] 9.4 Create Python test fixtures for all 5 L2 rules (fail + pass pairs)
- [x] 9.5 Create C# test fixtures for all 5 L2 rules (fail + pass pairs)
- [x] 9.6 Create Go test fixtures for all 5 L2 rules (fail + pass pairs)
- [x] 9.7 Add integration tests that scan each fixture and verify correct findings (or absence)

## 10. Regression and Performance

- [x] 10.1 Run full `cargo test` suite and verify all existing L1 tests pass without modification
- [x] 10.2 Run `cargo clippy` and resolve all new warnings
- [x] 10.3 Add benchmark test: measure L2 analysis of a 100-line function, assert < 10ms
- [x] 10.4 Add benchmark test: compare L1-only vs L2 scan on a 100-file project, assert < 50% overhead
- [x] 10.5 Update MEMORY.md with L2 implementation notes
