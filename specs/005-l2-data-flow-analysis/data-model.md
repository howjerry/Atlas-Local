# Data Model: L2 Data Flow Analysis

**Feature**: 005-l2-data-flow-analysis
**Created**: 2026-02-08
**Purpose**: Define the scope graph, taint propagation, and data flow finding data models for intra-procedural analysis.

## 1. Scope Graph

The scope graph represents variable scoping within a single function. Each scope contains variable definitions and references, forming a tree rooted at the function scope.

### Rust Types (Extending Existing Scaffold)

```rust
/// A tree of lexical scopes within a single function.
pub struct ScopeGraph {
    /// The root scope (function body).
    pub root: ScopeId,
    /// All scopes indexed by ScopeId.
    pub scopes: Vec<Scope>,
    /// All variable definitions across all scopes.
    pub var_defs: Vec<VarDef>,
    /// All variable uses across all scopes.
    pub var_uses: Vec<VarUse>,
}

pub type ScopeId = usize;

/// A lexical scope (function body, block, if-branch, loop body, etc.).
pub struct Scope {
    pub id: ScopeId,
    pub parent: Option<ScopeId>,
    pub children: Vec<ScopeId>,
    /// Line range of this scope in source.
    pub start_line: usize,
    pub end_line: usize,
    /// Variable definitions directly in this scope.
    pub definitions: Vec<VarDefId>,
}

pub type VarDefId = usize;

/// A variable definition (declaration or assignment).
pub struct VarDef {
    pub id: VarDefId,
    pub name: String,
    pub scope_id: ScopeId,
    pub line: usize,
    pub column: usize,
    /// The taint state of this definition.
    pub taint: TaintState,
    /// The AST node kind (let_declaration, assignment, parameter, etc.).
    pub kind: VarDefKind,
}

/// How a variable was defined.
pub enum VarDefKind {
    Declaration,    // let x = ..., const x = ..., var x = ...
    Parameter,      // function parameter
    Assignment,     // x = ... (reassignment)
    Destructuring,  // const { a, b } = obj
}

/// A variable reference (read/use).
pub struct VarUse {
    pub name: String,
    pub scope_id: ScopeId,
    pub line: usize,
    pub column: usize,
    /// Resolved to the VarDef that reaches this use (after analysis).
    pub resolved_def: Option<VarDefId>,
}
```

## 2. Taint State

Tracks whether a variable holds tainted (user-controlled) data.

### Rust Type

```rust
/// Taint state of a variable definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintState {
    /// Variable holds user-controlled (tainted) data.
    Tainted {
        /// The original taint source (e.g., "req.body.name").
        source: String,
        /// Line where taint was introduced.
        source_line: usize,
    },
    /// Variable holds safe (non-tainted) data.
    Clean,
    /// Taint state is not yet determined (initial state for worklist).
    Unknown,
}
```

### Taint Propagation Rules

| Operation | Taint Result | Example |
|-----------|-------------|---------|
| Assignment from tainted | Tainted | `let x = req.body.name` → x is tainted |
| Assignment from clean | Clean | `let x = "literal"` → x is clean |
| Concatenation with tainted | Tainted | `"SELECT " + tainted` → tainted |
| Template literal with tainted | Tainted | `` `${tainted}` `` → tainted |
| Sanitiser call | Clean | `escapeHtml(tainted)` → clean |
| Reassignment to clean | Clean | `x = "safe"` clears taint on x |
| Function parameter (from tainted arg) | Tainted | `foo(tainted)` → parameter is tainted (intra-proc only) |

## 3. Taint Source/Sink Configuration

### Source Configuration YAML

```yaml
# rules/l2/typescript/sources.yaml
language: TypeScript
sources:
  - pattern: "req.body"
    label: "HTTP request body"
  - pattern: "req.params"
    label: "HTTP URL parameters"
  - pattern: "req.query"
    label: "HTTP query string"
  - pattern: "req.headers"
    label: "HTTP request headers"
  - pattern: "process.env"
    label: "Environment variable"
  - pattern: "document.location"
    label: "Browser URL"
  - pattern: "document.cookie"
    label: "Browser cookie"
```

### Sink Configuration YAML

```yaml
# rules/l2/typescript/sinks.yaml
language: TypeScript
sinks:
  - function: "db.query"
    tainted_args: [0]
    vulnerability: "sql-injection"
    label: "SQL query execution"
  - function: "pool.query"
    tainted_args: [0]
    vulnerability: "sql-injection"
    label: "SQL query execution (pool)"
  - function: "res.send"
    tainted_args: [0]
    vulnerability: "xss"
    label: "HTTP response body"
  - function: "res.write"
    tainted_args: [0]
    vulnerability: "xss"
    label: "HTTP response write"
  - function: "execSync"
    tainted_args: [0]
    vulnerability: "command-injection"
    label: "OS command execution"
  - function: "fs.readFile"
    tainted_args: [0]
    vulnerability: "path-traversal"
    label: "File system read"
  - function: "fetch"
    tainted_args: [0]
    vulnerability: "ssrf"
    label: "HTTP request URL"
```

### Sanitiser Configuration YAML

```yaml
# rules/l2/typescript/sanitisers.yaml
language: TypeScript
sanitisers:
  - function: "parseInt"
    label: "Integer parsing"
  - function: "Number"
    label: "Numeric conversion"
  - function: "escapeHtml"
    label: "HTML entity encoding"
  - function: "encodeURIComponent"
    label: "URL encoding"
  - function: "validator.escape"
    label: "Validator escape"
  - function: "path.normalize"
    label: "Path normalisation"
    note: "Partial sanitiser — may not prevent all path traversal"
```

## 4. Data Flow Finding

### Rust Type

```rust
/// A data flow step in an L2 finding's flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowStep {
    /// The type of step in the flow.
    pub step_type: FlowStepType,
    /// Source file path.
    pub file: String,
    /// Line number (1-based).
    pub line: usize,
    /// Column number (1-based).
    pub column: usize,
    /// The code expression at this step.
    pub expression: String,
    /// Human-readable description of this step.
    pub description: String,
}

/// Type of step in a data flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStepType {
    /// Taint origin (user input enters the system).
    Source,
    /// Taint propagation through assignment or operation.
    Propagation,
    /// Taint reaches a dangerous function.
    Sink,
}
```

### Example Finding JSON

```json
{
  "fingerprint": "l2-abc123...",
  "rule_id": "atlas/security/typescript/l2-sql-injection",
  "severity": "critical",
  "category": "security",
  "cwe_id": "CWE-89",
  "file_path": "src/api/users.ts",
  "line_range": {
    "start_line": 15,
    "start_col": 3,
    "end_line": 15,
    "end_col": 45
  },
  "snippet": "db.query(`SELECT * FROM users WHERE name = '${name}'`)",
  "description": "User-controlled input from req.body.name flows into SQL query without sanitisation.",
  "remediation": "Use parameterised queries: db.query('SELECT * FROM users WHERE name = $1', [name])",
  "analysis_level": "L2",
  "confidence": "high",
  "metadata": {
    "data_flow": [
      {
        "step_type": "source",
        "file": "src/api/users.ts",
        "line": 8,
        "column": 14,
        "expression": "req.body.name",
        "description": "User input from HTTP request body"
      },
      {
        "step_type": "propagation",
        "file": "src/api/users.ts",
        "line": 8,
        "column": 3,
        "expression": "const name = req.body.name",
        "description": "Tainted value assigned to variable 'name'"
      },
      {
        "step_type": "propagation",
        "file": "src/api/users.ts",
        "line": 15,
        "column": 12,
        "expression": "`SELECT * FROM users WHERE name = '${name}'`",
        "description": "Tainted variable interpolated into SQL query string"
      },
      {
        "step_type": "sink",
        "file": "src/api/users.ts",
        "line": 15,
        "column": 3,
        "expression": "db.query(...)",
        "description": "SQL query executed with tainted input"
      }
    ],
    "vulnerability_type": "sql-injection",
    "source_label": "HTTP request body",
    "sink_label": "SQL query execution"
  }
}
```

## 5. L2 Rule Configuration

### Rust Type

```rust
/// Configuration for an L2 taint analysis rule.
pub struct L2RuleConfig {
    /// Rule identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// The vulnerability type this rule detects.
    pub vulnerability_type: String,
    /// CWE identifier.
    pub cwe_id: String,
    /// Severity of findings produced by this rule.
    pub severity: Severity,
    /// Source patterns that introduce taint for this rule.
    pub sources: Vec<String>,
    /// Sink patterns where taint is dangerous.
    pub sinks: Vec<SinkPattern>,
    /// Sanitiser patterns that clear taint.
    pub sanitisers: Vec<String>,
    /// Path to the Rhai script implementing the rule logic.
    pub script_path: String,
}

/// A sink pattern with argument position tracking.
pub struct SinkPattern {
    pub function: String,
    pub tainted_args: Vec<usize>,
}
```

### L2 Rule Inventory

| # | Rule ID | Vulnerability | CWE | Severity |
|---|---------|--------------|-----|----------|
| 1 | `atlas/security/*/l2-sql-injection` | SQL Injection | CWE-89 | Critical |
| 2 | `atlas/security/*/l2-xss` | Cross-Site Scripting | CWE-79 | High |
| 3 | `atlas/security/*/l2-command-injection` | OS Command Injection | CWE-78 | Critical |
| 4 | `atlas/security/*/l2-path-traversal` | Path Traversal | CWE-22 | High |
| 5 | `atlas/security/*/l2-ssrf` | Server-Side Request Forgery | CWE-918 | High |

## 6. Reaching-Definitions Algorithm

### Pseudocode

```
function analyse_function(scope_graph):
    worklist = all VarDefs in scope_graph

    // Step 1: Mark initial taint sources
    for each var_def in scope_graph.var_defs:
        if var_def.initialiser matches any taint source:
            var_def.taint = Tainted(source)
        else if var_def.initialiser is a literal/constant:
            var_def.taint = Clean
        else:
            var_def.taint = Unknown

    // Step 2: Propagate taint through assignments
    changed = true
    while changed:
        changed = false
        for each var_def in worklist:
            if var_def.taint == Unknown:
                // Check if the RHS references any tainted variable
                rhs_vars = get_referenced_vars(var_def.initialiser)
                for rhs_var in rhs_vars:
                    rhs_def = resolve_to_reaching_def(rhs_var, scope_graph)
                    if rhs_def.taint == Tainted:
                        // Check if sanitiser is applied
                        if is_sanitised(var_def.initialiser):
                            var_def.taint = Clean
                        else:
                            var_def.taint = Tainted(rhs_def.taint.source)
                        changed = true

    // Step 3: Check sinks
    findings = []
    for each call in function_body:
        if call matches any taint sink:
            for each arg_position in sink.tainted_args:
                arg_expr = call.arguments[arg_position]
                arg_vars = get_referenced_vars(arg_expr)
                for arg_var in arg_vars:
                    arg_def = resolve_to_reaching_def(arg_var, scope_graph)
                    if arg_def.taint == Tainted:
                        findings.push(build_data_flow_finding(
                            source=arg_def.taint.source,
                            path=trace_path(arg_def, call),
                            sink=call
                        ))

    return findings
```

## 7. Analysis Pipeline Integration

```
Scan Request (--analysis-level L2)
  │
  ▼
L1 Pattern Engine (always runs)
  │  ├─ Parse tree-sitter AST
  │  └─ Match L1 patterns → L1 Findings
  │
  ▼
L2 Data Flow Engine (opt-in)
  │  ├─ Build ScopeGraph per function (reuse parsed AST)
  │  ├─ Load taint sources/sinks/sanitisers for language
  │  ├─ Run reaching-definitions propagation
  │  └─ Check sinks for tainted arguments → L2 Findings
  │
  ▼
Merge L1 + L2 Findings
  │  ├─ Deduplicate (L2 finding on same line as L1 → keep L2, richer metadata)
  │  └─ Sort by file path, line number
  │
  ▼
Gate Evaluation + Report
```

## 8. Language-Specific AST Patterns

### Source Detection Patterns (tree-sitter)

| Language | Source Pattern | AST Query |
|----------|--------------|-----------|
| TypeScript | `req.body` | `(member_expression object: (identifier) @obj property: (property_identifier) @prop) (#eq? @obj "req") (#match? @prop "^(body\|params\|query\|headers)$")` |
| Java | `request.getParameter()` | `(method_invocation object: (identifier) @obj name: (identifier) @method) (#eq? @obj "request") (#match? @method "^getParameter")` |
| Python | `request.form` | `(attribute object: (identifier) @obj attribute: (identifier) @attr) (#eq? @obj "request") (#match? @attr "^(form\|args\|values\|data)$")` |
| Go | `r.FormValue()` | `(call_expression function: (selector_expression field: (field_identifier) @method)) (#match? @method "^(FormValue\|URL\|Body)$")` |
| C# | `Request.Form` | `(member_access_expression name: (identifier) @prop) (#match? @prop "^(Form\|QueryString\|Params)$")` |

### Sink Detection Patterns

| Language | Sink Pattern | AST Query | Arg Position |
|----------|-------------|-----------|-------------|
| TypeScript | `db.query(x)` | `(call_expression function: (member_expression property: (property_identifier) @fn)) (#match? @fn "^(query\|execute\|raw)$")` | 0 |
| Java | `stmt.executeQuery(x)` | `(method_invocation name: (identifier) @fn) (#match? @fn "^(executeQuery\|executeUpdate\|execute)$")` | 0 |
| Python | `cursor.execute(x)` | `(call function: (attribute attribute: (identifier) @fn)) (#match? @fn "^(execute\|executemany)$")` | 0 |
| Go | `db.Query(x)` | `(call_expression function: (selector_expression field: (field_identifier) @fn)) (#match? @fn "^(Query\|Exec\|QueryRow)$")` | 0 |
| C# | `cmd.ExecuteReader()` | `(invocation_expression function: (member_access_expression name: (identifier) @fn)) (#match? @fn "^(ExecuteReader\|ExecuteNonQuery\|ExecuteScalar)$")` | 0 |
