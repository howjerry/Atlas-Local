# Data Model: L3 Taint Tracking

**Feature**: 011-l3-taint-tracking
**Created**: 2026-02-08
**Purpose**: Define the call graph, cross-function taint propagation, and L3 finding data models.

## 1. Call Graph

The call graph represents function call relationships across the project.

### Rust Types

```rust
/// A directed graph of function call relationships in the project.
pub struct CallGraph {
    /// All function nodes indexed by FunctionId.
    pub functions: Vec<CallGraphNode>,
    /// All call edges.
    pub edges: Vec<CallGraphEdge>,
    /// Index: function name → FunctionId (for quick lookup).
    pub name_index: HashMap<String, Vec<FunctionId>>,
    /// Index: (file, name) → FunctionId (for qualified lookup).
    pub qualified_index: HashMap<(String, String), FunctionId>,
}

pub type FunctionId = usize;

/// A function in the call graph.
pub struct CallGraphNode {
    pub id: FunctionId,
    /// Fully qualified function name (e.g., "UserService.findByName").
    pub name: String,
    /// File path.
    pub file: String,
    /// Starting line number.
    pub start_line: usize,
    /// Ending line number.
    pub end_line: usize,
    /// Parameter names (ordered).
    pub parameters: Vec<String>,
    /// Whether this function has been analysed for taint (memoization).
    pub analysed: bool,
}

/// A function call edge in the call graph.
pub struct CallGraphEdge {
    /// The calling function.
    pub caller: FunctionId,
    /// The called function.
    pub callee: FunctionId,
    /// Line number of the call site in the caller.
    pub call_site_line: usize,
    /// Column number of the call site.
    pub call_site_column: usize,
    /// Mapping of caller arguments to callee parameters.
    /// Index = callee parameter position, Value = caller expression.
    pub argument_mapping: Vec<ArgumentMapping>,
}

/// Maps a caller argument expression to a callee parameter.
pub struct ArgumentMapping {
    /// The callee parameter index (0-based).
    pub param_index: usize,
    /// The caller argument expression (e.g., "req.body.name").
    pub argument_expression: String,
    /// Whether the argument is tainted at the call site.
    pub is_tainted: bool,
}
```

## 2. Call Graph Construction

### Resolution Strategy by Language

| Language | Function Declaration | Call Expression | Resolution |
|----------|---------------------|-----------------|-----------|
| TypeScript | `function_declaration`, `arrow_function`, `method_definition` | `call_expression` with `member_expression` or `identifier` | Name + file imports |
| Java | `method_declaration` | `method_invocation` | Class + method name |
| Python | `function_definition` | `call` | Module + function name |
| Go | `function_declaration`, `method_declaration` | `call_expression` | Package + function name |
| C# | `method_declaration` | `invocation_expression` | Class + method name |

### Resolution Algorithm

```
function build_call_graph(files):
    graph = new CallGraph()

    // Phase 1: Index all function definitions
    for file in files:
        ast = parse(file)
        for function_node in ast.functions():
            node = CallGraphNode {
                name: extract_name(function_node),
                file: file.path,
                start_line: function_node.start_line,
                parameters: extract_parameters(function_node),
            }
            graph.add_node(node)

    // Phase 2: Resolve all call expressions
    for file in files:
        ast = parse(file)
        for call_node in ast.call_expressions():
            caller = graph.find_enclosing_function(file, call_node.line)
            callee_name = extract_callee_name(call_node)

            // Try qualified resolution first (file + name), then name-only
            callee = graph.resolve(file, callee_name)
                  ?? graph.resolve_by_name(callee_name)

            if callee is not None:
                edge = CallGraphEdge {
                    caller: caller.id,
                    callee: callee.id,
                    call_site_line: call_node.line,
                    argument_mapping: map_arguments(call_node, callee),
                }
                graph.add_edge(edge)

    return graph
```

## 3. Cross-Function Taint Propagation

### Algorithm (Worklist with Depth Limiting)

```
function l3_analyse(call_graph, taint_config, max_depth):
    findings = []

    // Start from functions containing taint sources
    for function in call_graph.functions:
        scope_graph = build_scope_graph(function)  // L2 scope graph
        sources = find_sources_in_function(scope_graph, taint_config)
        if sources is empty:
            continue

        // For each tainted source, trace through call graph
        for source in sources:
            worklist = [(function, source, depth=0)]

            while worklist is not empty:
                (current_fn, tainted_var, depth) = worklist.pop()

                if depth > max_depth:
                    continue  // Depth limit reached

                // Check sinks in current function
                sinks = find_sinks_in_function(current_fn, taint_config)
                for sink in sinks:
                    if tainted_var reaches sink:
                        findings.push(build_l3_finding(source, sink, path))

                // Propagate to callees
                for edge in call_graph.outgoing_edges(current_fn):
                    // Check if tainted var is passed as argument
                    for mapping in edge.argument_mapping:
                        if mapping.argument == tainted_var:
                            callee = call_graph.get(edge.callee)
                            param = callee.parameters[mapping.param_index]
                            worklist.push((callee, param, depth + 1))

    return deduplicate(findings)
```

### Taint Across Call Boundaries

```
Caller function                              Callee function
────────────────                              ────────────────
let name = req.body.name;  ← TAINTED         function findByName(name) {
                                                ↑ TAINTED (from argument)
userService.findByName(name);  ──────────→
                                                let query = "SELECT ... " + name;
                                                                              ↑ TAINTED (propagated)
                                                db.query(query);  ← SINK (finding!)
```

### Return Value Taint Propagation

```
Callee function                              Caller function
────────────────                              ────────────────
function getInput() {                         let data = getInput();  ← TAINTED
    return req.body.data;  ← TAINTED                                   (from return)
}                          ──────────→
                                              db.query(data);  ← SINK (finding!)
```

## 4. L3 Finding

### Extended Data Flow Step

```rust
/// A data flow step in an L3 finding (extends L2's DataFlowStep).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3DataFlowStep {
    /// The type of step.
    pub step_type: L3FlowStepType,
    /// Source file path.
    pub file: String,
    /// Function name containing this step.
    pub function: String,
    /// Line number (1-based).
    pub line: usize,
    /// Column number (1-based).
    pub column: usize,
    /// The code expression at this step.
    pub expression: String,
    /// Human-readable description.
    pub description: String,
}

/// Types of steps in an L3 data flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3FlowStepType {
    /// Taint origin.
    Source,
    /// Taint propagation within a function.
    Propagation,
    /// Function call passing tainted data (cross-function boundary).
    Call,
    /// Receiving tainted data as a parameter (cross-function boundary).
    Parameter,
    /// Function return propagating taint back to caller.
    Return,
    /// Taint reaches a dangerous function.
    Sink,
}
```

### JSON Example

```json
{
  "fingerprint": "l3-xyz789...",
  "rule_id": "atlas/security/typescript/l3-sql-injection",
  "severity": "critical",
  "category": "security",
  "cwe_id": "CWE-89",
  "file_path": "src/repository/user-repo.ts",
  "line_range": {
    "start_line": 12,
    "start_col": 5,
    "end_line": 12,
    "end_col": 50
  },
  "snippet": "db.query(`SELECT * FROM users WHERE name = '${name}'`)",
  "description": "User-controlled input from req.body.name flows through userService.findByName() into SQL query without sanitisation.",
  "remediation": "Use parameterised queries at the repository level.",
  "analysis_level": "L3",
  "confidence": "high",
  "metadata": {
    "data_flow": [
      {
        "step_type": "source",
        "file": "src/controller/user-controller.ts",
        "function": "createUser",
        "line": 8,
        "column": 14,
        "expression": "req.body.name",
        "description": "User input from HTTP request body"
      },
      {
        "step_type": "call",
        "file": "src/controller/user-controller.ts",
        "function": "createUser",
        "line": 15,
        "column": 5,
        "expression": "userService.findByName(name)",
        "description": "Tainted value passed as argument to findByName()"
      },
      {
        "step_type": "parameter",
        "file": "src/service/user-service.ts",
        "function": "findByName",
        "line": 5,
        "column": 22,
        "expression": "name: string",
        "description": "Parameter receives tainted value from caller"
      },
      {
        "step_type": "call",
        "file": "src/service/user-service.ts",
        "function": "findByName",
        "line": 8,
        "column": 12,
        "expression": "userRepo.queryByName(name)",
        "description": "Tainted value passed to repository layer"
      },
      {
        "step_type": "parameter",
        "file": "src/repository/user-repo.ts",
        "function": "queryByName",
        "line": 5,
        "column": 20,
        "expression": "name: string",
        "description": "Parameter receives tainted value"
      },
      {
        "step_type": "propagation",
        "file": "src/repository/user-repo.ts",
        "function": "queryByName",
        "line": 12,
        "column": 15,
        "expression": "`SELECT * FROM users WHERE name = '${name}'`",
        "description": "Tainted variable interpolated into SQL query"
      },
      {
        "step_type": "sink",
        "file": "src/repository/user-repo.ts",
        "function": "queryByName",
        "line": 12,
        "column": 5,
        "expression": "db.query(...)",
        "description": "SQL query executed with tainted input"
      }
    ],
    "call_depth": 2,
    "vulnerability_type": "sql-injection",
    "source_label": "HTTP request body",
    "sink_label": "SQL query execution"
  }
}
```

## 5. Taint Configuration

### User-Customisable Config File

```yaml
# atlas-taint.yaml (project root)
# Merges with built-in defaults

sources:
  - pattern: "ctx.request.body"
    language: TypeScript
    label: "Custom framework request body"
  - pattern: "ctx.query"
    language: TypeScript
    label: "Custom framework query params"

sinks:
  - function: "orm.rawQuery"
    language: TypeScript
    tainted_args: [0]
    vulnerability: "sql-injection"
    label: "Custom ORM raw query"

sanitisers:
  - function: "customEscape"
    language: TypeScript
    label: "Custom escape function"

settings:
  max_depth: 5           # Maximum call chain depth (default: 5)
  timeout_per_chain: 100  # Max milliseconds per call chain (default: 100)
```

### Rust Type

```rust
/// Complete taint analysis configuration (built-in + custom).
pub struct TaintConfig {
    /// Taint sources per language.
    pub sources: HashMap<Language, Vec<TaintSource>>,
    /// Taint sinks per language.
    pub sinks: HashMap<Language, Vec<TaintSink>>,
    /// Taint sanitisers per language.
    pub sanitisers: HashMap<Language, Vec<TaintSanitiser>>,
    /// Analysis settings.
    pub max_depth: usize,
    pub timeout_per_chain_ms: u64,
}

/// A taint source definition.
pub struct TaintSource {
    pub pattern: String,
    pub label: String,
}

/// A taint sink definition.
pub struct TaintSink {
    pub function: String,
    pub tainted_args: Vec<usize>,
    pub vulnerability: String,
    pub label: String,
}

/// A taint sanitiser definition.
pub struct TaintSanitiser {
    pub function: String,
    pub label: String,
}
```

## 6. Analysis Pipeline Integration

```
Scan Request (--analysis-level L3)
  │
  ▼
L1 Pattern Engine (always runs)
  │  ├─ Parse tree-sitter AST per file
  │  └─ Match L1 patterns → L1 Findings
  │
  ▼
L2 Data Flow Engine (runs for L2+)
  │  ├─ Build ScopeGraph per function
  │  └─ Intra-procedural taint → L2 Findings
  │
  ▼
L3 Taint Tracking Engine (runs for L3 only)
  │  ├─ Build CallGraph across all scanned files
  │  │   ├─ Index function definitions
  │  │   └─ Resolve call expressions
  │  ├─ Load TaintConfig (built-in + custom atlas-taint.yaml)
  │  ├─ For each function with taint sources:
  │  │   └─ Worklist traversal (depth-limited)
  │  │       ├─ Propagate taint across call boundaries
  │  │       ├─ Check sinks at each level
  │  │       └─ Apply sanitisers
  │  └─ Produce L3 Findings
  │
  ▼
Merge L1 + L2 + L3 Findings
  │  ├─ Deduplicate (prefer higher analysis level)
  │  └─ Sort by severity, file, line
  │
  ▼
Gate Evaluation + Report
```

## 7. Performance Considerations

| Factor | Approach |
|--------|---------|
| Call graph size | Index only functions in scanned files; no third-party library modelling |
| Depth explosion | Hard limit at `max_depth` (default 5) |
| Wide call graphs | Per-chain timeout (default 100ms); skip if exceeded |
| Recursive calls | Cycle detection in call graph traversal; skip back-edges |
| Memory | ScopeGraphs built on-demand per function, not all at once |
| Parallelism | Independent call chains can be analysed in parallel via rayon |

### Complexity Analysis

- Call graph construction: O(F + C) where F = functions, C = call expressions
- Taint propagation per source: O(d^b) where d = max_depth, b = average branching factor
- With max_depth=5 and average branching factor of 3: 3^5 = 243 paths per source (bounded)
- Per-chain timeout prevents pathological cases
