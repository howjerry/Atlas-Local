# Data Model: Code Quality Metrics

**Feature**: 007-code-quality-metrics
**Created**: 2026-02-08
**Purpose**: Define the metrics data model for complexity computation, duplication detection, and LOC statistics.

## 1. Function Metrics

Per-function metrics computed by traversing the tree-sitter AST.

### Rust Type

```rust
/// Metrics computed for a single function/method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMetrics {
    /// Fully qualified function name (e.g., "UserService.getUser").
    pub name: String,
    /// File path relative to project root.
    pub file_path: String,
    /// Starting line number (1-based).
    pub start_line: usize,
    /// Ending line number (1-based).
    pub end_line: usize,
    /// Lines of code in this function (excluding blanks/comments).
    pub loc: usize,
    /// McCabe cyclomatic complexity score.
    pub cyclomatic_complexity: usize,
    /// SonarSource cognitive complexity score.
    pub cognitive_complexity: usize,
    /// Number of parameters.
    pub parameter_count: usize,
    /// Maximum nesting depth.
    pub max_nesting_depth: usize,
}
```

### JSON Example

```json
{
  "name": "UserService.getUser",
  "file_path": "src/services/user-service.ts",
  "start_line": 15,
  "end_line": 85,
  "loc": 55,
  "cyclomatic_complexity": 18,
  "cognitive_complexity": 32,
  "parameter_count": 3,
  "max_nesting_depth": 5
}
```

## 2. File Metrics

Per-file aggregate metrics.

### Rust Type

```rust
/// Metrics computed for a single source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetrics {
    /// File path relative to project root.
    pub path: String,
    /// Language of the file.
    pub language: String,
    /// Total lines in the file (including blanks and comments).
    pub total_lines: usize,
    /// Lines containing code (excluding blanks and comments).
    pub code_lines: usize,
    /// Blank lines.
    pub blank_lines: usize,
    /// Comment lines.
    pub comment_lines: usize,
    /// Number of functions/methods in this file.
    pub function_count: usize,
    /// Per-function metrics.
    pub functions: Vec<FunctionMetrics>,
    /// Maximum cyclomatic complexity among functions in this file.
    pub max_cyclomatic: usize,
    /// Maximum cognitive complexity among functions in this file.
    pub max_cognitive: usize,
}
```

### JSON Example

```json
{
  "path": "src/services/user-service.ts",
  "language": "TypeScript",
  "total_lines": 250,
  "code_lines": 180,
  "blank_lines": 30,
  "comment_lines": 40,
  "function_count": 8,
  "functions": [],
  "max_cyclomatic": 18,
  "max_cognitive": 32
}
```

## 3. Project Metrics

Project-level aggregate metrics.

### Rust Type

```rust
/// Project-wide metrics aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMetrics {
    /// Total number of scanned files.
    pub total_files: usize,
    /// Total lines across all files.
    pub total_lines: usize,
    /// Total code lines (excluding blanks/comments).
    pub total_code_lines: usize,
    /// LOC breakdown by language.
    pub loc_by_language: BTreeMap<String, usize>,
    /// Total number of functions/methods.
    pub total_functions: usize,
    /// Average function LOC.
    pub avg_function_loc: f64,
    /// Average cyclomatic complexity.
    pub avg_cyclomatic: f64,
    /// Average cognitive complexity.
    pub avg_cognitive: f64,
    /// Code duplication percentage.
    pub duplication_percentage: f64,
    /// Detected duplicate blocks.
    pub duplicate_blocks: Vec<DuplicationBlock>,
}
```

### JSON Example (in report `metrics` section)

```json
{
  "metrics": {
    "project": {
      "total_files": 120,
      "total_lines": 45000,
      "total_code_lines": 32000,
      "loc_by_language": {
        "TypeScript": 18000,
        "Java": 8000,
        "Python": 4000,
        "Go": 1500,
        "CSharp": 500
      },
      "total_functions": 450,
      "avg_function_loc": 28.5,
      "avg_cyclomatic": 4.2,
      "avg_cognitive": 6.8,
      "duplication_percentage": 3.5,
      "duplicate_blocks": []
    },
    "files": [],
    "threshold_violations": {
      "cyclomatic": 12,
      "cognitive": 8,
      "duplication": 5
    }
  }
}
```

## 4. Duplication Block

Represents a pair of duplicated code regions.

### Rust Type

```rust
/// A detected pair of duplicated code blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicationBlock {
    /// First occurrence.
    pub location_a: DuplicationLocation,
    /// Second occurrence.
    pub location_b: DuplicationLocation,
    /// Number of duplicated tokens.
    pub token_count: usize,
    /// Approximate number of duplicated lines.
    pub line_count: usize,
}

/// A specific location of a duplicated code block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicationLocation {
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
}
```

### JSON Example

```json
{
  "location_a": {
    "file_path": "src/api/users.ts",
    "start_line": 45,
    "end_line": 72
  },
  "location_b": {
    "file_path": "src/api/orders.ts",
    "start_line": 30,
    "end_line": 57
  },
  "token_count": 145,
  "line_count": 27
}
```

## 5. Metrics Configuration

### Rust Type

```rust
/// Configuration for metrics computation thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Whether metrics computation is enabled.
    pub enabled: bool,
    /// Maximum cyclomatic complexity before producing a finding.
    pub cyclomatic_max: usize,      // default: 15
    /// Maximum cognitive complexity before producing a finding.
    pub cognitive_max: usize,        // default: 25
    /// Minimum token count for duplication detection.
    pub min_tokens: usize,           // default: 100
    /// Minimum duplicated lines for reporting.
    pub min_duplicate_lines: usize,  // default: 10
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cyclomatic_max: 15,
            cognitive_max: 25,
            min_tokens: 100,
            min_duplicate_lines: 10,
        }
    }
}
```

### YAML Configuration Example

```yaml
# In atlas.yaml or policy.yaml
metrics:
  enabled: true
  cyclomatic_max: 15
  cognitive_max: 25
  min_tokens: 100
  min_duplicate_lines: 10
```

## 6. Cyclomatic Complexity Computation

### Decision Point to Increment Mapping

| AST Node Type | TypeScript | Java | Python | Go | C# | Increment |
|--------------|-----------|------|--------|----|----|-----------|
| `if` | `if_statement` | `if_statement` | `if_statement` | `if_statement` | `if_statement` | +1 |
| `else if` | `else` clause with `if` | `if_statement` (chained) | `elif_clause` | `if_statement` (chained) | `else` clause with `if` | +1 |
| `for` | `for_statement`, `for_in_statement` | `for_statement`, `enhanced_for_statement` | `for_statement` | `for_statement` | `for_statement`, `for_each_statement` | +1 |
| `while` | `while_statement` | `while_statement` | `while_statement` | `for_statement` (Go has no while) | `while_statement` | +1 |
| `do-while` | `do_statement` | `do_statement` | — | — | `do_statement` | +1 |
| `case` | `switch_case` | `switch_label` | `case_clause` (match) | `expression_case` | `switch_section` | +1 |
| `catch` | `catch_clause` | `catch_clause` | `except_clause` | — (errors are values) | `catch_clause` | +1 |
| `&&` / `\|\|` | `binary_expression` | `binary_expression` | `boolean_operator` | `binary_expression` | `binary_expression` | +1 each |
| `?:` ternary | `ternary_expression` | `ternary_expression` | `conditional_expression` | — | `conditional_expression` | +1 |

### Pseudocode

```
function cyclomatic_complexity(function_node):
    complexity = 1  // Base complexity
    for each node in function_node.descendants():
        if node.kind in DECISION_NODES:
            complexity += 1
        if node.kind == "binary_expression":
            if node.operator in ["&&", "||"]:
                complexity += 1
    return complexity
```

## 7. Cognitive Complexity Computation

### Increment Rules (SonarSource Specification)

| Category | Examples | Base Increment | Nesting Penalty |
|----------|---------|---------------|----------------|
| Structural | `if`, `else if`, `else`, `for`, `while`, `do`, `catch`, `switch` | +1 | +nesting_level |
| Logical | `&&`, `\|\|` (each sequence of same operator) | +1 | None |
| Nesting | Each level of `if`/`for`/`while`/`try`/`switch` | None | +1 to nested increments |
| Fundamentally complex | Recursion | +1 | None |

### Nesting Penalty Example

```typescript
function example() {                // nesting = 0
    if (a) {                        // +1 (structural, nesting=0)
        for (let i = 0; ...) {      // +2 (structural +1, nesting penalty +1)
            if (b) {                // +3 (structural +1, nesting penalty +2)
                while (c) {         // +4 (structural +1, nesting penalty +3)
                }
            }
        }
    }
}
// Cognitive complexity = 1 + 2 + 3 + 4 = 10
```

### Pseudocode

```
function cognitive_complexity(function_node):
    score = 0
    nesting = 0

    function visit(node):
        if node.kind in NESTING_NODES:
            score += 1 + nesting  // structural increment + nesting penalty
            nesting += 1
            for child in node.children:
                visit(child)
            nesting -= 1
        else if node.kind in LOGICAL_NODES:
            score += 1  // no nesting penalty for logical operators
            // Consecutive same-operator sequences count as 1
        else:
            for child in node.children:
                visit(child)

    visit(function_node)
    return score
```

## 8. Token-Based Duplication Detection

### Algorithm: Rabin-Karp Rolling Hash

1. **Tokenise**: Extract tokens from all files, normalising identifiers to a placeholder (e.g., `$ID`)
2. **Hash**: Compute rolling hash for each window of `min_tokens` tokens
3. **Match**: Hash collisions are verified by exact token sequence comparison
4. **Merge**: Adjacent duplicate blocks are merged into larger blocks
5. **Report**: Each unique duplicate pair is reported with locations and token count

### Token Normalisation

| Original Token | Normalised Token | Rationale |
|---------------|-----------------|-----------|
| `userName` | `$ID` | Variable name (Type II detection) |
| `42` | `$NUM` | Numeric literal |
| `"hello"` | `$STR` | String literal |
| `if` | `if` | Keyword (preserved) |
| `+` | `+` | Operator (preserved) |
| `(` | `(` | Delimiter (preserved) |

### Example

```typescript
// File A, lines 10-25
function processUser(user) {
    if (user.active) {
        const name = user.name.trim();
        const email = user.email.toLowerCase();
        return { name, email, status: "active" };
    }
    return null;
}

// File B, lines 30-45
function processOrder(order) {
    if (order.active) {
        const name = order.name.trim();
        const email = order.email.toLowerCase();
        return { name, email, status: "active" };
    }
    return null;
}
```

After normalisation, both functions produce the same token sequence (identifiers normalised), yielding a duplication match.

## 9. Metrics Findings

### Complexity Threshold Violation Finding

```json
{
  "fingerprint": "metrics-cc-abc123...",
  "rule_id": "atlas/metrics/typescript/cyclomatic-complexity",
  "severity": "medium",
  "category": "metrics",
  "file_path": "src/services/user-service.ts",
  "line_range": {
    "start_line": 15,
    "end_line": 85
  },
  "snippet": "async function getUser(id, options, context) {",
  "description": "Function 'getUser' has cyclomatic complexity of 18, exceeding the threshold of 15.",
  "remediation": "Consider breaking this function into smaller, more focused functions. Extract conditional branches into helper methods.",
  "analysis_level": "L1",
  "confidence": "high",
  "metadata": {
    "cyclomatic_complexity": 18,
    "cognitive_complexity": 32,
    "threshold": 15,
    "function_name": "getUser",
    "function_loc": 70
  }
}
```

### Duplication Finding

```json
{
  "fingerprint": "metrics-dup-def456...",
  "rule_id": "atlas/metrics/duplication",
  "severity": "low",
  "category": "metrics",
  "file_path": "src/api/users.ts",
  "line_range": {
    "start_line": 45,
    "end_line": 72
  },
  "snippet": "function processUser(user) { ...",
  "description": "27 duplicated lines (145 tokens) found in src/api/users.ts:45-72 and src/api/orders.ts:30-57.",
  "remediation": "Extract the duplicated logic into a shared utility function.",
  "analysis_level": "L1",
  "confidence": "high",
  "metadata": {
    "duplicate_location": "src/api/orders.ts:30-57",
    "token_count": 145,
    "line_count": 27
  }
}
```

## 10. Report Integration

### Full Metrics Section in JSON Report

```json
{
  "scan_metadata": { "..." : "..." },
  "findings": [ "..." ],
  "gate_result": { "..." : "..." },
  "metrics": {
    "enabled": true,
    "config": {
      "cyclomatic_max": 15,
      "cognitive_max": 25,
      "min_tokens": 100
    },
    "project": {
      "total_files": 120,
      "total_lines": 45000,
      "total_code_lines": 32000,
      "loc_by_language": {
        "TypeScript": 18000,
        "Java": 8000,
        "Python": 4000,
        "Go": 1500,
        "CSharp": 500
      },
      "total_functions": 450,
      "avg_function_loc": 28.5,
      "avg_cyclomatic": 4.2,
      "avg_cognitive": 6.8,
      "duplication_percentage": 3.5
    },
    "violations": {
      "cyclomatic_violations": 12,
      "cognitive_violations": 8,
      "duplication_blocks": 5
    }
  }
}
```
