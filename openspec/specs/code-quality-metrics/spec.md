## ADDED Requirements

### Requirement: Cyclomatic complexity computation
The system SHALL compute McCabe cyclomatic complexity for every function/method in scanned files when `--metrics` is enabled. Decision points counted: `if`, `else if`/`elif`, `for`, `while`, `do-while`, `case`, `catch`, `&&`, `||`, ternary `? :`. Base complexity is 1.

#### Scenario: Simple function with known decision points
- **WHEN** a function contains 3 if statements, 1 for loop, and 1 while loop
- **THEN** cyclomatic complexity is 6 (1 base + 5 decision points)

#### Scenario: Function with no branches
- **WHEN** a function contains only sequential statements
- **THEN** cyclomatic complexity is 1

#### Scenario: Function with switch/case
- **WHEN** a function contains a switch with 5 case branches
- **THEN** each case adds 1, yielding cyclomatic complexity of 6 (1 base + 5 cases)

### Requirement: Cyclomatic complexity threshold findings
The system SHALL produce a Finding with `category: Metrics`, `severity: medium`, and `metadata.cyclomatic_complexity` when a function exceeds the configurable `cyclomatic_max` threshold (default: 15).

#### Scenario: Function exceeds threshold
- **WHEN** a function has cyclomatic complexity 20 and threshold is 15
- **THEN** a Finding is produced with `rule_id: "atlas/metrics/{lang}/cyclomatic-complexity"`, `severity: medium`, and `metadata.cyclomatic_complexity: 20`

#### Scenario: Function within threshold
- **WHEN** a function has cyclomatic complexity 10 and threshold is 15
- **THEN** no Finding is produced, but the metric is still recorded in the metrics report

### Requirement: Cognitive complexity computation
The system SHALL compute cognitive complexity following the SonarSource specification (structural increment + nesting penalty) for every function/method. Increments: `if`, `else if`, `else`, `for`, `while`, `catch`, `switch`, `&&`, `||`, ternary, recursion. Each nesting level adds +1 to the increment.

#### Scenario: Deeply nested function
- **WHEN** a function has 4 levels of nested if/for/while
- **THEN** cognitive complexity score reflects nesting penalties and is higher than the cyclomatic score

#### Scenario: Flat function with many branches
- **WHEN** a function has 5 sequential if statements (no nesting)
- **THEN** cognitive complexity increments are all +1 (no nesting penalty)

### Requirement: Cognitive complexity threshold findings
The system SHALL produce a Finding with `severity: medium` and `metadata.cognitive_complexity` when a function exceeds the configurable `cognitive_max` threshold (default: 25).

#### Scenario: Cognitive threshold exceeded
- **WHEN** a function has cognitive complexity 30 and threshold is 25
- **THEN** a Finding is produced with `rule_id: "atlas/metrics/{lang}/cognitive-complexity"` and `metadata.cognitive_complexity: 30`

### Requirement: Token-based code duplication detection
The system SHALL detect duplicated code blocks using token-based comparison with identifier normalization (Type I + Type II clones). Duplicated blocks MUST be at least `min_tokens` tokens long (default: 100).

#### Scenario: Exact duplicate detection (Type I)
- **WHEN** two files contain identical 150-token code blocks
- **THEN** a duplication Finding is produced listing both locations and the duplicated token count

#### Scenario: Renamed variable duplicate detection (Type II)
- **WHEN** two code blocks differ only in variable names
- **THEN** they are detected as duplicates via identifier normalization

#### Scenario: Below minimum token threshold
- **WHEN** a 90-token block is duplicated and min_tokens is 100
- **THEN** no Finding is produced

### Requirement: Duplication findings
Each duplicate pair SHALL produce a Finding with `category: Metrics`, `severity: low`, listing both file locations and the duplicated token count in metadata.

#### Scenario: Duplication finding structure
- **WHEN** a 150-token duplicate pair is detected between file A and file B
- **THEN** the Finding includes `metadata.token_count: 150`, `metadata.duplicate_location` with both file paths and line ranges

### Requirement: LOC statistics
The system SHALL compute per-file and per-project line statistics: total lines, code lines (excluding blanks and comments), blank lines, and comment lines. Per-language LOC breakdowns SHALL be included in project metrics.

#### Scenario: Multi-language project LOC
- **WHEN** a project contains TypeScript (5000 LOC), Java (3000 LOC), Python (2000 LOC)
- **THEN** the report includes total_loc: 10000 and per-language breakdowns

#### Scenario: Accurate line classification
- **WHEN** a file has 100 total lines (70 code, 20 blank, 10 comment)
- **THEN** the metrics reflect code_lines: 70, blank_lines: 20, comment_lines: 10

### Requirement: Metrics CLI flag
Metrics computation SHALL be opt-in via `--metrics` CLI flag. Default scans SHALL NOT compute metrics.

#### Scenario: Metrics enabled
- **WHEN** user runs `atlas scan --metrics ./src`
- **THEN** metrics are computed and included in the report

#### Scenario: Metrics disabled by default
- **WHEN** user runs `atlas scan ./src` without `--metrics`
- **THEN** no metrics are computed and no metrics section appears in the report

### Requirement: Metrics report section
A `metrics` section SHALL be added to JSON reports containing: per-function metrics (name, complexity scores, LOC), per-file metrics (aggregates, function list), and project-level aggregates (total LOC, duplication percentage, function count averages).

#### Scenario: JSON report with metrics
- **WHEN** scan completes with `--metrics` enabled
- **THEN** the JSON report contains a `metrics` object with `files[]` (each with `functions[]`), and `project` aggregate fields

#### Scenario: JSON report without metrics
- **WHEN** scan completes without `--metrics`
- **THEN** the JSON report `metrics` field is null/absent

### Requirement: Metrics gate evaluation
Metrics findings SHALL participate in gate evaluation under `category_overrides.metrics`. The policy SHALL support severity thresholds for metrics category.

#### Scenario: Gate fails on metrics threshold
- **WHEN** policy has `category_overrides.metrics.medium: 0` and a cyclomatic complexity Finding (medium) exists
- **THEN** the gate fails

#### Scenario: Gate ignores metrics when not configured
- **WHEN** policy has no `category_overrides.metrics` section
- **THEN** metrics findings do not affect gate result

### Requirement: Performance — AST reuse
Metrics computation SHALL reuse already-parsed tree-sitter ASTs from the scan pass. No files SHALL be re-parsed for metrics.

#### Scenario: No duplicate parsing
- **WHEN** metrics is enabled alongside L1 scanning
- **THEN** each file is parsed exactly once, and the same tree-sitter Tree is used for both rule evaluation and metrics computation

### Requirement: Performance — computation time
Metrics computation for a 100,000-line project SHALL complete in less than 10 seconds (excluding AST parse time).

#### Scenario: Large project performance
- **WHEN** a 100,000-line multi-language project is scanned with `--metrics`
- **THEN** metrics computation (excluding parsing) completes in under 10 seconds
