## MODIFIED Requirements

### Requirement: CLI analysis-level flag
The system SHALL accept an `--analysis-level <L1|L2|L3>` flag on the `atlas scan` command. The default SHALL be `L1`. When set to `L2`, the scan pipeline SHALL execute L2 analysis in addition to L1 analysis. When set to `L3`, the scan pipeline SHALL execute L1, L2, and L3 analysis.

#### Scenario: Default analysis level is L1
- **WHEN** running `atlas scan ./src` without `--analysis-level`
- **THEN** only L1 analysis runs and no L2 or L3 findings are produced

#### Scenario: L2 analysis enabled via flag
- **WHEN** running `atlas scan --analysis-level L2 ./src`
- **THEN** both L1 and L2 analysis run, and L2 findings are included in the results

#### Scenario: L3 analysis enabled via flag
- **WHEN** running `atlas scan --analysis-level L3 ./src`
- **THEN** L1, L2, and L3 analysis all run, and findings from all three levels are included in the results

#### Scenario: Invalid analysis level rejected
- **WHEN** running `atlas scan --analysis-level L4 ./src`
- **THEN** the command fails with an error message indicating valid levels are L1, L2, L3

### Requirement: Taint configuration loading
The system SHALL load per-language taint configurations (sources, sinks, sanitizers) from embedded YAML files at compile time using `include_str!`. Each language (TypeScript, Java, Python, C#, Go) SHALL have a `taint_config.yaml` file containing source patterns, sink function definitions with tainted argument positions, and sanitizer function names. The system SHALL also support merging user-defined taint configurations from an `atlas-taint.yaml` file in the project root, using append semantics (custom entries add to, do not replace, defaults).

#### Scenario: Load TypeScript taint config
- **WHEN** the L2 engine initializes for TypeScript analysis
- **THEN** it loads `rules/l2/typescript/taint_config.yaml` containing at least sources (`req.body`, `req.params`, `req.query`), sinks (`db.query`, `eval`), and sanitizers (`parseInt`, `escapeHtml`)

#### Scenario: Load config for all supported languages
- **WHEN** the L2 engine initializes
- **THEN** taint configs are available for all 5 languages: TypeScript, Java, Python, C#, Go

#### Scenario: Invalid taint config format
- **WHEN** a taint config YAML file has invalid structure
- **THEN** the system SHALL return an error at compile time or during deserialization with a descriptive message

#### Scenario: Custom taint config merged with built-in
- **WHEN** an `atlas-taint.yaml` file exists in the project root with additional sources and sinks
- **THEN** the custom entries are appended to the built-in taint config for the current language

#### Scenario: Custom config does not replace built-in
- **WHEN** `atlas-taint.yaml` defines a custom source `ctx.request.body`
- **THEN** all built-in sources (e.g., `req.body`) remain active alongside the custom source
