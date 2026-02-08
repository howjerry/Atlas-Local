## ADDED Requirements

### Requirement: Quality rule YAML schema
Each quality rule SHALL be a YAML file in `rules/builtin/{language}/` following the declarative rule schema with these mandatory fields: `id` (format `atlas/quality/{language}/{rule-name}`), `name`, `description`, `severity`, `category` (value `quality`), `language`, `pattern` (tree-sitter S-expression), `remediation`, `references`, `tags` (MUST include `code-quality` and one domain tag), `version`, `confidence`, and `metadata` (MUST include `quality_domain`). The `cwe_id` field MUST be omitted.

#### Scenario: Valid quality rule loads successfully
- **WHEN** the rule loader processes a YAML file with `category: quality`, valid tree-sitter pattern, tags including `code-quality` and `error-handling`, and `metadata.quality_domain: "error-handling"`
- **THEN** a `Rule` struct is produced with `category == Quality`, `cwe_id == None`, and `metadata["quality_domain"] == "error-handling"`

#### Scenario: Quality rule without cwe_id
- **WHEN** a quality rule YAML omits the `cwe_id` field
- **THEN** the loaded rule has `cwe_id: None` and findings produced by this rule have `cwe_id: null` in all output formats

### Requirement: Quality rule test fixtures
Each quality rule SHALL have a `fail.{ext}` fixture containing code that MUST trigger the rule, and a `pass.{ext}` fixture containing code that MUST NOT trigger the rule. Pass fixtures SHALL use fundamentally different code patterns rather than calling the same function with safe arguments.

#### Scenario: Fail fixture triggers rule
- **WHEN** the L1 engine evaluates `rules/builtin/typescript/tests/empty-catch-block/fail.ts`
- **THEN** at least one finding is produced with `rule_id: "atlas/quality/typescript/empty-catch-block"`

#### Scenario: Pass fixture produces no findings
- **WHEN** the L1 engine evaluates `rules/builtin/typescript/tests/empty-catch-block/pass.ts`
- **THEN** zero findings are produced for the `empty-catch-block` rule

### Requirement: Metadata plumbing from rule to finding
The `Rule` struct SHALL include a `metadata: BTreeMap<String, serde_json::Value>` field. The L1 engine SHALL copy the rule's `metadata` map into `Finding.metadata` for every match. Existing rules with no `metadata` key in YAML SHALL produce findings with an empty metadata map (backward compatible).

#### Scenario: Quality domain appears in finding metadata
- **WHEN** a quality rule with `metadata: { quality_domain: "debug-residual" }` matches a code pattern
- **THEN** the resulting `Finding.metadata` contains `{ "quality_domain": "debug-residual" }`

#### Scenario: Existing security rule metadata is unaffected
- **WHEN** a security rule YAML with no `metadata` key produces a finding
- **THEN** the resulting `Finding.metadata` is an empty map (no regression)

### Requirement: TypeScript quality rules (10 rules)
The system SHALL provide 10 TypeScript quality rules: `empty-catch-block` (medium/error-handling), `console-log` (low/debug-residual), `any-type-usage` (low/type-safety), `loose-equality` (medium/best-practices), `var-declaration` (low/best-practices), `non-null-assertion` (info/best-practices), `todo-comment` (info/maintainability), `empty-function-body` (low/maintainability), `redundant-boolean` (low/best-practices), `excessive-parameters` (medium/maintainability).

#### Scenario: All TypeScript quality rules load
- **WHEN** the declarative rule loader scans `rules/builtin/typescript/`
- **THEN** at least 10 rules with `category == Quality` are loaded alongside the existing 5 security rules (15 total)

#### Scenario: empty-catch-block detects empty catch body
- **WHEN** scanning TypeScript code `try { riskyOp() } catch (e) { }`
- **THEN** a finding is produced with `rule_id: "atlas/quality/typescript/empty-catch-block"`, `severity: "medium"`, `category: "quality"`

#### Scenario: console-log detects debug output
- **WHEN** scanning TypeScript code `console.log("debug value:", x)`
- **THEN** a finding is produced with `rule_id: "atlas/quality/typescript/console-log"`, `severity: "low"`

#### Scenario: loose-equality detects == operator
- **WHEN** scanning TypeScript code `if (x == null)`
- **THEN** a finding is produced with `rule_id: "atlas/quality/typescript/loose-equality"`, `severity: "medium"`

### Requirement: Java quality rules (7 rules)
The system SHALL provide 7 Java quality rules: `empty-catch-block` (medium/error-handling), `system-out-println` (low/debug-residual), `todo-comment` (info/maintainability), `empty-method-body` (low/maintainability), `redundant-boolean` (low/best-practices), `string-concat-in-loop` (medium/performance), `raw-type-usage` (low/type-safety).

#### Scenario: All Java quality rules load
- **WHEN** the declarative rule loader scans `rules/builtin/java/`
- **THEN** at least 7 rules with `category == Quality` are loaded alongside the existing 4 security rules (11 total)

#### Scenario: system-out-println detects debug output
- **WHEN** scanning Java code `System.out.println("debug");`
- **THEN** a finding is produced with `rule_id: "atlas/quality/java/system-out-println"`, `severity: "low"`

#### Scenario: string-concat-in-loop detects concatenation
- **WHEN** scanning Java code containing `result += item.toString()` inside a `for` loop
- **THEN** a finding is produced with `rule_id: "atlas/quality/java/string-concat-in-loop"`, `severity: "medium"`

### Requirement: Python quality rules (7 rules)
The system SHALL provide 7 Python quality rules: `bare-except` (medium/error-handling), `print-statement` (low/debug-residual), `pass-in-except` (medium/error-handling), `mutable-default-arg` (medium/best-practices), `todo-comment` (info/maintainability), `empty-function-body` (low/maintainability), `magic-number` (low/maintainability).

#### Scenario: All Python quality rules load
- **WHEN** the declarative rule loader scans `rules/builtin/python/`
- **THEN** at least 7 rules with `category == Quality` are loaded alongside the existing 4 security rules (11 total)

#### Scenario: bare-except detects bare except clause
- **WHEN** scanning Python code `except:\n    pass`
- **THEN** a finding is produced with `rule_id: "atlas/quality/python/bare-except"`, `severity: "medium"`

#### Scenario: mutable-default-arg detects list default
- **WHEN** scanning Python code `def add_item(item, items=[]):`
- **THEN** a finding is produced with `rule_id: "atlas/quality/python/mutable-default-arg"`, `severity: "medium"`

### Requirement: Go quality rules (6 rules)
The system SHALL provide 6 Go quality rules: `empty-error-check` (medium/error-handling), `fmt-println` (low/debug-residual), `defer-in-loop` (medium/performance), `unchecked-error` (high/error-handling), `todo-comment` (info/maintainability), `empty-function-body` (low/maintainability).

#### Scenario: All Go quality rules load
- **WHEN** the declarative rule loader scans `rules/builtin/go/`
- **THEN** at least 6 rules with `category == Quality` are loaded alongside the existing 3 security rules (9 total)

#### Scenario: defer-in-loop detects defer in for loop
- **WHEN** scanning Go code containing `defer file.Close()` inside a `for` loop
- **THEN** a finding is produced with `rule_id: "atlas/quality/go/defer-in-loop"`, `severity: "medium"`

#### Scenario: empty-error-check detects empty if-err block
- **WHEN** scanning Go code `if err != nil { }`
- **THEN** a finding is produced with `rule_id: "atlas/quality/go/empty-error-check"`, `severity: "medium"`

### Requirement: C# quality rules (6 rules)
The system SHALL provide 6 C# quality rules: `empty-catch-block` (medium/error-handling), `console-writeline` (low/debug-residual), `todo-comment` (info/maintainability), `empty-method-body` (low/maintainability), `redundant-boolean` (low/best-practices), `object-type-usage` (low/type-safety).

#### Scenario: All C# quality rules load
- **WHEN** the declarative rule loader scans `rules/builtin/csharp/`
- **THEN** at least 6 rules with `category == Quality` are loaded alongside the existing 5 security rules (11 total)

#### Scenario: console-writeline detects debug output
- **WHEN** scanning C# code `Console.WriteLine("debug");`
- **THEN** a finding is produced with `rule_id: "atlas/quality/csharp/console-writeline"`, `severity: "low"`

### Requirement: Quality findings use correct SARIF levels
Quality findings SHALL map to SARIF `level` as follows: Critical/High → `error`, Medium → `warning`, Low/Info → `note`. This differentiates quality findings from security findings which typically use `error`.

#### Scenario: Medium quality finding produces SARIF warning
- **WHEN** an `empty-catch-block` finding (severity: medium) is serialized to SARIF
- **THEN** the SARIF result has `level: "warning"`

#### Scenario: Low quality finding produces SARIF note
- **WHEN** a `console-log` finding (severity: low) is serialized to SARIF
- **THEN** the SARIF result has `level: "note"`

### Requirement: Quality gate independence
Quality findings SHALL participate in `category_overrides.quality` gate evaluation independently from security findings. When no `category_overrides.quality` is configured, quality findings SHALL fall back to global `fail_on` thresholds.

#### Scenario: Quality gate passes while security gate fails
- **WHEN** a policy has `fail_on: { critical: 0 }` and `category_overrides: { quality: { medium: 50 } }`, and a scan produces 1 critical security finding and 10 medium quality findings
- **THEN** the security gate result is FAIL (1 critical > 0 threshold) and the quality gate is evaluated separately (10 medium < 50 threshold)

#### Scenario: Quality falls back to global thresholds
- **WHEN** a policy has `fail_on: { medium: 5 }` with no `category_overrides.quality`, and a scan produces 10 medium quality findings
- **THEN** the gate result is FAIL because quality findings are counted against the global medium threshold

### Requirement: Non-regression of existing rules
Adding quality rules SHALL NOT modify any existing YAML rule files or their test fixtures. All 27 security rules and 6 secrets rules SHALL continue to pass their test fixtures without modification.

#### Scenario: Security rules unaffected
- **WHEN** all rules are loaded after adding 36 quality rules
- **THEN** the 27 security rules and 6 secrets rules produce the same findings on their existing test fixtures as before

### Requirement: Rule count assertion updates
The `load_builtin_{lang}_rules_from_disk()` tests in `declarative.rs` SHALL be updated to reflect the new total rule counts per language: TypeScript 15 (5+10), Java 11 (4+7), Python 11 (4+7), Go 9 (3+6), C# 11 (5+6). Secrets count (6) SHALL remain unchanged.

#### Scenario: TypeScript rule count updated
- **WHEN** the `load_builtin_typescript_rules_from_disk()` test runs
- **THEN** it asserts exactly 15 rules are loaded

#### Scenario: Secrets rule count unchanged
- **WHEN** the `load_builtin_secrets_rules_from_disk()` test runs
- **THEN** it asserts exactly 6 rules are loaded (unchanged)
