## ADDED Requirements

### Requirement: Kotlin language detection
The system SHALL detect `.kt` and `.kts` files as Kotlin language and apply Kotlin-specific rules during scanning.

#### Scenario: Kotlin file detected by .kt extension
- **WHEN** a file with `.kt` extension is encountered during scanning
- **THEN** the system identifies it as `Language::Kotlin` and parses it with the Kotlin tree-sitter grammar

#### Scenario: Kotlin script file detected by .kts extension
- **WHEN** a file with `.kts` extension is encountered during scanning
- **THEN** the system identifies it as `Language::Kotlin`

### Requirement: Kotlin LanguageAdapter implementation
The system SHALL provide a `KotlinAdapter` implementing `LanguageAdapter` trait with Kotlin-specific tree-sitter grammar, file extensions (`kt`, `kts`), and comment prefix (`//`).

#### Scenario: Kotlin adapter parses valid Kotlin
- **WHEN** a valid Kotlin source file is parsed by `KotlinAdapter`
- **THEN** a tree-sitter AST is returned without errors

#### Scenario: Kotlin adapter registered in AdapterRegistry
- **WHEN** `ScanEngine` is initialized
- **THEN** `AdapterRegistry` contains a Kotlin adapter accessible by `Language::Kotlin` and extensions `kt`/`kts`

### Requirement: Kotlin security rules
The system SHALL include at least 8 security rules for Kotlin covering SQL injection, command injection, XSS, path traversal, insecure random, weak crypto, hardcoded secrets, and insecure deserialization.

#### Scenario: SQL injection via string template detected
- **WHEN** a Kotlin file contains `connection.prepareStatement("SELECT * FROM users WHERE id = $id")`
- **THEN** a finding is produced with `rule_id: "atlas/security/kotlin/sql-injection"` and `severity: critical`

#### Scenario: Insecure random detected
- **WHEN** a Kotlin file contains `java.util.Random()` for security-sensitive operations
- **THEN** a finding is produced with `rule_id: "atlas/security/kotlin/insecure-random"` and `severity: medium`

#### Scenario: Safe Kotlin code produces no security findings
- **WHEN** a Kotlin file uses parameterised queries with `?` placeholders
- **THEN** no SQL injection finding is produced

### Requirement: Kotlin quality rules
The system SHALL include at least 12 quality rules for Kotlin covering error-handling (empty catch block), debug residual (println), maintainability (todo comment, empty function body, magic number, excessive parameters, empty when branch), best-practices (redundant boolean, var could be val), type-safety (unsafe cast, force unwrap), and performance (string concat in loop).

#### Scenario: println residual detected
- **WHEN** a Kotlin file contains `println("debug: $value")`
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/kotlin/println-residual"` and `metadata.quality_domain: "debug-residual"`

#### Scenario: Unsafe cast detected
- **WHEN** a Kotlin file contains `val x = obj as String` (unsafe cast)
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/kotlin/unsafe-cast"` and `metadata.quality_domain: "type-safety"`

### Requirement: Kotlin rule test fixtures
Every Kotlin rule SHALL have a `fail.kt` and `pass.kt` test fixture. Fail fixtures MUST trigger the rule. Pass fixtures MUST NOT trigger the rule.

#### Scenario: All Kotlin rules have test fixtures
- **WHEN** Kotlin rules are loaded from disk
- **THEN** each rule has corresponding `rules/builtin/kotlin/tests/{rule-name}/fail.kt` and `pass.kt` files

#### Scenario: Fail fixture triggers rule
- **WHEN** a Kotlin rule's `fail.kt` fixture is scanned
- **THEN** at least one finding is produced matching the rule ID

#### Scenario: Pass fixture does not trigger rule
- **WHEN** a Kotlin rule's `pass.kt` fixture is scanned
- **THEN** zero findings are produced for that rule
