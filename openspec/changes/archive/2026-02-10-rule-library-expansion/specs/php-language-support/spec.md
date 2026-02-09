## ADDED Requirements

### Requirement: PHP language detection
The system SHALL detect `.php` files as PHP language and apply PHP-specific rules during scanning.

#### Scenario: PHP file detected by extension
- **WHEN** a file with `.php` extension is encountered during scanning
- **THEN** the system identifies it as `Language::Php` and parses it with the PHP tree-sitter grammar

#### Scenario: Mixed HTML+PHP file parsed correctly
- **WHEN** a `.php` file containing mixed HTML and PHP code is encountered
- **THEN** the PHP grammar correctly parses PHP code blocks within the file

### Requirement: PHP LanguageAdapter implementation
The system SHALL provide a `PhpAdapter` implementing `LanguageAdapter` trait with PHP-specific tree-sitter grammar (`LANGUAGE_PHP`), file extensions (`php`), and comment prefix (`//`).

#### Scenario: PHP adapter parses valid PHP
- **WHEN** a valid PHP source file (with `<?php` tag) is parsed by `PhpAdapter`
- **THEN** a tree-sitter AST is returned without errors

#### Scenario: PHP adapter registered in AdapterRegistry
- **WHEN** `ScanEngine` is initialized
- **THEN** `AdapterRegistry` contains a PHP adapter accessible by `Language::Php` and extension `php`

### Requirement: PHP security rules
The system SHALL include at least 10 security rules for PHP covering SQL injection, command injection, XSS, path traversal, code injection (eval), unsafe unserialize, file inclusion, weak crypto, open redirect, and SSRF.

#### Scenario: SQL injection via concatenation detected
- **WHEN** a PHP file contains `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id'])`
- **THEN** a finding is produced with `rule_id: "atlas/security/php/sql-injection"` and `severity: critical`

#### Scenario: Unsafe unserialize detected
- **WHEN** a PHP file contains `unserialize($_POST['data'])`
- **THEN** a finding is produced with `rule_id: "atlas/security/php/unserialize"` and `severity: critical`

#### Scenario: Safe PHP code produces no security findings
- **WHEN** a PHP file uses prepared statements like `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?")`
- **THEN** no SQL injection finding is produced

### Requirement: PHP quality rules
The system SHALL include at least 15 quality rules for PHP covering error-handling (empty catch block, error suppression, bare exception), debug residual (var_dump, print_r), maintainability (todo comment, empty function body, empty conditional, magic number, nested ternary, excessive parameters), and best-practices (loose comparison, redundant boolean, global statement, exit usage).

#### Scenario: var_dump residual detected
- **WHEN** a PHP file contains `var_dump($variable)`
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/php/var-dump-residual"` and `metadata.quality_domain: "debug-residual"`

#### Scenario: Loose comparison detected
- **WHEN** a PHP file contains `if ($a == $b)`
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/php/loose-comparison"` and `metadata.quality_domain: "best-practices"`

### Requirement: PHP rule test fixtures
Every PHP rule SHALL have a `fail.php` and `pass.php` test fixture. Fail fixtures MUST trigger the rule. Pass fixtures MUST NOT trigger the rule.

#### Scenario: All PHP rules have test fixtures
- **WHEN** PHP rules are loaded from disk
- **THEN** each rule has corresponding `rules/builtin/php/tests/{rule-name}/fail.php` and `pass.php` files

#### Scenario: Fail fixture triggers rule
- **WHEN** a PHP rule's `fail.php` fixture is scanned
- **THEN** at least one finding is produced matching the rule ID

#### Scenario: Pass fixture does not trigger rule
- **WHEN** a PHP rule's `pass.php` fixture is scanned
- **THEN** zero findings are produced for that rule
