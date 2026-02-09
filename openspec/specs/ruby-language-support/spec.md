## ADDED Requirements

### Requirement: Ruby language detection
The system SHALL detect `.rb` files as Ruby language and apply Ruby-specific rules during scanning.

#### Scenario: Ruby file detected by extension
- **WHEN** a file with `.rb` extension is encountered during scanning
- **THEN** the system identifies it as `Language::Ruby` and parses it with the Ruby tree-sitter grammar

#### Scenario: Non-Ruby file ignored by Ruby rules
- **WHEN** a file with `.py` extension is encountered
- **THEN** Ruby rules are NOT applied to it

### Requirement: Ruby LanguageAdapter implementation
The system SHALL provide a `RubyAdapter` implementing `LanguageAdapter` trait with Ruby-specific tree-sitter grammar, file extensions (`rb`), and comment prefix (`#`).

#### Scenario: Ruby adapter parses valid Ruby
- **WHEN** a valid Ruby source file is parsed by `RubyAdapter`
- **THEN** a tree-sitter AST is returned without errors

#### Scenario: Ruby adapter registered in AdapterRegistry
- **WHEN** `ScanEngine` is initialized
- **THEN** `AdapterRegistry` contains a Ruby adapter accessible by `Language::Ruby` and extension `rb`

### Requirement: Ruby security rules
The system SHALL include at least 10 security rules for Ruby covering SQL injection, command injection, XSS, path traversal, dynamic code execution, open redirect, unsafe YAML load, mass assignment, weak crypto, and hardcoded secrets.

#### Scenario: SQL injection via string interpolation detected
- **WHEN** a Ruby file contains `User.where("name = '#{params[:name]}'")`
- **THEN** a finding is produced with `rule_id: "atlas/security/ruby/sql-injection"` and `severity: critical`

#### Scenario: Command injection via backticks detected
- **WHEN** a Ruby file contains `` `#{user_input}` `` or `system(user_input)`
- **THEN** a finding is produced with `rule_id: "atlas/security/ruby/command-injection"` and `severity: critical`

#### Scenario: Safe Ruby code produces no security findings
- **WHEN** a Ruby file uses parameterised queries like `User.where(name: name)`
- **THEN** no SQL injection finding is produced

### Requirement: Ruby quality rules
The system SHALL include at least 15 quality rules for Ruby covering error-handling (empty rescue, bare rescue, unused exception variable), debug residual (puts, p), maintainability (todo comment, empty method body, empty conditional, magic number, nested ternary, excessive parameters), best-practices (redundant boolean, global variable, class variable), and performance (string concat in loop).

#### Scenario: Empty rescue block detected
- **WHEN** a Ruby file contains `rescue => e; end` with empty body
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/ruby/empty-rescue-block"` and `metadata.quality_domain: "error-handling"`

#### Scenario: Debug puts residual detected
- **WHEN** a Ruby file contains `puts variable`
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/ruby/puts-residual"` and `metadata.quality_domain: "debug-residual"`

### Requirement: Ruby rule test fixtures
Every Ruby rule SHALL have a `fail.rb` and `pass.rb` test fixture. Fail fixtures MUST trigger the rule. Pass fixtures MUST NOT trigger the rule.

#### Scenario: All Ruby rules have test fixtures
- **WHEN** Ruby rules are loaded from disk
- **THEN** each rule has corresponding `rules/builtin/ruby/tests/{rule-name}/fail.rb` and `pass.rb` files

#### Scenario: Fail fixture triggers rule
- **WHEN** a Ruby rule's `fail.rb` fixture is scanned
- **THEN** at least one finding is produced matching the rule ID

#### Scenario: Pass fixture does not trigger rule
- **WHEN** a Ruby rule's `pass.rb` fixture is scanned
- **THEN** zero findings are produced for that rule
