## ADDED Requirements

### Requirement: TypeScript rule expansion to 30 rules
The system SHALL expand TypeScript rules from 15 to at least 30, adding security rules (insecure random, weak crypto, open redirect, prototype pollution, regex DoS, SSRF, hardcoded secret) and quality rules (empty conditional, nested ternary, magic number, excessive parameters, string concat in loop).

#### Scenario: TypeScript insecure random detected
- **WHEN** a TypeScript file contains `Math.random()` in security context
- **THEN** a finding is produced with `rule_id: "atlas/security/typescript/insecure-random"`

#### Scenario: TypeScript magic number detected
- **WHEN** a TypeScript file contains a numeric literal outside of common constants (0, 1, -1)
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/typescript/magic-number"`

#### Scenario: All TypeScript rules have test fixtures
- **WHEN** TypeScript rules are loaded from disk
- **THEN** at least 30 rules are loaded, each with fail/pass test fixtures

### Requirement: Java rule expansion to 25 rules
The system SHALL expand Java rules from 11 to at least 25, adding security rules (insecure random, weak crypto, open redirect, SSRF, XXE, hardcoded secret) and quality rules (empty conditional, magic number, nested ternary, excessive parameters, string concat in loop, redundant boolean, raw type usage).

#### Scenario: Java XXE vulnerability detected
- **WHEN** a Java file creates `DocumentBuilderFactory` without disabling external entities
- **THEN** a finding is produced with `rule_id: "atlas/security/java/xxe"`

#### Scenario: All Java rules have test fixtures
- **WHEN** Java rules are loaded from disk
- **THEN** at least 25 rules are loaded, each with fail/pass test fixtures

### Requirement: Python rule expansion to 25 rules
The system SHALL expand Python rules from 11 to at least 25, adding security rules (insecure random, weak crypto, open redirect, SSRF, unsafe deserialization, hardcoded secret) and quality rules (empty conditional, magic number, nested ternary, excessive parameters, string concat in loop, bare except improvement, mutable default argument).

#### Scenario: Python unsafe deserialization detected
- **WHEN** a Python file deserializes untrusted data
- **THEN** a finding is produced with appropriate security rule ID

#### Scenario: Python mutable default argument detected
- **WHEN** a Python file contains `def foo(bar=[]):`
- **THEN** a quality finding is produced with `rule_id: "atlas/quality/python/mutable-default-argument"`

#### Scenario: All Python rules have test fixtures
- **WHEN** Python rules are loaded from disk
- **THEN** at least 25 rules are loaded, each with fail/pass test fixtures

### Requirement: Go rule expansion to 20 rules
The system SHALL expand Go rules from 9 to at least 20, adding security rules (insecure random, weak crypto, open redirect, SSRF, hardcoded secret) and quality rules (empty conditional, magic number, nested ternary, excessive parameters, string concat in loop).

#### Scenario: Go insecure random detected
- **WHEN** a Go file contains `math/rand` usage for security purposes
- **THEN** a finding is produced with `rule_id: "atlas/security/go/insecure-random"`

#### Scenario: All Go rules have test fixtures
- **WHEN** Go rules are loaded from disk
- **THEN** at least 20 rules are loaded, each with fail/pass test fixtures

### Requirement: C# rule expansion to 20 rules
The system SHALL expand C# rules from 11 to at least 20, adding security rules (insecure random, weak crypto, open redirect) and quality rules (empty conditional, magic number, nested ternary, excessive parameters).

#### Scenario: C# insecure random detected
- **WHEN** a C# file contains `new Random()` for security-sensitive operations
- **THEN** a finding is produced with `rule_id: "atlas/security/csharp/insecure-random"`

#### Scenario: All C# rules have test fixtures
- **WHEN** C# rules are loaded from disk
- **THEN** at least 20 rules are loaded, each with fail/pass test fixtures

### Requirement: All new rules include compliance metadata
All new security rules SHALL include CWE mappings (`cwe_id` field) and OWASP Top 10 compliance metadata in the `metadata.compliance` field. All new quality rules SHALL include `metadata.quality_domain`.

#### Scenario: New security rule has CWE mapping
- **WHEN** a new security rule YAML is loaded
- **THEN** it contains a non-empty `cwe_id` field

#### Scenario: New quality rule has quality_domain
- **WHEN** a new quality rule YAML is loaded
- **THEN** it contains `metadata.quality_domain` with a valid domain value

### Requirement: Zero regression on existing rules
All 63 existing rules SHALL continue to pass their test fixtures after the expansion. No existing rule behavior SHALL be modified.

#### Scenario: Existing rules unaffected
- **WHEN** all existing rule test fixtures are executed after the expansion
- **THEN** all pass with zero false negatives on fail fixtures and zero false positives on pass fixtures
