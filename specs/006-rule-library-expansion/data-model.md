# Data Model: Rule Library Expansion

**Feature**: 006-rule-library-expansion
**Created**: 2026-02-08
**Purpose**: Define the language adapter interface, new language enum variants, and rule distribution data model.

## 1. Language Enum Extension

### Current State

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    TypeScript,
    Java,
    Python,
    Go,
    CSharp,
    Secrets,
}
```

### Target State

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    TypeScript,
    Java,
    Python,
    Go,
    CSharp,
    Ruby,       // NEW
    Php,        // NEW
    Kotlin,     // NEW
    Secrets,
}
```

### Language Metadata

| Language | Enum Variant | File Extensions | tree-sitter Crate | Comment Prefix |
|----------|-------------|-----------------|-------------------|---------------|
| TypeScript | `TypeScript` | `.ts`, `.tsx`, `.js`, `.jsx` | `tree-sitter-typescript` | `//` |
| Java | `Java` | `.java` | `tree-sitter-java` | `//` |
| Python | `Python` | `.py` | `tree-sitter-python` | `#` |
| Go | `Go` | `.go` | `tree-sitter-go` | `//` |
| C# | `CSharp` | `.cs` | `tree-sitter-c-sharp` | `//` |
| Ruby | `Ruby` | `.rb` | `tree-sitter-ruby` | `#` |
| PHP | `Php` | `.php` | `tree-sitter-php` | `//` |
| Kotlin | `Kotlin` | `.kt`, `.kts` | `tree-sitter-kotlin` | `//` |
| Secrets | `Secrets` | (all files) | N/A (regex-based) | N/A |

## 2. Language Adapter Interface

Each language requires an adapter that implements the core trait for language integration.

### Trait Definition

```rust
/// Adapter for integrating a programming language into the scan engine.
pub trait LanguageAdapter: Send + Sync {
    /// Returns the Language enum variant for this adapter.
    fn language(&self) -> Language;

    /// Returns the file extensions this language handles.
    fn file_extensions(&self) -> &[&str];

    /// Returns the tree-sitter language grammar.
    fn grammar(&self) -> tree_sitter::Language;

    /// Returns the single-line comment prefix for inline suppression matching.
    fn comment_prefix(&self) -> &str;

    /// Returns the YAML rule directory name for this language.
    fn rule_directory(&self) -> &str;
}
```

### New Adapter Implementations

```rust
// crates/atlas-lang/src/ruby.rs
pub struct RubyAdapter;

impl LanguageAdapter for RubyAdapter {
    fn language(&self) -> Language { Language::Ruby }
    fn file_extensions(&self) -> &[&str] { &["rb"] }
    fn grammar(&self) -> tree_sitter::Language { tree_sitter_ruby::language() }
    fn comment_prefix(&self) -> &str { "#" }
    fn rule_directory(&self) -> &str { "ruby" }
}

// crates/atlas-lang/src/php.rs
pub struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language(&self) -> Language { Language::Php }
    fn file_extensions(&self) -> &[&str] { &["php"] }
    fn grammar(&self) -> tree_sitter::Language { tree_sitter_php::language_php() }
    fn comment_prefix(&self) -> &str { "//" }
    fn rule_directory(&self) -> &str { "php" }
}

// crates/atlas-lang/src/kotlin.rs
pub struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    fn language(&self) -> Language { Language::Kotlin }
    fn file_extensions(&self) -> &[&str] { &["kt", "kts"] }
    fn grammar(&self) -> tree_sitter::Language { tree_sitter_kotlin::language() }
    fn comment_prefix(&self) -> &str { "//" }
    fn rule_directory(&self) -> &str { "kotlin" }
}
```

## 3. New Security Rule Catalog

### Ruby Security Rules (10 rules)

| # | Rule ID | Name | CWE | Severity |
|---|---------|------|-----|----------|
| 1 | `atlas/security/ruby/sql-injection` | SQL Injection via interpolation | CWE-89 | Critical |
| 2 | `atlas/security/ruby/command-injection` | Command injection via backticks/system | CWE-78 | Critical |
| 3 | `atlas/security/ruby/xss` | Cross-site scripting via raw output | CWE-79 | High |
| 4 | `atlas/security/ruby/path-traversal` | Path traversal via File.read | CWE-22 | High |
| 5 | `atlas/security/ruby/dynamic-code-execution` | Dangerous dynamic code execution | CWE-95 | Critical |
| 6 | `atlas/security/ruby/open-redirect` | Open redirect via redirect_to | CWE-601 | Medium |
| 7 | `atlas/security/ruby/yaml-load` | Unsafe YAML.load (deserialisation) | CWE-502 | High |
| 8 | `atlas/security/ruby/mass-assignment` | Unprotected mass assignment | CWE-915 | High |
| 9 | `atlas/security/ruby/weak-crypto` | Weak cryptographic algorithm | CWE-327 | Medium |
| 10 | `atlas/security/ruby/hardcoded-secret` | Hardcoded secret in source | CWE-798 | High |

### PHP Security Rules (10 rules)

| # | Rule ID | Name | CWE | Severity |
|---|---------|------|-----|----------|
| 1 | `atlas/security/php/sql-injection` | SQL injection via concatenation | CWE-89 | Critical |
| 2 | `atlas/security/php/command-injection` | Command injection via system functions | CWE-78 | Critical |
| 3 | `atlas/security/php/xss` | XSS via echo without escaping | CWE-79 | High |
| 4 | `atlas/security/php/path-traversal` | Path traversal via file functions | CWE-22 | High |
| 5 | `atlas/security/php/code-injection` | Dangerous dynamic code execution | CWE-95 | Critical |
| 6 | `atlas/security/php/unserialize` | Unsafe unserialize on user input | CWE-502 | Critical |
| 7 | `atlas/security/php/file-inclusion` | Local/remote file inclusion | CWE-98 | Critical |
| 8 | `atlas/security/php/weak-crypto` | Weak cryptographic function (md5/sha1) | CWE-327 | Medium |
| 9 | `atlas/security/php/open-redirect` | Open redirect via header() | CWE-601 | Medium |
| 10 | `atlas/security/php/ssrf` | Server-side request forgery | CWE-918 | High |

### Kotlin Security Rules (8 rules)

| # | Rule ID | Name | CWE | Severity |
|---|---------|------|-----|----------|
| 1 | `atlas/security/kotlin/sql-injection` | SQL injection via string template | CWE-89 | Critical |
| 2 | `atlas/security/kotlin/command-injection` | Command injection via Runtime.exec | CWE-78 | Critical |
| 3 | `atlas/security/kotlin/xss` | Cross-site scripting | CWE-79 | High |
| 4 | `atlas/security/kotlin/path-traversal` | Path traversal via File constructor | CWE-22 | High |
| 5 | `atlas/security/kotlin/insecure-random` | Insecure random number generation | CWE-330 | Medium |
| 6 | `atlas/security/kotlin/weak-crypto` | Weak cryptographic algorithm | CWE-327 | Medium |
| 7 | `atlas/security/kotlin/hardcoded-secret` | Hardcoded secret in source | CWE-798 | High |
| 8 | `atlas/security/kotlin/insecure-deserialization` | Unsafe deserialization | CWE-502 | High |

## 4. New Quality Rule Catalog

### Ruby Quality Rules (15 rules)

| # | Rule ID | Quality Domain |
|---|---------|---------------|
| 1 | `atlas/quality/ruby/empty-rescue-block` | error-handling |
| 2 | `atlas/quality/ruby/puts-residual` | debug-residual |
| 3 | `atlas/quality/ruby/todo-comment` | maintainability |
| 4 | `atlas/quality/ruby/empty-method-body` | maintainability |
| 5 | `atlas/quality/ruby/redundant-boolean` | best-practices |
| 6 | `atlas/quality/ruby/bare-rescue` | error-handling |
| 7 | `atlas/quality/ruby/global-variable` | best-practices |
| 8 | `atlas/quality/ruby/class-variable` | best-practices |
| 9 | `atlas/quality/ruby/magic-number` | maintainability |
| 10 | `atlas/quality/ruby/nested-ternary` | maintainability |
| 11 | `atlas/quality/ruby/excessive-parameters` | maintainability |
| 12 | `atlas/quality/ruby/string-concat-in-loop` | performance |
| 13 | `atlas/quality/ruby/empty-conditional` | maintainability |
| 14 | `atlas/quality/ruby/p-debug` | debug-residual |
| 15 | `atlas/quality/ruby/unused-exception-variable` | error-handling |

### PHP Quality Rules (15 rules)

| # | Rule ID | Quality Domain |
|---|---------|---------------|
| 1 | `atlas/quality/php/empty-catch-block` | error-handling |
| 2 | `atlas/quality/php/var-dump-residual` | debug-residual |
| 3 | `atlas/quality/php/todo-comment` | maintainability |
| 4 | `atlas/quality/php/empty-function-body` | maintainability |
| 5 | `atlas/quality/php/loose-comparison` | best-practices |
| 6 | `atlas/quality/php/error-suppression` | error-handling |
| 7 | `atlas/quality/php/print-r-residual` | debug-residual |
| 8 | `atlas/quality/php/magic-number` | maintainability |
| 9 | `atlas/quality/php/excessive-parameters` | maintainability |
| 10 | `atlas/quality/php/empty-conditional` | maintainability |
| 11 | `atlas/quality/php/redundant-boolean` | best-practices |
| 12 | `atlas/quality/php/global-statement` | best-practices |
| 13 | `atlas/quality/php/exit-usage` | best-practices |
| 14 | `atlas/quality/php/nested-ternary` | maintainability |
| 15 | `atlas/quality/php/bare-exception` | error-handling |

### Kotlin Quality Rules (12 rules)

| # | Rule ID | Quality Domain |
|---|---------|---------------|
| 1 | `atlas/quality/kotlin/empty-catch-block` | error-handling |
| 2 | `atlas/quality/kotlin/println-residual` | debug-residual |
| 3 | `atlas/quality/kotlin/todo-comment` | maintainability |
| 4 | `atlas/quality/kotlin/empty-function-body` | maintainability |
| 5 | `atlas/quality/kotlin/redundant-boolean` | best-practices |
| 6 | `atlas/quality/kotlin/unsafe-cast` | type-safety |
| 7 | `atlas/quality/kotlin/magic-number` | maintainability |
| 8 | `atlas/quality/kotlin/excessive-parameters` | maintainability |
| 9 | `atlas/quality/kotlin/var-could-be-val` | best-practices |
| 10 | `atlas/quality/kotlin/force-unwrap` | type-safety |
| 11 | `atlas/quality/kotlin/empty-when-branch` | maintainability |
| 12 | `atlas/quality/kotlin/string-concat-in-loop` | performance |

## 5. Expanded Secrets Rules

| # | Rule ID | Name | Pattern |
|---|---------|------|---------|
| 7 | `atlas/secrets/gcp-api-key` | GCP API Key | `AIza[0-9A-Za-z_-]{35}` |
| 8 | `atlas/secrets/azure-storage-key` | Azure Storage Account Key | Base64 88-char pattern |
| 9 | `atlas/secrets/github-pat` | GitHub Personal Access Token | `ghp_[A-Za-z0-9]{36}` |
| 10 | `atlas/secrets/gitlab-pat` | GitLab Personal Access Token | `glpat-[A-Za-z0-9_-]{20}` |
| 11 | `atlas/secrets/slack-webhook` | Slack Webhook URL | `https://hooks.slack.com/...` |
| 12 | `atlas/secrets/stripe-secret-key` | Stripe Secret Key | `sk_live_[A-Za-z0-9]{24,}` |
| 13 | `atlas/secrets/twilio-api-key` | Twilio API Key | `SK[a-f0-9]{32}` |
| 14 | `atlas/secrets/sendgrid-api-key` | SendGrid API Key | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` |
| 15 | `atlas/secrets/jwt-secret` | Hardcoded JWT Secret | `jwt[_-]?secret` assignment patterns |

## 6. Rule YAML Examples for New Languages

### Ruby Security Rule Example

```yaml
id: atlas/security/ruby/sql-injection
name: SQL Injection via String Interpolation
description: >
  Detects SQL queries constructed using Ruby string interpolation, which may
  allow SQL injection if the interpolated value comes from user input.
severity: critical
category: security
language: Ruby
cwe_id: CWE-89
pattern: |
  (call
    method: (identifier) @method
    arguments: (argument_list
      (string
        (interpolation)) @query))
  (#match? @method "^(where|find_by_sql|execute|select_all)$")
  @match
remediation: >
  Use parameterised queries: User.where("name = ?", name) or
  User.where(name: name) instead of string interpolation.
references:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://guides.rubyonrails.org/security.html#sql-injection
tags:
  - owasp-top-10
  - injection
  - sql
version: 1.0.0
confidence: high
metadata:
  compliance:
    - framework: owasp-top-10-2021
      requirement: "A03:2021"
      description: "Injection"
```

### PHP Security Rule Example

```yaml
id: atlas/security/php/sql-injection
name: SQL Injection via Concatenation
description: >
  Detects SQL queries built using string concatenation with variables,
  which may allow SQL injection attacks.
severity: critical
category: security
language: Php
cwe_id: CWE-89
pattern: |
  (function_call_expression
    function: (name) @fn
    arguments: (arguments
      (binary_expression
        operator: "."
        (variable_name) @var)))
  (#match? @fn "^(mysql_query|mysqli_query|pg_query)$")
  @match
remediation: >
  Use prepared statements with PDO or mysqli_prepare() instead of
  string concatenation for SQL queries.
references:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://www.php.net/manual/en/pdo.prepared-statements.php
tags:
  - owasp-top-10
  - injection
  - sql
version: 1.0.0
confidence: high
```

### Kotlin Quality Rule Example

```yaml
id: atlas/quality/kotlin/empty-catch-block
name: Empty Catch Block
description: >
  Detects try-catch blocks where the catch clause has an empty body.
  Empty catch blocks silently swallow exceptions, hiding errors.
severity: medium
category: quality
language: Kotlin
pattern: |
  (catch_block
    body: (statements
      .
      "}"))
  @match
remediation: >
  Handle the caught exception explicitly. Log it, re-throw it, or
  handle it with appropriate error recovery logic.
references:
  - https://detekt.dev/docs/rules/empty-blocks/
tags:
  - code-quality
  - error-handling
version: 1.0.0
confidence: high
metadata:
  quality_domain: "error-handling"
```

## 7. Cargo Feature Flags

```toml
# Cargo.toml (workspace root)
[features]
default = ["ruby", "php", "kotlin"]
ruby = ["dep:tree-sitter-ruby"]
php = ["dep:tree-sitter-php"]
kotlin = ["dep:tree-sitter-kotlin"]

[dependencies]
tree-sitter-ruby = { version = "0.21", optional = true }
tree-sitter-php = { version = "0.22", optional = true }
tree-sitter-kotlin = { version = "0.3", optional = true }
```

## 8. Test Fixture Structure

Each rule has two test fixtures:

```
rules/builtin/ruby/
├── sql-injection.yaml
├── command-injection.yaml
├── tests/
│   ├── sql-injection/
│   │   ├── fail.rb       # Contains vulnerable code that MUST trigger the rule
│   │   └── pass.rb       # Contains safe code that MUST NOT trigger the rule
│   ├── command-injection/
│   │   ├── fail.rb
│   │   └── pass.rb
│   └── ...
```

### Test Naming Convention

```rust
#[test]
fn load_builtin_ruby_rules_from_disk() {
    let rules = load_builtin_rules_for_language(Language::Ruby);
    assert_eq!(rules.len(), 25, "Expected 25 Ruby rules");
    // ... per-rule fixture testing
}

#[test]
fn load_builtin_php_rules_from_disk() {
    let rules = load_builtin_rules_for_language(Language::Php);
    assert_eq!(rules.len(), 25, "Expected 25 PHP rules");
}

#[test]
fn load_builtin_kotlin_rules_from_disk() {
    let rules = load_builtin_rules_for_language(Language::Kotlin);
    assert_eq!(rules.len(), 20, "Expected 20 Kotlin rules");
}
```
