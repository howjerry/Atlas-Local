# Feature Specification: Atlas Local — Rule Library Expansion to 200+

**Feature Branch**: `006-rule-library-expansion`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, L1 pattern engine), 002-code-quality-analysis (quality rule format, metadata schema)

## Overview & Scope

Atlas-Local currently ships with 63 builtin rules (27 security + 6 secrets + 30 quality) across 5 languages (TypeScript, Java, Python, Go, C#). To be competitive with established SAST tools and provide comprehensive coverage, the rule library must expand to 200+ rules, covering more vulnerability classes in existing languages and adding support for Ruby, PHP, and Kotlin.

**Purpose**: Achieve comprehensive OWASP Top 10 coverage across 8 languages with 200+ rules, making Atlas viable as a primary SAST tool rather than a supplementary scanner.

**Scope**: L1 declarative rules only (YAML + tree-sitter patterns). Three new languages (Ruby, PHP, Kotlin) with full language adapter integration. Expansion of existing language rule sets.

**Exclusions** (deferred to future specs):
- L2/L3 rules for new languages (requires 005/011 completion)
- Swift, Rust, or Scala language support
- Framework-specific rules (e.g., Rails-specific, Laravel-specific) beyond generic language patterns
- Custom rule authoring tooling or documentation
- Rule performance benchmarking framework

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Developer Scans a Ruby on Rails Project (Priority: P1)

A developer working on a Ruby project runs `atlas scan ./app` and receives security and quality findings specific to Ruby, including common vulnerabilities like SQL injection via string interpolation, command injection via backticks, and quality issues like empty rescue blocks.

**Why this priority**: Ruby is one of the most requested languages for SAST coverage, particularly due to the large Rails ecosystem. Without Ruby support, Atlas cannot serve a significant user segment.

**Independent Test**: Create a Ruby file with known vulnerabilities (SQL injection, command injection, XSS) and quality issues (empty rescue, puts residual), scan it, and verify findings are produced with correct rule IDs, severity, and metadata.

**Acceptance Scenarios**:

1. **Given** a Ruby file with `User.where("name = '#{params[:name]}'")`, **When** scanned, **Then** a finding is produced with `rule_id: "atlas/security/ruby/sql-injection"` and `severity: "critical"`.
2. **Given** a Ruby file with an empty `rescue => e; end` block, **When** scanned, **Then** a quality finding is produced with `rule_id: "atlas/quality/ruby/empty-rescue-block"`.
3. **Given** a `.rb` file extension, **When** the language detector runs, **Then** it identifies the file as Ruby and applies Ruby rules.

---

### User Story 2 — Security Team Scans a PHP Application (Priority: P1)

A security team scans a legacy PHP application for common vulnerabilities. Atlas detects PHP-specific patterns like `mysql_query` with string concatenation, dangerous dynamic code evaluation, and `unserialize()` on user input.

**Why this priority**: PHP remains one of the most deployed web languages and has a large surface area for security vulnerabilities. PHP support significantly expands Atlas's market reach.

**Independent Test**: Create PHP files with known vulnerability patterns and verify all expected findings are produced.

**Acceptance Scenarios**:

1. **Given** a PHP file with `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id'])`, **When** scanned, **Then** a SQL injection finding is produced.
2. **Given** a PHP file with dangerous dynamic code evaluation using user input, **When** scanned, **Then** a code injection finding is produced with `severity: "critical"`.
3. **Given** a mixed-language project with PHP, TypeScript, and Python files, **When** scanned, **Then** each file is analysed with the correct language rules.

---

### User Story 3 — Android Developer Scans Kotlin Code (Priority: P1)

An Android developer scans their Kotlin codebase for security issues and code quality. Atlas detects Kotlin-specific patterns including unsafe type casts, platform type assertion issues, and common Android security mistakes.

**Why this priority**: Kotlin is the primary language for Android development and increasingly used for backend services. It fills a gap in JVM language coverage alongside Java.

**Independent Test**: Create Kotlin files with security vulnerabilities and quality issues, scan them, and verify correct detection.

**Acceptance Scenarios**:

1. **Given** a Kotlin file with SQL string concatenation in a Room database query, **When** scanned, **Then** a SQL injection finding is produced.
2. **Given** a Kotlin file with `println()` debug statements, **When** scanned, **Then** a quality finding is produced with `rule_id: "atlas/quality/kotlin/println-residual"`.
3. **Given** Kotlin files with `.kt` and `.kts` extensions, **When** scanned, **Then** both are detected as Kotlin.

---

### User Story 4 — Security Engineer Reviews OWASP Coverage Gaps (Priority: P2)

A security engineer runs `atlas compliance coverage owasp-top-10-2021` (from spec 003) after the rule expansion and sees improved coverage across all 10 categories. The expanded rule set closes coverage gaps that existed with 27 security rules.

**Why this priority**: Rule expansion is only valuable if it improves coverage meaningfully. OWASP coverage is the industry benchmark.

**Independent Test**: Compare OWASP coverage percentages before and after rule expansion, verify coverage increased for at least 3 categories.

**Acceptance Scenarios**:

1. **Given** the expanded 200+ rule set, **When** OWASP coverage is computed, **Then** at least 9 of 10 OWASP categories have rule coverage (up from ~7).
2. **Given** rules across 8 languages, **When** coverage is computed per language, **Then** each language covers at least 5 OWASP categories.

---

### Edge Cases

- What happens when a Ruby file uses ERB templates? ERB files (`.erb`) are out of scope for initial Ruby support. Only pure `.rb` files are scanned.
- What happens with PHP files that mix HTML and PHP? The tree-sitter-php grammar handles embedded PHP in HTML. Rules target PHP code blocks only.
- What happens with Kotlin/Java interop? Each file is scanned independently by its language's rules. Cross-language analysis is not performed.
- What happens with new language grammars that have different node types than expected? Each new grammar requires AST research (like the existing `research.md` pattern). Tree-sitter playground testing is essential before rule authoring.

## Requirements *(mandatory)*

### Functional Requirements

**New Language Support**

- **FR-R01**: Atlas MUST support Ruby (`.rb`) with a `Language::Ruby` enum variant and corresponding tree-sitter grammar (`tree-sitter-ruby`).
- **FR-R02**: Atlas MUST support PHP (`.php`) with a `Language::Php` enum variant and corresponding tree-sitter grammar (`tree-sitter-php`).
- **FR-R03**: Atlas MUST support Kotlin (`.kt`, `.kts`) with a `Language::Kotlin` enum variant and corresponding tree-sitter grammar (`tree-sitter-kotlin`).
- **FR-R04**: Each new language MUST have a `LanguageAdapter` implementation supporting: file extension detection, tree-sitter grammar initialisation, and comment syntax (for inline suppression).
- **FR-R05**: New languages MUST participate in all existing features: policy gating, baseline comparison, report output, and inline suppression.

**Rule Expansion Targets**

- **FR-R06**: The total rule count MUST reach at least 200 (security + secrets + quality combined).
- **FR-R07**: Each existing language (TypeScript, Java, Python, Go, C#) MUST have at least 20 rules.
- **FR-R08**: Each new language (Ruby, PHP, Kotlin) MUST have at least 15 rules (security + quality).
- **FR-R09**: The secrets rule set MUST expand to at least 15 rules (from current 6).
- **FR-R10**: New security rules MUST include CWE mappings and OWASP Top 10 compliance metadata (per spec 003).

**Rule Quality**

- **FR-R11**: Every new rule MUST have a `fail.{ext}` and `pass.{ext}` test fixture.
- **FR-R12**: Security rules MUST achieve < 15% false positive rate when tested against 3 mainstream open-source projects per language.
- **FR-R13**: Quality rules MUST follow the metadata schema from spec 002 (quality_domain, confidence, remediation).

**Dependency Management**

- **FR-R14**: New tree-sitter grammar crates MUST be added to the workspace `Cargo.toml` as optional dependencies behind feature flags.
- **FR-R15**: Language support SHOULD be individually toggleable via Cargo feature flags (e.g., `--features ruby,php,kotlin`) with all enabled by default.

### Key Entities

- **Language** (extended): Enum with 3 new variants: `Ruby`, `Php`, `Kotlin`.
- **LanguageAdapter** (new implementations): Ruby, PHP, and Kotlin adapters implementing `file_extensions()`, `grammar()`, `comment_prefix()`.
- **Rule** (unchanged): Uses existing YAML schema. New rules are pure data additions.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-R01**: Total rule count reaches at least 205 (142 new + 63 existing).
- **SC-R02**: All new rules pass their `fail.{ext}` and `pass.{ext}` test fixtures with zero false negatives on fail fixtures and zero false positives on pass fixtures.
- **SC-R03**: Ruby, PHP, and Kotlin files are correctly detected by extension and parsed without errors on 10 sample files per language.
- **SC-R04**: All 63 existing rules continue to pass their test fixtures (zero regression).
- **SC-R05**: A full scan of a 100,000-line polyglot project (8 languages) with 200+ rules completes in < 60 seconds on a 4-core machine.
- **SC-R06**: Each new language covers at least 5 OWASP Top 10 categories with security rules.
- **SC-R07**: Secrets rules expand from 6 to at least 15, covering: AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid tokens.

## Assumptions

- `tree-sitter-ruby`, `tree-sitter-php`, and `tree-sitter-kotlin` crates are available on crates.io and produce stable ASTs.
- The existing L1 pattern engine handles all tree-sitter query features needed by new language rules.
- New language rules are expressible as L1 patterns (tree-sitter queries) without requiring L2/L3 analysis.
- The build time increase from 3 additional tree-sitter grammars is acceptable (estimated +30 seconds).

## Scope Boundaries

**In Scope**:
- 3 new languages: Ruby, PHP, Kotlin
- 3 new LanguageAdapter implementations
- ~142 new YAML rules with test fixtures (~284 test files)
- Expansion of existing language rule sets
- Secrets rule expansion to 15+
- Language enum extension
- Feature flag–gated grammar dependencies

**Out of Scope**:
- L2/L3 rules for new languages
- Framework-specific rules (Rails, Laravel, Ktor, etc.)
- Swift, Rust, Scala, or other language additions
- Custom rule authoring documentation
- Rule performance benchmarking
- ERB, JSP, Jinja, or other template language support

## Implementation Notes

### Rule Distribution Target

| Language | Current | Security Target | Quality Target | Secrets Target | Total Target | New Rules |
|----------|---------|----------------|----------------|----------------|-------------|-----------|
| TypeScript | 15 | 12 | 18 | — | 30 | +15 |
| Java | 11 | 10 | 15 | — | 25 | +14 |
| Python | 11 | 10 | 15 | — | 25 | +14 |
| Go | 9 | 8 | 12 | — | 20 | +11 |
| C# | 11 | 8 | 12 | — | 20 | +9 |
| Secrets | 6 | — | — | 15 | 15 | +9 |
| Ruby | 0 | 10 | 15 | — | 25 | +25 |
| PHP | 0 | 10 | 15 | — | 25 | +25 |
| Kotlin | 0 | 8 | 12 | — | 20 | +20 |
| **Total** | **63** | **76** | **114** | **15** | **205** | **+142** |

### Files to Create

| Category | Count | Pattern |
|----------|-------|---------|
| New rule YAML files | ~142 | `rules/builtin/{lang}/{rule-name}.yaml` |
| New fail test fixtures | ~142 | `rules/builtin/{lang}/tests/{rule-name}/fail.{ext}` |
| New pass test fixtures | ~142 | `rules/builtin/{lang}/tests/{rule-name}/pass.{ext}` |
| Ruby adapter | 1 | `crates/atlas-lang/src/ruby.rs` |
| PHP adapter | 1 | `crates/atlas-lang/src/php.rs` |
| Kotlin adapter | 1 | `crates/atlas-lang/src/kotlin.rs` |
| **Total new files** | **~429** | |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-lang/src/lib.rs` | Add Ruby, Php, Kotlin to Language enum |
| `crates/atlas-rules/src/declarative.rs` | Update rule count assertions, add new language tests |
| `Cargo.toml` (workspace) | Add tree-sitter-ruby, tree-sitter-php, tree-sitter-kotlin dependencies |

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| `specs/002-code-quality-analysis/spec.md` | Quality rule format reference |
| `specs/003-compliance-framework-mapping/spec.md` | Compliance metadata for new rules |
| [Brakeman](https://brakemanscanner.org/) | Ruby security scanner reference |
| [PHPStan Rules](https://phpstan.org/developing-extensions/rules) | PHP static analysis reference |
| [detekt](https://detekt.dev/) | Kotlin static analysis reference |
| [tree-sitter-ruby](https://github.com/tree-sitter/tree-sitter-ruby) | Ruby grammar |
| [tree-sitter-php](https://github.com/tree-sitter/tree-sitter-php) | PHP grammar |
| [tree-sitter-kotlin](https://github.com/fwcd/tree-sitter-kotlin) | Kotlin grammar |
