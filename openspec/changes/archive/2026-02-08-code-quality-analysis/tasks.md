## 1. Metadata Plumbing (prerequisite for all rules)

- [x] 1.1 Add `metadata: BTreeMap<String, serde_json::Value>` field to `Rule` struct in `crates/atlas-rules/src/lib.rs` with `#[serde(default)]`
- [x] 1.2 Add `metadata: Option<BTreeMap<String, serde_json::Value>>` field to `DeclarativeRuleFile` in `crates/atlas-rules/src/declarative.rs` with `#[serde(default)]`
- [x] 1.3 Plumb metadata in `From<DeclarativeRuleFile> for Rule` conversion (unwrap_or default empty map)
- [x] 1.4 Add `metadata: BTreeMap<String, serde_json::Value>` field to `RuleMatchMetadata` in `crates/atlas-analysis/src/l1_pattern.rs`
- [x] 1.5 Populate `RuleMatchMetadata.metadata` from `Rule.metadata` where `RuleMatchMetadata` is constructed
- [x] 1.6 Copy `rule_metadata.metadata` into `FindingBuilder` in `L1PatternEngine::evaluate()`
- [x] 1.7 Verify existing tests pass — security rules produce empty metadata maps (no regression)

## 2. P1 TypeScript Quality Rules (5 rules)

- [x] 2.1 Create `empty-catch-block` rule YAML + fail.ts + pass.ts
- [x] 2.2 Create `console-log` rule YAML + fail.ts + pass.ts
- [x] 2.3 Create `any-type-usage` rule YAML + fail.ts + pass.ts
- [x] 2.4 Create `loose-equality` rule YAML + fail.ts + pass.ts
- [x] 2.5 Create `var-declaration` rule YAML + fail.ts + pass.ts

## 3. P1 Java Quality Rules (2 rules)

- [x] 3.1 Create `empty-catch-block` rule YAML + fail.java + pass.java
- [x] 3.2 Create `system-out-println` rule YAML + fail.java + pass.java

## 4. P1 Python Quality Rules (4 rules)

- [x] 4.1 Create `bare-except` rule YAML + fail.py + pass.py
- [x] 4.2 Create `print-statement` rule YAML + fail.py + pass.py
- [x] 4.3 Create `pass-in-except` rule YAML + fail.py + pass.py
- [x] 4.4 Create `mutable-default-arg` rule YAML + fail.py + pass.py

## 5. P1 Go Quality Rules (3 rules)

- [x] 5.1 Create `empty-error-check` rule YAML + fail.go + pass.go
- [x] 5.2 Create `fmt-println` rule YAML + fail.go + pass.go
- [x] 5.3 Create `defer-in-loop` rule YAML + fail.go + pass.go

## 6. P1 C# Quality Rules (2 rules)

- [x] 6.1 Create `empty-catch-block` rule YAML + fail.cs + pass.cs
- [x] 6.2 Create `console-writeline` rule YAML + fail.cs + pass.cs

## 7. P1 Validation

- [x] 7.1 Run `cargo test` — verify all 16 P1 rules load and existing security/secrets rules pass
- [x] 7.2 Validate fail fixtures produce findings and pass fixtures produce zero findings for each P1 rule

## 8. P2 TypeScript Quality Rules (5 rules)

- [x] 8.1 Create `non-null-assertion` rule YAML + fail.ts + pass.ts
- [x] 8.2 Create `todo-comment` rule YAML + fail.ts + pass.ts
- [x] 8.3 Create `empty-function-body` rule YAML + fail.ts + pass.ts
- [x] 8.4 Create `redundant-boolean` rule YAML + fail.ts + pass.ts
- [x] 8.5 Create `excessive-parameters` rule YAML + fail.ts + pass.ts

## 9. P2 Java Quality Rules (5 rules)

- [x] 9.1 Create `todo-comment` rule YAML + fail.java + pass.java
- [x] 9.2 Create `empty-method-body` rule YAML + fail.java + pass.java
- [x] 9.3 Create `redundant-boolean` rule YAML + fail.java + pass.java
- [x] 9.4 Create `string-concat-in-loop` rule YAML + fail.java + pass.java
- [x] 9.5 Create `raw-type-usage` rule YAML + fail.java + pass.java

## 10. P2 Python Quality Rules (2 rules)

- [x] 10.1 Create `todo-comment` rule YAML + fail.py + pass.py
- [x] 10.2 Create `empty-function-body` rule YAML + fail.py + pass.py

## 11. P2 Go Quality Rules (3 rules)

- [x] 11.1 Create `unchecked-error` rule YAML + fail.go + pass.go
- [x] 11.2 Create `todo-comment` rule YAML + fail.go + pass.go
- [x] 11.3 Create `empty-function-body` rule YAML + fail.go + pass.go

## 12. P2 C# Quality Rules (4 rules)

- [x] 12.1 Create `todo-comment` rule YAML + fail.cs + pass.cs
- [x] 12.2 Create `empty-method-body` rule YAML + fail.cs + pass.cs
- [x] 12.3 Create `redundant-boolean` rule YAML + fail.cs + pass.cs
- [x] 12.4 Create `object-type-usage` rule YAML + fail.cs + pass.cs

## 13. P2 Validation

- [x] 13.1 Run `cargo test` — verify all 33 quality rules (16 P1 + 17 P2) load correctly
- [x] 13.2 Validate fail/pass fixtures for each P2 rule

## 14. P3 Quality Rules (3 rules)

- [x] 14.1 Create Python `magic-number` rule YAML + fail.py + pass.py
- [x] 14.2 Create Java `raw-type-usage` — already in P2 group 9.5, done
- [x] 14.3 Create C# `object-type-usage` — already in P2 group 12.4, done

## 15. Test Assertion Updates

- [x] 15.1 Update TypeScript rule count assertion in `declarative.rs` — no TS test exists (N/A)
- [x] 15.2 Update Java rule count assertion in `declarative.rs` from 4 → 11
- [x] 15.3 Update Python rule count assertion in `declarative.rs` from 4 → 11
- [x] 15.4 Update Go rule count assertion in `declarative.rs` from 3 → 9
- [x] 15.5 Update C# rule count assertion in `declarative.rs` from 5 → 11
- [x] 15.6 Verify secrets rule count assertion remains at 6 (unchanged)

## 16. Final Validation

- [x] 16.1 Run full `cargo test` — all 63 rules (27 security + 6 secrets + 36 quality) load and pass
- [x] 16.2 Run `cargo clippy` — zero warnings on changed code
- [x] 16.3 Verify quality findings include `metadata.quality_domain` in output
- [x] 16.4 Spot-check SARIF output: medium quality → `level: "warning"`, low quality → `level: "note"`
