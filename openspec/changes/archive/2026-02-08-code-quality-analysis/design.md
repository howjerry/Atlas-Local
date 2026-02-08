## Context

Atlas-Local ships 27 security + 6 secrets rules as declarative YAML files loaded by the L1 pattern engine. The engine is category-agnostic: it evaluates tree-sitter queries from any YAML rule and emits `Finding` structs. Policy gating already supports `category_overrides.quality`. This change adds 36 quality rules (YAML + fixtures only), with one targeted code change to plumb rule-level metadata into findings.

**Current metadata gap**: `Rule` struct has no `metadata` field. The L1 engine builds findings via `RuleMatchMetadata`, which carries `severity`, `category`, `cwe_id`, `description`, `remediation`, `confidence` — but no generic metadata map. `Finding.metadata` (a `BTreeMap<String, serde_json::Value>`) exists but is always empty for L1 findings. Quality rules need `metadata.quality_domain` on their findings (FR-Q10).

## Goals / Non-Goals

**Goals:**
- Add 36 quality rules (108 new files) with passing test fixtures
- Plumb `quality_domain` metadata from rule YAML into `Finding.metadata`
- Maintain zero false positives on pass fixtures, zero false negatives on fail fixtures
- Keep scan performance within 40s for 100K-line polyglot projects

**Non-Goals:**
- CLI `--category` filter (separate enhancement)
- L2/L3 analysis rules (complexity, data flow)
- Auto-fix suggestions
- `FindingsSummary.by_category` aggregation
- Tag-based metadata derivation (too implicit; explicit YAML is clearer)

## Decisions

### D1: Metadata plumbing — add `metadata` field to Rule and RuleMatchMetadata

**Decision**: Add `metadata: BTreeMap<String, serde_json::Value>` to both `Rule` (via `DeclarativeRuleFile`) and `RuleMatchMetadata`, and copy it into `Finding.metadata` during L1 evaluation.

**Alternatives considered**:
- *Tag-based derivation in the engine*: Automatically map tags like `error-handling` → `quality_domain: "error-handling"`. Avoids duplication but couples tag semantics to engine logic and is fragile if tags change. Rejected — too implicit.
- *Post-processing pass*: Populate metadata after findings are built, by looking up the rule. Avoids changing the engine hot path but adds a separate pass and couples report generation to rule storage. Rejected — unnecessary complexity.
- *Direct `quality_domain` field on Rule/Finding*: Too specific; a generic `metadata` map is more extensible for future use cases (e.g., `auto_fixable`, `fix_suggestion`).

**Scope of change**:
1. `DeclarativeRuleFile` — add `metadata: Option<BTreeMap<String, serde_json::Value>>` with `serde(default)`
2. `Rule` — add `metadata: BTreeMap<String, serde_json::Value>` (default empty)
3. `From<DeclarativeRuleFile> for Rule` — plumb metadata through
4. `RuleMatchMetadata` — add `metadata: BTreeMap<String, serde_json::Value>`
5. `L1PatternEngine::evaluate()` — copy `rule_metadata.metadata` into `FindingBuilder`
6. Where `RuleMatchMetadata` is constructed from `Rule` — populate the field

This is ~20 lines of Rust across 3 files. Existing rules have no `metadata` key in YAML, so `serde(default)` ensures backward compatibility (empty map).

### D2: Rule implementation order — P1 first, language-grouped

**Decision**: Implement all 16 P1 rules first (across all 5 languages), then P2 (17 rules), then P3 (3 rules). Within each priority, group by language to batch-test fixtures.

**Rationale**: P1 rules cover the highest-value patterns (empty catch, debug prints, bare except). Shipping P1 first provides immediate value and validates the metadata plumbing before scaling to 36 rules.

### D3: Test fixture strategy — minimal, focused examples

**Decision**: Each `fail.{ext}` fixture contains 1–3 minimal functions triggering the rule. Each `pass.{ext}` fixture demonstrates safe patterns that must NOT trigger. Pass fixtures avoid calling the dangerous function entirely (not just using safe arguments).

**Rationale**: Learned from security rule development — pass fixtures that call the same function with "safe" arguments can still match overly broad patterns. The pass fixture should use a fundamentally different code pattern.

### D4: YAML metadata for quality_domain — explicit, not derived

**Decision**: Each quality rule YAML includes an explicit `metadata` section:

```yaml
metadata:
  quality_domain: "error-handling"
```

**Rationale**: Duplicates information already in `tags`, but is unambiguous and doesn't require engine logic to derive. Consistent with keeping the engine generic. The spec's data-model.md recommends this approach for the initial implementation.

### D5: Test assertion updates — per-language counts only

**Decision**: Update the 5 existing `load_builtin_{lang}_rules_from_disk()` tests in `declarative.rs` to reflect the new total rule counts per language. No new test functions needed.

**Rationale**: The existing test pattern already validates that all YAML files in a language directory parse correctly and produce valid `Rule` structs. Adding quality rules to the same directories means the existing tests automatically cover them.

## Risks / Trade-offs

**[Risk] Tree-sitter query patterns may not match across all parser versions** → Mitigation: Each rule has a fail fixture that CI runs; pattern breakage is caught immediately.

**[Risk] Metadata plumbing changes the L1 engine hot path** → Mitigation: `BTreeMap::clone()` for an empty or 1-entry map is negligible (~ns). Benchmark before/after to confirm < 1% overhead.

**[Risk] Some quality patterns have inherently higher false positive rates (e.g., `magic-number`, `todo-comment`)** → Mitigation: These are P2/P3 with `confidence: low` or `confidence: medium`. Users can suppress via policy (`category_overrides.quality`) or inline annotations.

**[Risk] 108 new files could be error-prone to create manually** → Mitigation: Use the spec's research.md which contains pre-researched S-expression patterns for each rule. Implement in batches (P1 → P2 → P3) with CI validation between batches.

**[Trade-off] Explicit `metadata.quality_domain` in YAML duplicates tag information** → Accepted: Small duplication cost for clarity and zero engine-logic coupling. Can be consolidated in a future refactor.
