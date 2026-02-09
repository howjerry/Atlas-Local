## Context

Atlas-Local 目前支援 6 種語言（TypeScript、JavaScript、Java、Python、Go、C#）共 63 條 L1 宣告式規則。語言整合透過 `LanguageAdapter` trait + `AdapterRegistry` 架構，每個 adapter 負責副檔名對應、tree-sitter grammar 初始化與 AST 解析。規則以 YAML 格式存放於 `rules/builtin/{lang}/`，由 `DeclarativeRuleLoader` 載入並轉換為 `Rule` 結構。

本次擴展需新增 Ruby、PHP、Kotlin 三語言支援，並將總規則數從 63 擴展至 205+。

## Goals / Non-Goals

**Goals:**
- 新增 Ruby、PHP、Kotlin 三語言的完整 L1 掃描支援（adapter + grammar + 規則）
- 將總規則數擴展至 205+（76 安全 + 15 secrets + 114 品質）
- Secrets 規則從 6 擴展至 15，涵蓋主流雲端服務 token
- 現有 5 語言各達到至少 20 條規則
- 所有新規則含 fail/pass 測試夾具
- 新安全規則含 CWE 映射與 OWASP Top 10 合規 metadata

**Non-Goals:**
- 新語言的 L2/L3 污點追蹤（需先擴展 L2 taint config）
- 框架特定規則（Rails、Laravel、Ktor 等）
- Swift、Rust、Scala 語言支援
- 自訂規則編寫工具或文件
- 效能基準測試框架

## Decisions

### D1: 新語言 adapter 遵循現有模式

**決定**：每個新語言建立獨立模組（`ruby.rs`、`php.rs`、`kotlin.rs`），實作 `LanguageAdapter` trait，並在 `adapter.rs` 新增 `register_*_adapter()` 便利函式。

**理由**：現有 6 語言已建立穩定的 adapter 模式（無狀態 struct + parse 每次建新 Parser）。新語言無需引入新模式，直接複用可降低認知成本並確保一致性。

**替代方案**：
- 巨集自動生成 adapter（程式碼更精簡但降低可讀性且偵錯困難）→ 拒絕

### D2: tree-sitter grammar 依賴放在 atlas-lang crate

**決定**：新的 `tree-sitter-ruby`、`tree-sitter-php`、`tree-sitter-kotlin` 依賴加入 `crates/atlas-lang/Cargo.toml`，作為必要依賴（非 optional）。

**理由**：現有 6 語言的 grammar 全部是必要依賴（非 feature-gated）。為保持一致性且避免 `#[cfg(feature)]` 散佈於 adapter/engine/規則載入等多處，初始版本維持相同做法。未來若需減小二進位檔可另行加入 feature flags。

**替代方案**：
- Optional 依賴 + Cargo feature flags（spec 原始建議）→ 延後。新增 3 個 grammar 對編譯大小影響有限（~2-3 MB），feature flag 的複雜度不值得現階段引入。

### D3: Language enum 與 from_extension 同步擴展

**決定**：在 `Language` enum 新增 `Ruby`、`Php`、`Kotlin` 變體，同時更新 `from_extension()`、`extensions()`、`all()`、`Display` 等方法。

**理由**：Language enum 是全系統的語言標識符，所有下游功能（規則載入、報告、合規映射、差異掃描）都依賴它。集中修改一處即可讓新語言自動參與所有既有功能。

### D4: 規則分批實作，按語言分組

**決定**：實作順序為 (1) 基礎設施（Language enum + adapters）→ (2) Secrets 擴展 → (3) 現有語言擴展 → (4) Ruby → (5) PHP → (6) Kotlin。

**理由**：
- 基礎設施先行確保新語言的 adapter 可用
- Secrets 規則不依賴新語言，可獨立完成
- 現有語言擴展複用已驗證的 AST 節點知識
- 新語言按社群需求排序（Ruby > PHP > Kotlin）

### D5: PHP grammar 使用 `tree-sitter-php` 的 `language_php()` 函式

**決定**：PHP adapter 使用 `tree_sitter_php::LANGUAGE_PHP`（僅解析 PHP 程式碼區塊），而非 `LANGUAGE_PHP_ONLY`。

**理由**：`tree-sitter-php` crate 提供兩種 grammar：`LANGUAGE_PHP`（含 PHP 標籤如 `<?php`）和 `LANGUAGE_PHP_ONLY`（純 PHP 語法）。使用完整 grammar 可正確處理混合 HTML+PHP 的檔案。

### D6: 測試夾具結構維持不變

**決定**：新規則的測試夾具繼續使用 `rules/builtin/{lang}/tests/{rule-name}/fail.{ext}` + `pass.{ext}` 結構。每語言在 `declarative.rs` 新增 `load_builtin_{lang}_rules_from_disk()` 測試。

**理由**：現有測試基礎設施已驗證可行。一致的結構讓新規則作者可參考既有範例。

## Risks / Trade-offs

**[風險] tree-sitter grammar crate API 不穩定** → 鎖定特定版本，研究階段先驗證 grammar 的 AST 節點結構。若 crate 不在 crates.io 上，使用 git 依賴作為備案。

**[風險] 新語言 AST 節點命名差異** → 每個新語言在規則撰寫前必須進行 AST 研究（tree-sitter playground 或 `ts-cli parse`），記錄節點名稱於 MEMORY.md。已知教訓：C# 的 `identifier` vs Java 的 `type_identifier`、Go 的 `field_identifier` vs `identifier`。

**[風險] 142 條新規則的品質控制** → 每條規則必須有 fail/pass 測試夾具。pass 夾具不得呼叫危險函式（避免僅用安全參數的模式）。CI 自動執行全量測試。

**[風險] 編譯時間增加** → 3 個額外 tree-sitter grammar 預估增加 ~30 秒。可接受範圍。若未來語言持續增加，可考慮 feature flags。

**[取捨] 非 feature-gated 依賴** → 犧牲二進位大小的可控性，換取程式碼簡潔性。短期可接受，長期可回頭加 feature flags。

**[取捨] 不含框架特定規則** → 減少規則數量但降低假陽性風險。框架規則（如 Rails 的 `params` 追蹤）適合在 L2 分析中處理。

## Open Questions

- `tree-sitter-kotlin` 在 crates.io 的最新穩定版本為何？是否由官方維護？
- PHP 的 `tree-sitter-php` crate 的確切 language 常數名稱（`LANGUAGE_PHP` vs `language_php()`）需在整合時驗證。
- 現有語言擴展的具體規則清單需在 specs 階段定義（本設計不列出 142 條規則的完整清單）。
