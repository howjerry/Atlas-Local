## Why

Atlas-Local 目前僅有 63 條內建規則（27 安全 + 6 secrets + 30 品質），覆蓋 5 種語言。要作為主力 SAST 工具使用，規則庫需擴展至 200+ 條，並新增 Ruby、PHP、Kotlin 語言支援，以達到 OWASP Top 10 全面覆蓋。

## What Changes

- 新增 3 種語言支援：Ruby（`.rb`）、PHP（`.php`）、Kotlin（`.kt`/`.kts`），各需 tree-sitter grammar 整合與 `LanguageAdapter` 實作
- 新增 ~142 條 L1 宣告式規則（YAML + tree-sitter），含對應的 fail/pass 測試夾具
- 擴展現有 5 語言的規則集（TypeScript +15、Java +14、Python +14、Go +11、C# +9）
- Secrets 規則從 6 條擴展至 15 條，新增 GCP、Azure、GitHub、GitLab、Slack、Stripe、Twilio、SendGrid、JWT 偵測
- 新增 Cargo feature flags 支援語言按需啟用（`ruby`、`php`、`kotlin`）
- 所有新安全規則包含 CWE 映射與 OWASP Top 10 合規 metadata

## Capabilities

### New Capabilities
- `ruby-language-support`: Ruby 語言支援，含 LanguageAdapter、tree-sitter grammar 整合、10 安全規則 + 15 品質規則
- `php-language-support`: PHP 語言支援，含 LanguageAdapter、tree-sitter grammar 整合、10 安全規則 + 15 品質規則
- `kotlin-language-support`: Kotlin 語言支援，含 LanguageAdapter、tree-sitter grammar 整合、8 安全規則 + 12 品質規則
- `secrets-rule-expansion`: Secrets 規則擴展至 15 條，新增 9 種 token/key 偵測模式
- `existing-language-rule-expansion`: 現有 5 語言規則集擴展，每語言至少 20 條規則

### Modified Capabilities
（無既有 spec 級需求變更）

## Impact

- **程式碼**：`crates/atlas-lang/src/lib.rs`（Language enum）、`crates/atlas-rules/src/declarative.rs`（規則載入與測試）、新增 3 個 LanguageAdapter 模組
- **依賴**：workspace `Cargo.toml` 新增 `tree-sitter-ruby`、`tree-sitter-php`、`tree-sitter-kotlin` optional 依賴
- **檔案規模**：~429 新檔案（~142 YAML 規則 + ~284 測試夾具 + 3 adapter 模組）
- **編譯時間**：預估增加 ~30 秒（3 個額外 tree-sitter grammar）
- **效能**：200+ 規則全量掃描 100K 行多語言專案需維持 < 60 秒
