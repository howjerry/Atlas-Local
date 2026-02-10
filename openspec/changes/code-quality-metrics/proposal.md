## Why

Atlas-Local 目前只偵測離散的程式碼問題（安全漏洞、品質 smell），缺乏量化的程式碼品質度量。開發團隊需要循環複雜度、認知複雜度、程式碼重複偵測、LOC 統計等指標來全面掌握 codebase 健康狀態，並透過 CI 閾值強制執行品質標準。

## What Changes

- 新增 `MetricsEngine`：基於已解析的 tree-sitter AST 計算 cyclomatic / cognitive complexity
- 新增 `DuplicationDetector`：token-based 重複偵測（Type I + Type II clones），使用 Rabin-Karp rolling hash
- 新增 LOC 統計：per-file 與 project-level 的 total/code/blank/comment lines
- 新增 `--metrics` CLI 旗標（opt-in），啟用 metrics 計算
- 新增 `Category::Metrics` 類別，複雜度超過閾值產生 Finding
- JSON 報告新增 `metrics` 段落（per-function、per-file、project-level 聚合）
- Policy gate 支援 `category_overrides.metrics` 閾值

## Capabilities

### New Capabilities
- `code-quality-metrics`: 程式碼品質度量引擎 — 循環複雜度、認知複雜度、code duplication、LOC 統計，含閾值超標 findings 與報告整合

### Modified Capabilities
- `compliance-framework-mapping`: 無需求變更
- `diff-aware-scanning`: 無需求變更

## Impact

- **新增檔案**: `crates/atlas-analysis/src/metrics.rs`、`crates/atlas-analysis/src/duplication.rs`
- **修改 crate**: atlas-rules（Category enum）、atlas-core（engine pipeline）、atlas-cli（CLI flag）、atlas-report（JSON report）、atlas-policy（gate evaluation）
- **相依性**: 無新外部 dependency（tree-sitter AST 已可用，token-based 演算法自行實作）
- **效能**: metrics 計算複用已解析 AST，100K 行專案需 < 10 秒額外時間
- **相容性**: 預設不啟用（opt-in `--metrics`），現有行為零影響
