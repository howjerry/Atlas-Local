## Context

Atlas-Local 是一個 Rust-based 靜態分析工具，透過 tree-sitter 解析 AST 並執行 L1 模式比對 / L2 資料流分析。目前只產生離散的 Finding（安全/品質/secrets），缺少量化的程式碼度量能力。

現有架構：
- `ScanEngine::process_file()` 解析 AST → L1 查詢 → L2 分析 → 收集 findings
- 每個檔案已有解析完成的 `tree_sitter::Tree`，可直接複用
- Report 使用 `AtlasReport` struct，序列化為 JSON/SARIF
- Policy gate 透過 `CategoryOverrides` 依 category 設定 severity 閾值

## Goals / Non-Goals

**Goals:**
- 計算 per-function cyclomatic / cognitive complexity，超閾值產生 Finding
- Token-based 重複偵測（Type I + II），報告重複區塊位置
- Per-file / project-level LOC 統計（total/code/blank/comment）
- 透過 `--metrics` opt-in，不影響現有掃描行為
- JSON 報告新增 `metrics` 段落（function/file/project 三層）
- Policy gate 支援 `category_overrides.metrics`

**Non-Goals:**
- Type III clone 偵測（AST-based semantic clones）
- 跨模組依賴/耦合度量（afferent/efferent coupling）
- 測試覆蓋率、churn metrics
- Halstead metrics、Maintainability Index
- Metric trend tracking（依賴 010 Web Dashboard）

## Decisions

### D1: Metrics 作為獨立模組而非額外 analysis level

**決定**: 新增 `metrics.rs` 和 `duplication.rs` 模組，透過 `ScanOptions.compute_metrics: bool` 控制，與 `analysis_level` (L1/L2) 正交。

**替代方案**: 新增 L0 或讓 metrics 成為 L1 的一部分。
**理由**: Metrics 與安全/品質規則語義不同（量化度量 vs 模式比對），正交控制更靈活 — 使用者可以單獨啟用 metrics 而不影響分析深度。

### D2: Category::Metrics 新增列舉值

**決定**: 在 `Category` enum 新增 `Metrics` variant，讓 metrics findings 參與現有 gate 評估流程。

**替代方案**: 複用 `Category::Quality` 並用 metadata 區分。
**理由**: 獨立 category 讓 policy 配置更清晰（`category_overrides.metrics` vs 混在 quality 中），且語義明確。

### D3: Complexity 計算在 process_file() 中逐檔執行

**決定**: 在 `process_file()` 中，L1/L2 分析完成後，若 `compute_metrics` 為 true，呼叫 `MetricsEngine::compute_file_metrics(tree, source, language)` 回傳 `FileMetrics` 結構。

**理由**: 已有解析完的 AST，不需重新解析。逐檔計算可被 rayon 平行化，與現有 pipeline 一致。

### D4: Token-based 重複偵測使用 Rabin-Karp rolling hash

**決定**: 將每個檔案 tokenize（使用 tree-sitter leaf nodes），normalize identifiers/literals → 建立 token hash sequences → Rabin-Karp rolling hash 建立 fingerprint map → 比對找出重複區塊。

**替代方案**: Suffix tree / suffix array。
**理由**: Rabin-Karp 實作簡單、O(n) 平均時間、記憶體友善。對 100K 行專案足夠高效。Suffix tree 效能更佳但實作複雜度高。

### D5: Metrics 結果雙軌輸出

**決定**:
1. 超閾值 metrics 產生 `Finding`（`category: Metrics`），進入 `findings` 陣列，參與 gate 評估
2. 所有 metrics 資料進入 `AtlasReport.metrics: Option<MetricsReport>`，提供完整度量資訊

**理由**: Finding 路徑保持與現有 pipeline 一致（gate/baseline/diff 自動生效），而獨立 metrics 段落提供非超標函數的正常度量資料。

### D6: Cognitive Complexity 遵循 SonarSource 規格

**決定**: 完全遵循 SonarSource cognitive complexity 規格（structural increment + nesting penalty）。

**理由**: 業界標準，有完整文件與參考實作可驗證正確性。

## Risks / Trade-offs

- **[Complexity 計算因語言差異不一致]** → 每個語言的 AST node type 不同（如 Go 沒有 ternary），需要 per-language 的 node kind mapping。透過 trait 抽象化，類似 L2 的 `L2LanguageConfig`。

- **[Duplication 偵測大型專案記憶體消耗]** → Token fingerprint map 可能很大。緩解：限制最大 fingerprint window（如 500 tokens），使用 u64 hash 而非完整 token 序列比較。

- **[Report schema 變更影響下游消費者]** → `metrics` 欄位為 `Option`，預設 `None`，不破壞現有 JSON 消費者。

- **[Category::Metrics 新增需同步多處]** → gate.rs、json.rs、CategoryOverrides、serde。透過 exhaustive match 讓編譯器強制處理。
