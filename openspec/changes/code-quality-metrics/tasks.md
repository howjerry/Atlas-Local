## 1. Type System 擴充

- [x] 1.1 在 `atlas-rules` 的 `Category` enum 新增 `Metrics` variant，更新 serde 序列化
- [x] 1.2 在 `atlas-policy/src/gate.rs` 的 `CategoryOverrides` 新增 `metrics` 欄位，更新 `CategoryCounts` 與 `check_category_overrides()`
- [x] 1.3 在 `atlas-report/src/json.rs` 新增 `MetricsReport`、`FileMetrics`、`FunctionMetrics`、`ProjectMetrics`、`DuplicationBlock` struct
- [x] 1.4 在 `AtlasReport` struct 新增 `metrics: Option<MetricsReport>` 欄位
- [x] 1.5 更新所有 `Category` exhaustive match（gate、report、engine 等），確保編譯通過

## 2. Metrics Engine 核心

- [x] 2.1 建立 `crates/atlas-analysis/src/metrics.rs` — `MetricsEngine` struct 與 `compute_file_metrics()` 方法框架
- [x] 2.2 實作 per-language node kind mapping trait（`MetricsLanguageConfig`），支援 TS/Java/Python/Go/C#/Ruby/PHP/Kotlin
- [x] 2.3 實作 cyclomatic complexity 計算 — AST 走訪計算 decision points（if/for/while/case/catch/&&/||/ternary）
- [x] 2.4 實作 cognitive complexity 計算 — structural increment + nesting penalty（SonarSource spec）
- [x] 2.5 實作 LOC 統計 — per-file total/code/blank/comment lines 分類
- [x] 2.6 實作 function extraction — 從 AST 提取所有 function/method 節點及其範圍
- [x] 2.7 實作閾值檢查 — 超過 `cyclomatic_max` / `cognitive_max` 時產生 Finding（category: Metrics）

## 3. Duplication Detection

- [x] 3.1 建立 `crates/atlas-analysis/src/duplication.rs` — `DuplicationDetector` struct 框架
- [x] 3.2 實作 tokenizer — 使用 tree-sitter leaf nodes 提取 token 序列，normalize identifiers/literals
- [x] 3.3 實作 Rabin-Karp rolling hash fingerprint 建立
- [x] 3.4 實作 duplicate block 比對邏輯 — 找出 >= min_tokens 的重複區塊
- [x] 3.5 實作 duplication findings 產生 — 每對重複區塊產生 Finding（severity: low）
- [x] 3.6 計算 project-level duplication percentage

## 4. Pipeline 整合

- [x] 4.1 在 `ScanOptions` 新增 `compute_metrics: bool` 欄位
- [x] 4.2 在 `ScanEngine::process_file()` 中整合 metrics 計算（在 L1/L2 分析後，複用已解析 AST）
- [x] 4.3 收集 per-file metrics 並在 scan 完成後聚合為 project-level metrics
- [x] 4.4 整合 duplication detection 到 scan pipeline（需跨檔案比對，在所有檔案處理完後執行）
- [x] 4.5 將 metrics findings 合併到總 findings 列表，將 MetricsReport 附加到 AtlasReport

## 5. CLI 與配置

- [x] 5.1 在 `atlas-cli/src/commands/scan.rs` 新增 `--metrics` flag
- [x] 5.2 將 `--metrics` flag 傳遞到 `ScanOptions.compute_metrics`
- [x] 5.3 新增 `MetricsConfig` struct（`cyclomatic_max`、`cognitive_max`、`min_tokens` 含預設值）
- [x] 5.4 支援從 policy YAML 讀取 metrics 閾值配置

## 6. 測試

- [x] 6.1 Cyclomatic complexity 單元測試 — 5 語言各 4 個測試案例（simple/branching/switch/ternary）
- [x] 6.2 Cognitive complexity 單元測試 — 驗證 nesting penalty 與 SonarSource spec 一致
- [x] 6.3 LOC 統計單元測試 — 驗證 code/blank/comment 行分類
- [x] 6.4 Duplication detection 單元測試 — Type I（exact）、Type II（renamed vars）、below-threshold
- [x] 6.5 Pipeline 整合測試 — `--metrics` 啟用時產生正確 report，未啟用時無 metrics 段落
- [x] 6.6 Gate 整合測試 — `category_overrides.metrics` 閾值正確觸發 gate failure
- [ ] 6.7 效能基準測試 — 驗證 100K 行專案 metrics 計算 < 10 秒

## 7. 驗證與清理

- [x] 7.1 執行完整 `cargo test` 確保無回歸
- [x] 7.2 執行 `cargo clippy` 確保無警告
- [x] 7.3 驗證 JSON report schema 向後相容（metrics 為 Optional）
