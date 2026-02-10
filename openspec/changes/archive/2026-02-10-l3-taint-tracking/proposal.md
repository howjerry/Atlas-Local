## Why

Atlas-Local 的 L2 分析（spec 005）僅追蹤單一函數內的資料流。然而真實世界的漏洞往往跨越多個函數 — 使用者輸入在 controller 進入、經過 service 方法傳遞、最終在 data access 層觸及危險 sink。這種分層架構（layered architecture）在企業級應用中極為普遍，L2 對此完全無能為力。L3 跨函數污染追蹤透過建構 call graph 並在函數邊界傳播污染狀態，填補此關鍵偵測缺口。

## What Changes

- 實作 call graph 建構模組，從 tree-sitter AST 解析函數定義與呼叫關係，支援同檔案及跨檔案函數解析
- 實作跨函數污染傳播引擎：參數→引數（caller→callee）正向傳播、回傳值→呼叫端（callee→caller）反向傳播
- 深度限制（max_depth，預設 5）與循環偵測，防止遞迴函數造成無限迴圈
- 複用 L2 的 scope graph 與 taint config（source/sink/sanitizer），在每個 callee 按需建構 scope graph
- 新增至少 3 條 L3 規則：跨函數 SQL Injection、XSS、Command Injection
- 支援使用者自訂 taint 配置（`atlas-taint.yaml`），與內建定義合併
- Finding 輸出包含跨檔案多函數的 `data_flow` 路徑，含 `call_depth` 元資料
- `--analysis-level L3` CLI 旗標啟用 L3 分析（L1 + L2 + L3 疊加執行）

## Capabilities

### New Capabilities
- `l3-taint-tracking`: 跨函數（inter-procedural）污染追蹤引擎，包含 call graph 建構、深度限制遍歷、跨函數污染傳播、循環偵測、L3 規則執行、自訂 taint 配置合併、以及掃描管道整合

### Modified Capabilities
- `l2-data-flow-analysis`: L2 的 scope graph builder 需支援按需為 callee 函數建構 scope graph（供 L3 呼叫）；taint config 需支援使用者自訂配置合併

## Impact

- **Crates 影響**: `atlas-analysis`（call graph 模組 + L3 引擎）、`atlas-core`（掃描管道 L3 整合）、`atlas-cli`（L3 旗標啟用）
- **新增檔案**: `call_graph.rs`（call graph 建構）、`l3_engine.rs`（跨函數污染傳播引擎）、`taint_config.rs`（自訂 config 載入/合併）、L3 規則（Rhai 腳本或 YAML）、L3 測試 fixtures
- **複用既有**: L2 scope graph builder、L2 reaching-definitions 演算法、L2 taint config YAML（source/sink/sanitizer）
- **效能考量**: L3 比 L2 更昂貴（O(n*d)，n=函數數量，d=max_depth）。預設仍為 L1，使用者需明確啟用 `--analysis-level L3`
- **相依性**: 直接依賴 L2 data flow analysis（spec 005）的 scope graph 與 taint propagation 基礎設施
