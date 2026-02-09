## Why

Atlas-Local 目前僅支援 L1（AST 模式匹配）分析，無法偵測跨行的資料流漏洞。當使用者輸入被賦值給變數後經過數行才傳入危險函數時，L1 完全無能為力。L2 單函數內資料流分析（intra-procedural data flow analysis）是填補此缺口的關鍵步驟，可大幅提升 SQL Injection、XSS、Command Injection 等漏洞的偵測覆蓋率。

## What Changes

- 實作污染源（source）、接收點（sink）、淨化函數（sanitizer）的 YAML 配置系統，支援 per-language 定義
- 實作 reaching-definitions 演算法，完成函數內的污染傳播追蹤
- 將現有 `l2_intraprocedural.rs` 死碼模組整合進掃描管道，根據 `AnalysisLevel` 觸發 L2 分析
- 新增 `--analysis-level` CLI 旗標，允許使用者選擇分析深度（L1/L2）
- 實作至少 5 條 L2 安全規則（Rhai 腳本），涵蓋 SQL Injection、XSS、Command Injection、Path Traversal、SSRF
- Finding 輸出包含 `data_flow` 元資料，呈現從 source 到 sink 的完整路徑

## Capabilities

### New Capabilities
- `l2-data-flow-analysis`: 單函數內資料流追蹤引擎，包含污染傳播、source/sink/sanitizer 配置、reaching-definitions 演算法、L2 規則執行、以及掃描管道整合

### Modified Capabilities
（無現有 spec 層級的需求變更）

## Impact

- **Crates 影響**: `atlas-analysis`（L2 引擎整合）、`atlas-core`（掃描管道擴展）、`atlas-rules`（L2 規則載入）、`atlas-cli`（CLI 旗標）
- **新增檔案**: `rules/l2/{lang}/sources.yaml`、`sinks.yaml`、`sanitizers.yaml`、L2 Rhai 規則腳本
- **既有死碼**: `l2_intraprocedural.rs` 將從 `#![allow(dead_code)]` 提升為正式整合
- **效能考量**: L2 分析比 L1 慢，預設 `--analysis-level L1`，使用者需明確啟用 L2
- **相依性**: 為未來 L3 跨函數分析（spec 011）奠定基礎
