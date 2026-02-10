## 1. Scaffold 型別演化

- [x] 1.1 擴展 `FunctionRef` — 新增 `parameters: Vec<String>` 欄位記錄函數參數名稱列表，保持既有欄位與 Serialize/Deserialize 相容
- [x] 1.2 擴展 `CallSite` — 新增 `argument_expressions: Vec<String>` 欄位記錄呼叫端每個引數的原始碼文字，保持 `tainted_args` 欄位
- [x] 1.3 新增 `ImportEntry` 型別 — 定義 `file_path`, `imported_name`, `source_module`, `exported_name` 欄位
- [x] 1.4 新增 `ImportIndex` 型別 — `HashMap<(String, String), (String, String)>` 包裝，提供 `resolve(file, name)` 方法
- [x] 1.5 擴展 `CallGraph` — 新增 `imports: ImportIndex` 欄位，新增 `resolve_call()` 方法結合 import index 與 function index 解析跨檔案呼叫
- [x] 1.6 確保所有既有 `l3_interprocedural.rs` 測試通過（7 個測試），移除 `#![allow(dead_code)]`

## 2. L3 語言配置

- [x] 2.1 定義 `L3LanguageConfig` trait — 擴展 L2LanguageConfig，新增 `parameter_list_kind()`, `return_statement_kind()`, `import_statement_kinds()`, `export_kinds()` 方法
- [x] 2.2 實作 TypeScript `L3LanguageConfig` — 映射 `formal_parameters`, `return_statement`, `import_statement`, `export_statement`
- [x] 2.3 實作 Java `L3LanguageConfig` — 映射 `formal_parameters`, `return_statement`, `import_declaration`
- [x] 2.4 實作 Python `L3LanguageConfig` — 映射 `parameters`, `return_statement`, `import_from_statement`
- [x] 2.5 實作 C# `L3LanguageConfig` — 映射 `parameter_list`, `return_statement`, `using_directive`
- [x] 2.6 實作 Go `L3LanguageConfig` — 映射 `parameter_list`, `return_statement`, `import_declaration`
- [x] 2.7 新增 `get_l3_config(Language) -> Option<Box<dyn L3LanguageConfig>>` 工廠函式

## 3. Call Graph 建構（Phase 1）

- [x] 3.1 建立 `call_graph_builder.rs` 模組 — 定義 `CallGraphBuilder` struct，接受 `L3LanguageConfig` 與 source bytes
- [x] 3.2 實作函數定義提取 — 遞迴走訪 AST 提取函數/方法定義，產生 `FunctionRef` 含參數名稱列表
- [x] 3.3 實作呼叫端提取 — 遞迴走訪 AST 提取 call expressions，產生 `CallSite` 含引數表達式與 caller 函數名稱
- [x] 3.4 實作 class 方法解析 — 解析 `this.method()` / `self.method()` 到同 class 的方法定義
- [x] 3.5 實作 `build_file(tree, source, file_path) -> (Vec<FunctionRef>, Vec<(String, CallSite)>)` 公開 API
- [x] 3.6 單元測試：單檔案函數定義提取（TypeScript）
- [x] 3.7 單元測試：呼叫端提取與同檔案解析
- [x] 3.8 單元測試：class 方法呼叫解析
- [x] 3.9 單元測試：未解析呼叫被跳過

## 4. 跨檔案 Import 解析

- [x] 4.1 實作 TypeScript import 提取 — 解析 `import_statement` AST node，提取 named imports 與 source module 路徑
- [x] 4.2 實作 TypeScript export 提取 — 解析 `export_statement` AST node，提取 exported 函數名稱
- [x] 4.3 實作 Python from-import 提取 — 解析 `import_from_statement`，提取 imported name 與 module path
- [x] 4.4 實作 module path 解析 — 將相對路徑（`./userService`）轉為絕對檔案路徑，嘗試 `.ts`/`.js`/`.py` 副檔名
- [x] 4.5 整合 import index 到 CallGraph — Phase 1 per-file 提取 import/export 後合併至全域 ImportIndex
- [x] 4.6 單元測試：TypeScript named import 解析
- [x] 4.7 單元測試：Python from-import 解析
- [x] 4.8 單元測試：未知 module path 回傳 None

## 5. 自訂 Taint Config 合併

- [x] 5.1 定義 `atlas-taint.yaml` schema — sources/sinks/sanitizers 欄位結構複用 L2 TaintConfig，新增 `max_depth: Option<u32>` 欄位
- [x] 5.2 實作 `load_custom_taint_config(scan_dir) -> Option<TaintConfig>` — 讀取專案根目錄 `atlas-taint.yaml`，不存在時回傳 None
- [x] 5.3 實作 `merge_taint_config(builtin, custom) -> TaintConfig` — append 語義合併 sources/sinks/sanitizers，custom max_depth 覆蓋 default
- [x] 5.4 單元測試：無 atlas-taint.yaml 時使用 built-in 配置
- [x] 5.5 單元測試：自訂 source/sink/sanitizer 被 append 到 built-in
- [x] 5.6 單元測試：自訂 max_depth 覆蓋預設值
- [x] 5.7 單元測試：無效 YAML 回傳描述性錯誤

## 6. L3 引擎 — 跨函數污染傳播（Phase 2）

- [x] 6.1 建立 `l3_engine.rs` 模組 — 定義 `L3Engine` struct，持有 `CallGraph`, `TaintConfig`, `Language`, `max_depth`
- [x] 6.2 實作入口點辨識 — 掃描 call graph 中含有 taint source 的函數作為分析起點
- [x] 6.3 實作 BFS 遍歷框架 — 從入口點 BFS 遍歷 call graph，`visited: HashSet` 循環偵測，`max_depth` 深度限制
- [x] 6.4 實作正向污染傳播（caller→callee）— 受污染引數對應 callee 參數標記為 Tainted，按需建構 scope graph 並執行 reaching-definitions
- [x] 6.5 實作反向污染傳播（callee→caller）— callee return expression 受污染時，caller 端接收變數標記為 Tainted
- [x] 6.6 實作 sanitizer 跨函數支援 — callee 內部 sanitizer 清除污染後，return 值為 Clean
- [x] 6.7 實作 sink 偵測 — 在每個 callee 的 scope graph 中偵測受污染變數傳入 sink，產生 L3 finding
- [x] 6.8 實作 scope graph 快取 — `HashMap<(file_path, func_name), ScopeGraph>` 避免重複建構
- [x] 6.9 實作 `analyze_project(files, taint_config) -> Vec<Finding>` 公開 API — 整合 Phase 1 call graph + Phase 2 污染傳播
- [x] 6.10 單元測試：入口點辨識（含 taint source 的函數）
- [x] 6.11 單元測試：BFS 深度限制（max_depth=2 阻止第 3 層）
- [x] 6.12 單元測試：循環偵測（A→B→A 不無限迴圈）
- [x] 6.13 單元測試：正向污染傳播（tainted arg → callee param → sink）
- [x] 6.14 單元測試：反向污染傳播（callee return tainted → caller var → sink）
- [x] 6.15 單元測試：sanitizer 清除跨函數污染
- [x] 6.16 單元測試：菱形呼叫（A→B→D, A→C→D）D 僅分析一次

## 7. L3 Finding 生成

- [x] 7.1 實作跨函數 `DataFlowStep` — 新增 `Call` 和 `Return` step types，每個 step 含 `file`, `function`, `line`, `column`, `expression`, `description`
- [x] 7.2 實作 `build_l3_finding()` — 組裝 rule_id (`atlas/security/{lang}/l3-{vuln}`), severity, CWE, analysis_level=L3, confidence=Medium
- [x] 7.3 實作 `metadata.data_flow` 序列化 — 跨檔案多函數的有序步驟陣列（source→propagation→call→return→sink）
- [x] 7.4 實作 `metadata.call_depth` — 計算函數呼叫邊界交叉次數
- [x] 7.5 單元測試：L3 finding 包含正確 analysis_level 和 confidence
- [x] 7.6 單元測試：data_flow 步驟跨越兩個檔案
- [x] 7.7 單元測試：call_depth 數值正確

## 8. CLI 與掃描管線整合

- [x] 8.1 修改 `parse_analysis_level()` — 移除 L3 錯誤訊息，新增 `"L3" => Ok(AnalysisLevel::L3)` 分支
- [x] 8.2 修改 `engine.rs` scan pipeline — 在 L1+L2 per-file 處理中加入 Phase 1 call graph 資料收集
- [x] 8.3 修改 `engine.rs` scan pipeline — 所有檔案處理完畢後，若 `analysis_level >= L3` 則執行 Phase 2 L3 分析
- [x] 8.4 整合自訂 taint config — 在 scan 初始化時載入 `atlas-taint.yaml`（若存在），合併到 L2/L3 taint config
- [x] 8.5 L3 findings 合併到最終結果 — append 到 L1+L2 findings 後排序輸出
- [x] 8.6 單元測試：L2 模式下不產生 L3 findings
- [x] 8.7 單元測試：L3 模式下同時產生 L1+L2+L3 findings

## 9. 測試夾具

- [ ] 9.1 建立 TypeScript L3 測試夾具 — `rules/l3/typescript/tests/` 下 l3-sql-injection, l3-xss, l3-command-injection 各含 fail/pass 檔案（跨函數呼叫模式）
- [ ] 9.2 建立 Java L3 測試夾具 — 同上模式，Java 跨方法呼叫
- [ ] 9.3 建立 Python L3 測試夾具 — 同上模式，Python 跨函數呼叫
- [ ] 9.4 建立 C# L3 測試夾具 — 同上模式，C# 跨方法呼叫
- [ ] 9.5 建立 Go L3 測試夾具 — 同上模式，Go 跨函數呼叫
- [ ] 9.6 建立跨檔案測試夾具（TypeScript）— controller.ts + service.ts 跨檔案 taint path
- [ ] 9.7 建立跨檔案測試夾具（Python）— views.py + services.py 跨檔案 taint path

## 10. 驗證與效能

- [ ] 10.1 全工作區編譯通過 `cargo build`
- [ ] 10.2 全工作區測試通過 `cargo test` — 確認零迴歸（L1+L2 測試不變）
- [ ] 10.3 Clippy 無警告 `cargo clippy`
- [ ] 10.4 L3 效能基準測試 — 500 函數專案 max_depth=5 在 30 秒內完成
- [ ] 10.5 端到端驗證 — `atlas scan --analysis-level L3 <test-project>` 產生正確的 L3 findings
