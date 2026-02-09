## Context

Atlas-Local 目前僅執行 L1 AST 模式匹配分析。L2 模組（`l2_intraprocedural.rs`）已有基礎型別定義（`VarDef`、`VarUse`、`ScopeGraph`、`DataFlowPath`）但標記為 `#![allow(dead_code)]`，未整合進掃描管道。掃描引擎（`engine.rs`）在 `precompile_queries()` 中已會跳過非 L1 規則，`process_file()` 僅透過 L1 `query_cache` 評估規則。

既有支援面：
- `AnalysisLevel` 枚舉已定義 L1/L2/L3
- `AnalysisConfig.max_depth` 已存在（預設 L2），但掃描引擎未讀取
- `RuleType::Scripted` 已定義（Rhai），但規則載入器僅處理 `Declarative`
- `Finding.metadata` 支援任意 JSON，可承載 `data_flow` 路徑
- CLI scan 指令無 `--analysis-level` 旗標

## Goals / Non-Goals

**Goals:**
- 建立完整的 L2 intra-procedural 污染傳播引擎，從 tree-sitter AST 構建 scope graph 並追蹤 source → sink 資料流
- 實作 source/sink/sanitizer 的 per-language YAML 配置系統（嵌入二進位檔）
- 將 L2 分析整合進掃描管道，於 L1 完成後執行
- 透過 `--analysis-level` CLI 旗標支援 opt-in L2 分析
- 實作 5 條 L2 安全規則（SQL injection、XSS、command injection、path traversal、SSRF）
- Finding 輸出包含 `data_flow` 步驟陣列

**Non-Goals:**
- 跨函數分析（L3，spec 011）
- SSA / phi-node 插入
- Field-sensitive 追蹤（`obj.field` 等同 `obj`）
- 使用者自定義 sanitizer（僅內建清單）
- 控制流敏感分析（path sensitivity）
- Rhai 腳本規則（本次採用 Rust 原生 L2 引擎而非 Rhai 腳本，見 Decision 1）

## Decisions

### Decision 1: Rust 原生引擎 vs Rhai 腳本規則

**選擇：Rust 原生 L2 引擎**

原始 spec 建議 L2 規則透過 Rhai 腳本定義（`RuleType::Scripted`）。經評估後改為 Rust 原生引擎，原因：

1. **效能**：Rhai 解譯執行比 Rust 原生慢 10-100x，L2 需要遍歷 AST 並執行 worklist 演算法，效能敏感
2. **型別安全**：Scope graph 構建涉及複雜的 tree-sitter cursor 操作，Rhai 的動態型別增加出錯風險
3. **API 暴露成本**：將 `ScopeGraph`、`VarDef`、`VarUse` 等型別暴露給 Rhai 需要大量 binding 程式碼
4. **規則同質性**：5 條 L2 規則的邏輯高度相似（都是 source → propagation → sink 追蹤），差異僅在 source/sink 配置，不需要腳本的靈活性

**替代方案**：Rhai 腳本允許使用者擴充 L2 規則而不需修改 Rust 程式碼。但現階段使用者不需要自定義 L2 規則（Non-Goal），未來可在需要時新增 Rhai binding 層。

### Decision 2: 污染傳播演算法

**選擇：Reaching-definitions worklist 演算法**

- 使用基本的 gen/kill 集合追蹤每個程式點的活躍定義
- 從 AST 提取的陳述列表上迭代至 fixed-point
- Path-insensitive：所有分支視為可達

**替代方案 1（SSA）**：需要 phi-node 插入，對 tree-sitter AST 來說實作複雜度過高。
**替代方案 2（Simple name matching）**：即現有 `ScopeGraph::resolve_flows()`，僅靠變數名稱和行號匹配，無法處理重新賦值清除污染。

### Decision 3: Source/Sink/Sanitizer 配置架構

**選擇：per-language 嵌入式 YAML + `include_str!` 編譯時載入**

```
rules/l2/
├── typescript/
│   └── taint_config.yaml   # sources + sinks + sanitizers 合併
├── java/
│   └── taint_config.yaml
├── python/
│   └── taint_config.yaml
├── csharp/
│   └── taint_config.yaml
└── go/
    └── taint_config.yaml
```

每個 `taint_config.yaml` 包含三個區段：

```yaml
sources:
  - pattern: "req.body"
    label: "HTTP request body"
  - pattern: "req.params"
    label: "HTTP URL parameters"

sinks:
  - function: "db.query"
    tainted_args: [0]
    vulnerability: "sql-injection"
    cwe: "CWE-89"

sanitizers:
  - function: "parseInt"
  - function: "escapeHtml"
```

**替代方案**：每個區段獨立 YAML 檔案（sources.yaml、sinks.yaml、sanitizers.yaml）。合併為單一檔案減少檔案數量和載入邏輯。

### Decision 4: L2 引擎在管道中的位置

**選擇：L1 完成後、排序前執行 L2**

```
discover_files → parse → L1 evaluate → L2 evaluate → sort → return
```

- L2 和 L1 共享已解析的 tree-sitter `Tree`，不需重新解析
- L2 在 `process_file()` 中 L1 迴圈之後新增一段 L2 分析邏輯
- 受 `ScanOptions` 中新增的 `analysis_level` 欄位控制

### Decision 5: Scope Graph 構建策略

**選擇：per-function 遍歷**

- 用 tree-sitter query 找到所有函數宣告節點（`function_declaration`、`method_definition` 等）
- 對每個函數的 AST 子樹遞迴走訪，收集 `VarDef` 和 `VarUse`
- 各語言的 AST 節點類型差異由 `L2LanguageConfig` trait 抽象化

### Decision 6: 模組結構

**選擇：擴展現有 l2_intraprocedural.rs 並新增子模組**

```
crates/atlas-analysis/src/
├── l2_intraprocedural.rs  → 保留並擴展型別定義
├── l2_builder.rs          → ScopeGraph 構建器（AST → ScopeGraph）
├── l2_engine.rs           → 污染傳播引擎 + Finding 產生
└── l2_taint_config.rs     → YAML 配置載入與型別
```

`l2_engine.rs` 會匯出 `L2Engine` 結構，供 `atlas-core/engine.rs` 在管道中調用。

## Risks / Trade-offs

**[Path-insensitive 分析可能產生誤報]** → 接受。對於 `if (condition) { x = safe; } else { x = tainted; }` 這類情況，path-insensitive 會假設兩個分支都可達，可能產生 false positive。透過 `confidence: Medium` 標記 L2 findings 來提示使用者。這是大多數 SAST 工具的標準做法。

**[Field-insensitive 可能漏報]** → 接受。`const name = req.body.name` 中 `req.body` 整體被標記為 tainted，而非精確追蹤到 `.name` 欄位。這在一般情境下是合理的（如果 `req.body` 是 tainted，其任何欄位也應為 tainted）。

**[L2 效能開銷]** → 透過 opt-in 機制緩解。預設 `--analysis-level L1`，使用者需明確啟用 L2。也支援 `l2_paths` 配置限制 L2 分析範圍。

**[多語言 AST 差異]** → 每種語言需要不同的 AST 節點類型映射（函數宣告、變數宣告、呼叫表達式等）。使用 `L2LanguageConfig` trait 封裝差異，但初始實作量較大。優先實作 TypeScript，再擴展到其他語言。

**[既有 ScopeGraph 型別需要大幅擴展]** → 現有型別過於簡化（無作用域層級、無 taint state 枚舉）。需要擴展但保持向後相容，既有測試不應受影響。
