## Context

Atlas-Local 已實作 L2 intra-procedural 資料流分析（spec 005），具備 scope graph 建構、reaching-definitions worklist 演算法、source/sink/sanitizer 配置系統、以及 5 種漏洞類型的偵測能力。L2 分析範圍限於單一函數內部，無法追蹤跨函數邊界的污染傳播。

現有基礎設施：
- `l2_engine.rs`：單函數污染分析引擎（`L2Engine.analyze_file()`）
- `l2_builder.rs`：`ScopeGraphBuilder` + `L2LanguageConfig` trait（5 語言）
- `l2_taint_config.rs`：per-language YAML 配置（`include_str!` 編譯時嵌入）
- `l2_intraprocedural.rs`：`ScopeGraph`、`VarDef`、`VarUse`、`TaintState`、`DataFlowStep` 型別
- `l3_interprocedural.rs`：scaffold 型別（`CallGraph`、`FunctionRef`、`CallSite`、`TaintPath`），未接入管線
- `engine.rs`：掃描管線在 `analysis_level.depth() >= 2` 時觸發 L2，L3 目前在 CLI 被擋下

## Goals / Non-Goals

**Goals:**
- 偵測跨越 2-5 個函數呼叫的 source-to-sink 漏洞（SQL injection、XSS、command injection）
- 建構 call graph 支援同檔案函數呼叫與跨檔案 import/export 解析
- 複用 L2 scope graph 與 taint config，避免重複實作
- `--analysis-level L3` 疊加執行（L1 + L2 + L3），L3 findings 與 L1/L2 清晰區分
- 深度限制（max_depth 預設 5）確保分析在合理時間內完成
- 使用者可透過 `atlas-taint.yaml` 自訂 sources/sinks/sanitizers

**Non-Goals:**
- 動態分派解析（virtual methods、interface implementations）
- 反射型呼叫解析
- 第三方函式庫建模（僅追蹤專案內部函數）
- 別名分析（alias analysis）
- 並行程式感知分析（goroutine、async/await）
- 無上限的全程式分析
- 跨語言污染追蹤

## Decisions

### D1: 兩階段分析架構

**決策**：採用兩階段架構 — Phase 1 建構 function index + call graph（per-file 平行化），Phase 2 跨函數污染傳播（per-entry-point 平行化）。

**理由**：L2 是 per-file 分析，可在 `process_file` 中直接執行。L3 需要全域 call graph，必須在所有檔案解析完畢後才能進行污染傳播。兩階段設計讓 Phase 1 與現有 L1/L2 管線平行執行，Phase 2 在 L1/L2 完成後啟動。

**替代方案**：
- 單階段 per-file（不可行 — 跨檔案資訊不足）
- 全域 AST pool + 單一遍歷（記憶體成本過高，不適合大型專案）

**架構圖**：
```
Phase 1 (per-file, 平行)          Phase 2 (全域, per-entry-point 平行)
┌──────────────────────┐         ┌─────────────────────────────────┐
│ parse AST            │         │ identify entry points           │
│ extract FunctionDef  │  merge  │ (functions containing sources)  │
│ extract CallSites    │ ──────→ │                                 │
│ run L1 + L2          │         │ for each entry point:           │
└──────────────────────┘         │   traverse call graph (BFS)     │
                                 │   per callee: build scope graph │
                                 │   propagate taint across params │
                                 │   detect sinks → L3 Finding     │
                                 └─────────────────────────────────┘
```

### D2: 演化現有 scaffold 型別

**決策**：演化 `l3_interprocedural.rs` 中的現有型別（`CallGraph`、`FunctionRef`、`CallSite`），而非重寫。新增必要欄位（如 `parameters`、`return_expressions`）但保持向後相容。

**理由**：scaffold 已有 7 個測試通過，型別設計合理。新增欄位比重寫風險低，也避免破壞既有測試。

**替代方案**：
- 全新型別定義（浪費既有設計，需重寫所有測試）
- 直接在 L2 型別上擴展（會混淆 L2/L3 邊界）

### D3: 函數解析策略 — 語法名稱解析

**決策**：使用語法名稱解析（syntactic name resolution）建構 call graph。透過函數名匹配呼叫端與定義端，不進行型別推斷。

**理由**：
1. tree-sitter AST 不提供型別資訊，型別推斷需要額外的型別系統
2. 語法名稱解析對大多數直接呼叫模式（module-level functions、class methods within same file）已足夠
3. Spec 明確排除動態分派與反射，語法解析已覆蓋 scope 內的所有案例

**解析優先順序**：
1. 同檔案同名函數 → 直接匹配
2. 跨檔案 import → 追蹤 import 路徑到 export 定義
3. class/object 方法 → `this.method()` / `self.method()` 在同 class 定義內解析
4. 未解析 → 跳過（conservative approach，不猜測）

**替代方案**：
- 型別推斷（複雜度過高，超出 tree-sitter 能力範圍）
- 字串模糊匹配（高誤報率）

### D4: 跨函數污染傳播機制

**決策**：
- **正向傳播**：caller 的受污染引數 → callee 的對應參數標記為 `Tainted`
- **反向傳播**：callee 的 return expression 受污染 → caller 端接收 return value 的變數標記為 `Tainted`
- 每個 callee 按需建構 L2 scope graph，執行 reaching-definitions 判斷參數污染是否傳播到 return 或 sink

**理由**：複用 L2 的 `ScopeGraphBuilder` 和 reaching-definitions 演算法，每個 callee 的分析邏輯與 L2 完全一致，只是初始污染來源從 L2 的 taint source pattern 變成 L3 的 caller 引數。

**替代方案**：
- 函數摘要（function summary）快取（適合重複分析，但增加實作複雜度，V1 暫不採用）
- 全展開（inline callee body）— 破壞 scope 結構，不可行

### D5: 深度限制 + 循環偵測

**決策**：BFS 遍歷 call graph，`max_depth` 預設 5，`visited: HashSet<FunctionKey>` 防止循環。超出深度或已造訪的函數直接跳過。

**理由**：
1. 研究顯示大多數注入漏洞在 3-4 層呼叫內
2. BFS 確保淺層路徑優先偵測
3. `visited` set 同時解決遞迴和菱形呼叫（A→B, A→C, B→D, C→D）

**替代方案**：
- DFS（可能在深層路徑浪費時間再回溯）
- Context-sensitive（精確但指數級複雜度）

### D6: 自訂 Taint Config 合併

**決策**：使用者可在專案根目錄放置 `atlas-taint.yaml`，其 sources/sinks/sanitizers 與內建 YAML 合併（append 語義，不替換）。

**理由**：企業級框架有非標準 API，使用者需要新增自訂定義。Append 語義確保內建安全規則不被意外覆蓋。

**格式**：
```yaml
sources:
  - pattern: "ctx.request.body"
    label: "Custom framework input"
sinks:
  - function: "orm.rawQuery"
    tainted_args: [0]
    vulnerability: "sql-injection"
    cwe: "CWE-89"
sanitizers:
  - function: "customEscape"
```

### D7: L3 規則定義方式

**決策**：L3 規則不使用 Rhai 腳本，而是由 L3 engine 內建（hardcoded vulnerability types），複用 L2 taint config 的 source/sink/sanitizer 定義。每個 L2 taint config 中的 vulnerability type 自動產生對應的 L3 規則。

**理由**：
1. L3 規則的偵測邏輯完全由 call graph traversal + taint propagation 驅動，不需要 per-rule 的自訂邏輯
2. L2 的 taint config 已定義了所有 source/sink/sanitizer 對應，L3 只需要在跨函數維度重複使用
3. 減少維護負擔 — 新增 sink 只需修改 YAML，L3 自動受益

**Rule ID 格式**：`atlas/security/{lang}/l3-{vulnerability}`（如 `atlas/security/typescript/l3-sql-injection`）

**替代方案**：
- Rhai 腳本（原 spec 建議，但 L3 分析邏輯不需要 per-rule 自訂，增加不必要的複雜度）
- 獨立 YAML 規則檔（與 L1 YAML 混淆，L3 規則結構不同）

### D8: 跨檔案 Import 解析

**決策**：Phase 1 額外從 AST 提取 import/export 資訊，建構 `ImportIndex`（`HashMap<(file, imported_name), (source_file, exported_name)>`）。Call graph 使用此 index 解析跨檔案呼叫。

**語言策略**：
- TypeScript/JavaScript：`import { foo } from './bar'` → `(import_statement)`
- Python：`from module import func` → `(import_from_statement)`
- Java：class-level method calls within same package（package imports）
- Go：`package.Function()` → 透過 package path 解析
- C#：`using` + namespace 解析

**限制**：只解析靜態 import，不處理動態 `require()` 或 reflection。

## Risks / Trade-offs

### R1: 語法名稱解析的誤報/漏報
**風險**：同名函數在不同 module 中可能導致 call graph 誤連接；未解析的動態呼叫導致漏報。
→ **緩解**：conservative approach — 僅追蹤可靜態解析的呼叫，未解析的直接跳過。Finding confidence 設為 `Medium`，讓使用者自行判斷。加入 import index 提高跨檔案解析精確度。

### R2: 大型專案效能
**風險**：500+ 函數的專案中 call graph 建構與 per-callee scope graph 建構可能超時。
→ **緩解**：max_depth 預設 5 限制遍歷範圍。Phase 1 per-file 平行化。Phase 2 per-entry-point 平行化（rayon）。Scope graph 快取避免重複建構。30 秒逾時保護。

### R3: L2 scope graph builder 的 per-callee 使用
**風險**：L2 `ScopeGraphBuilder` 原設計為 per-file 使用，L3 需要按需為 callee 函數建構 scope graph。可能需要小幅重構。
→ **緩解**：`ScopeGraphBuilder.build_all()` 已可處理單檔案中的所有函數。L3 可快取 per-file scope graph 結果，按函數名查詢。無需修改 L2 核心邏輯。

### R4: 跨檔案 import 解析的語言複雜度
**風險**：每個語言的 import/export 語法差異大，完整實作成本高。
→ **緩解**：V1 僅實作 TypeScript 和 Python 的跨檔案解析（最常見的 web 框架語言）。Java/Go/C# 先僅支援同檔案跨函數。後續版本逐步擴展。

### R5: 與 L2 taint config 的耦合
**風險**：L3 直接依賴 L2 taint config 結構。若 L2 config 格式變更，L3 也需同步修改。
→ **緩解**：L2 taint config 結構已穩定（5 語言 × 5 漏洞類型）。自訂 config 合併透過獨立的 `merge_taint_config()` 函數隔離。

## Open Questions

1. **函數摘要快取**：V1 是否需要快取 callee 的分析摘要（「此函數：param[0] → return 傳播污染」）？快取可大幅提升多 call-site 的效能，但增加實作複雜度。暫定 V1 不快取，依效能測試結果決定是否在 V2 加入。

2. **跨檔案解析的語言優先順序**：V1 僅支援 TypeScript + Python 跨檔案解析，還是 5 語言全部支援？建議先 TypeScript + Python，觀察社群回饋。
