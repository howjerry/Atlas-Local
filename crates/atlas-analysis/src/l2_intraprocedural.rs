//! L2 intra-procedural data flow analysis。
//!
//! 為每個函數構建 scope graph，追蹤變數定義與使用，
//! 並識別函數邊界內的資料流路徑。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 污染狀態
// ---------------------------------------------------------------------------

/// 變數的污染狀態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintState {
    /// 受使用者輸入污染。
    Tainted,
    /// 確認安全（未受污染）。
    Clean,
    /// 尚未確定。
    Unknown,
}

impl Default for TaintState {
    fn default() -> Self {
        Self::Unknown
    }
}

// ---------------------------------------------------------------------------
// 資料流步驟型別
// ---------------------------------------------------------------------------

/// 資料流步驟的類型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStepType {
    /// 污染來源（使用者輸入）。
    Source,
    /// 傳播步驟（賦值、串接等）。
    Propagation,
    /// 接收點（危險函數呼叫）。
    Sink,
}

/// 資料流路徑中的單一步驟，包含完整位置資訊。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowStep {
    /// 步驟類型。
    pub step_type: FlowStepType,
    /// 1-indexed 行號。
    pub line: u32,
    /// 1-indexed 欄位號。
    pub column: u32,
    /// 原始碼表達式。
    pub expression: String,
    /// 人類可讀的描述。
    pub description: String,
}

// ---------------------------------------------------------------------------
// Scope graph types
// ---------------------------------------------------------------------------

/// 詞法作用域節點。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// 作用域 ID。
    pub id: u32,
    /// 父作用域 ID（根作用域為 None）。
    pub parent: Option<u32>,
    /// 作用域層級（0 = 函數頂層）。
    pub level: u32,
}

/// 函數內的變數定義。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarDef {
    /// 變數名稱。
    pub name: String,
    /// 定義所在行（1-indexed）。
    pub def_line: u32,
    /// 舊版相容：是否受污染（deprecated，請用 taint_state）。
    pub tainted: bool,
    /// 污染狀態（新增）。
    #[serde(default)]
    pub taint_state: TaintState,
    /// 所屬作用域 ID。
    #[serde(default)]
    pub scope_id: u32,
}

/// 函數內的變數使用（讀取/引用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarUse {
    /// 變數名稱。
    pub name: String,
    /// 使用所在行（1-indexed）。
    pub use_line: u32,
    /// 解析到的 VarDef 索引（在 ScopeGraph.definitions 中的位置）。
    #[serde(default)]
    pub resolved_def: Option<usize>,
}

/// 單函數內的資料流路徑。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPath {
    /// 來源變數定義。
    pub source: VarDef,
    /// 接收點變數使用。
    pub sink: VarUse,
    /// 中間傳播步驟。
    pub steps: Vec<FlowStep>,
}

/// 資料流路徑中的單一步驟（舊版，保留向後相容）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub line: u32,
    pub description: String,
}

/// 單一函數的 Scope Graph。
#[derive(Debug, Clone, Default)]
pub struct ScopeGraph {
    /// 所有變數定義。
    pub definitions: Vec<VarDef>,
    /// 所有變數使用。
    pub uses: Vec<VarUse>,
    /// 計算出的資料流路徑。
    pub flows: Vec<DataFlowPath>,
    /// 詞法作用域樹。
    pub scopes: Vec<Scope>,
}

impl ScopeGraph {
    /// 建立新的空 scope graph。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 新增變數定義。
    pub fn add_definition(&mut self, def: VarDef) {
        self.definitions.push(def);
    }

    /// 新增變數使用。
    pub fn add_use(&mut self, var_use: VarUse) {
        self.uses.push(var_use);
    }

    /// 新增作用域。
    pub fn add_scope(&mut self, scope: Scope) {
        self.scopes.push(scope);
    }

    /// 透過名稱匹配解析資料流路徑（舊版簡化方法，保留向後相容）。
    ///
    /// 對每個受污染的定義，找到所有後續使用相同變數名稱的位置，建立資料流路徑。
    pub fn resolve_flows(&mut self) {
        let mut flows = Vec::new();

        for def in &self.definitions {
            if !def.tainted {
                continue;
            }
            for var_use in &self.uses {
                if var_use.name == def.name && var_use.use_line >= def.def_line {
                    flows.push(DataFlowPath {
                        source: def.clone(),
                        sink: var_use.clone(),
                        steps: Vec::new(),
                    });
                }
            }
        }

        self.flows = flows;
    }
}

/// 單一檔案的 L2 分析結果。
#[derive(Debug, Clone, Default)]
pub struct L2AnalysisResult {
    /// 按函數名稱/位置索引的 scope graph。
    pub scope_graphs: BTreeMap<String, ScopeGraph>,
    /// 找到的資料流路徑數量。
    pub flows_found: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_graph_new_is_empty() {
        let sg = ScopeGraph::new();
        assert!(sg.definitions.is_empty());
        assert!(sg.uses.is_empty());
        assert!(sg.flows.is_empty());
        assert!(sg.scopes.is_empty());
    }

    #[test]
    fn add_definition_and_use() {
        let mut sg = ScopeGraph::new();
        sg.add_definition(VarDef {
            name: "user_input".to_string(),
            def_line: 5,
            tainted: true,
            taint_state: TaintState::Tainted,
            scope_id: 0,
        });
        sg.add_use(VarUse {
            name: "user_input".to_string(),
            use_line: 10,
            resolved_def: None,
        });
        assert_eq!(sg.definitions.len(), 1);
        assert_eq!(sg.uses.len(), 1);
    }

    #[test]
    fn resolve_tainted_flow() {
        let mut sg = ScopeGraph::new();
        sg.add_definition(VarDef {
            name: "input".to_string(),
            def_line: 1,
            tainted: true,
            taint_state: TaintState::Tainted,
            scope_id: 0,
        });
        sg.add_use(VarUse {
            name: "input".to_string(),
            use_line: 5,
            resolved_def: None,
        });
        sg.add_use(VarUse {
            name: "input".to_string(),
            use_line: 10,
            resolved_def: None,
        });

        sg.resolve_flows();

        assert_eq!(sg.flows.len(), 2, "should find 2 flows from tainted source");
        assert_eq!(sg.flows[0].source.name, "input");
        assert_eq!(sg.flows[0].sink.use_line, 5);
        assert_eq!(sg.flows[1].sink.use_line, 10);
    }

    #[test]
    fn untainted_definitions_produce_no_flows() {
        let mut sg = ScopeGraph::new();
        sg.add_definition(VarDef {
            name: "safe".to_string(),
            def_line: 1,
            tainted: false,
            taint_state: TaintState::Clean,
            scope_id: 0,
        });
        sg.add_use(VarUse {
            name: "safe".to_string(),
            use_line: 5,
            resolved_def: None,
        });

        sg.resolve_flows();

        assert!(
            sg.flows.is_empty(),
            "untainted def should not produce flows"
        );
    }

    #[test]
    fn use_before_definition_not_tracked() {
        let mut sg = ScopeGraph::new();
        sg.add_definition(VarDef {
            name: "x".to_string(),
            def_line: 10,
            tainted: true,
            taint_state: TaintState::Tainted,
            scope_id: 0,
        });
        sg.add_use(VarUse {
            name: "x".to_string(),
            use_line: 5, // 在定義之前
            resolved_def: None,
        });

        sg.resolve_flows();

        assert!(sg.flows.is_empty(), "use before def should not be a flow");
    }

    #[test]
    fn l2_analysis_result_default() {
        let result = L2AnalysisResult::default();
        assert!(result.scope_graphs.is_empty());
        assert_eq!(result.flows_found, 0);
    }

    #[test]
    fn taint_state_default_is_unknown() {
        assert_eq!(TaintState::default(), TaintState::Unknown);
    }

    #[test]
    fn scope_graph_with_scopes() {
        let mut sg = ScopeGraph::new();
        sg.add_scope(Scope {
            id: 0,
            parent: None,
            level: 0,
        });
        sg.add_scope(Scope {
            id: 1,
            parent: Some(0),
            level: 1,
        });
        assert_eq!(sg.scopes.len(), 2);
        assert_eq!(sg.scopes[1].parent, Some(0));
    }

    #[test]
    fn data_flow_step_serialization() {
        let step = DataFlowStep {
            step_type: FlowStepType::Source,
            line: 5,
            column: 12,
            expression: "req.body.name".to_string(),
            description: "User input from request body".to_string(),
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"step_type\":\"source\""));
        assert!(json.contains("\"line\":5"));
    }
}
