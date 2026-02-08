//! L2 intra-procedural data flow analysis (T086).
//!
//! Builds a scope graph per function, tracks variable definitions and uses,
//! and identifies data flow paths within function boundaries.
//!
//! **Status: NOT YET INTEGRATED.** Type definitions and scope-graph builder
//! are scaffolded here but are not connected to the scan pipeline. No L2 rules
//! exist yet. This module is retained as a design reference for future work.

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Scope graph types
// ---------------------------------------------------------------------------

/// A variable definition within a function scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarDef {
    /// Variable name.
    pub name: String,
    /// Line where the variable is defined.
    pub def_line: u32,
    /// Whether this definition is tainted (comes from user input).
    pub tainted: bool,
}

/// A variable use (read/reference) within a function scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarUse {
    /// Variable name.
    pub name: String,
    /// Line where the variable is used.
    pub use_line: u32,
}

/// An intra-procedural data flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPath {
    /// Source variable definition.
    pub source: VarDef,
    /// Sink variable use.
    pub sink: VarUse,
    /// Intermediate assignments/operations in the flow.
    pub steps: Vec<FlowStep>,
}

/// A single step in a data flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub line: u32,
    pub description: String,
}

/// Scope graph for a single function.
#[derive(Debug, Clone, Default)]
pub struct ScopeGraph {
    /// All variable definitions in the function.
    pub definitions: Vec<VarDef>,
    /// All variable uses in the function.
    pub uses: Vec<VarUse>,
    /// Computed data flow paths from tainted sources to sinks.
    pub flows: Vec<DataFlowPath>,
}

impl ScopeGraph {
    /// Creates a new empty scope graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a variable definition.
    pub fn add_definition(&mut self, def: VarDef) {
        self.definitions.push(def);
    }

    /// Adds a variable use.
    pub fn add_use(&mut self, var_use: VarUse) {
        self.uses.push(var_use);
    }

    /// Resolves data flow paths by matching definitions to uses.
    ///
    /// For each tainted definition, finds all subsequent uses of the same
    /// variable name and creates a data flow path.
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

/// L2 analysis result for a single file.
#[derive(Debug, Clone, Default)]
pub struct L2AnalysisResult {
    /// Scope graphs indexed by function name/location.
    pub scope_graphs: BTreeMap<String, ScopeGraph>,
    /// Data flow paths found across all functions.
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
    }

    #[test]
    fn add_definition_and_use() {
        let mut sg = ScopeGraph::new();
        sg.add_definition(VarDef {
            name: "user_input".to_string(),
            def_line: 5,
            tainted: true,
        });
        sg.add_use(VarUse {
            name: "user_input".to_string(),
            use_line: 10,
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
        });
        sg.add_use(VarUse {
            name: "input".to_string(),
            use_line: 5,
        });
        sg.add_use(VarUse {
            name: "input".to_string(),
            use_line: 10,
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
        });
        sg.add_use(VarUse {
            name: "safe".to_string(),
            use_line: 5,
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
        });
        sg.add_use(VarUse {
            name: "x".to_string(),
            use_line: 5, // before definition
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
}
