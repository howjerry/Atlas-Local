//! L3 inter-procedural taint analysis (T087).
//!
//! Builds a cross-file call graph, tracks taint sources and sinks across
//! function boundaries, with a configurable call-depth limit to prevent
//! explosion in large codebases.
//!
//! **Current status**: Framework with type definitions and call graph builder.
//! Full cross-file taint propagation requires integration with the scan
//! pipeline (T088).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Call graph types
// ---------------------------------------------------------------------------

/// A function declaration with its location.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionRef {
    /// File containing the function.
    pub file_path: String,
    /// Function name.
    pub name: String,
    /// Line number of the function declaration.
    pub line: u32,
}

/// A call site within a function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallSite {
    /// The function being called.
    pub callee: String,
    /// Line number of the call.
    pub line: u32,
    /// Whether any arguments to the call are tainted.
    pub tainted_args: Vec<u32>, // argument indices
}

/// A taint source (user input, external data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub file_path: String,
    pub function: String,
    pub variable: String,
    pub line: u32,
    pub source_type: String, // e.g. "user_input", "database", "network"
}

/// A taint sink (dangerous operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub file_path: String,
    pub function: String,
    pub variable: String,
    pub line: u32,
    pub sink_type: String, // e.g. "sql_query", "exec", "innerHTML"
}

/// A cross-file taint path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: TaintSource,
    pub sink: TaintSink,
    /// Functions traversed in the call chain.
    pub call_chain: Vec<FunctionRef>,
    /// Depth of the call chain.
    pub depth: u32,
}

// ---------------------------------------------------------------------------
// Call graph
// ---------------------------------------------------------------------------

/// Configuration for taint analysis.
#[derive(Debug, Clone)]
pub struct TaintConfig {
    /// Maximum call-depth to follow.
    pub max_depth: u32,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self { max_depth: 5 }
    }
}

/// Cross-file call graph for taint analysis.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// Functions indexed by file_path::function_name.
    pub functions: BTreeMap<String, FunctionRef>,
    /// Outgoing calls from each function.
    pub calls: BTreeMap<String, Vec<CallSite>>,
    /// Known taint sources.
    pub sources: Vec<TaintSource>,
    /// Known taint sinks.
    pub sinks: Vec<TaintSink>,
}

impl CallGraph {
    /// Creates a new empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a function in the call graph.
    pub fn add_function(&mut self, func: FunctionRef) {
        let key = format!("{}::{}", func.file_path, func.name);
        self.functions.insert(key, func);
    }

    /// Adds a call site from a function.
    pub fn add_call(&mut self, caller_key: &str, call: CallSite) {
        self.calls
            .entry(caller_key.to_string())
            .or_default()
            .push(call);
    }

    /// Adds a taint source.
    pub fn add_source(&mut self, source: TaintSource) {
        self.sources.push(source);
    }

    /// Adds a taint sink.
    pub fn add_sink(&mut self, sink: TaintSink) {
        self.sinks.push(sink);
    }

    /// Returns the set of functions reachable from a given function within max_depth.
    pub fn reachable_from(&self, function_key: &str, max_depth: u32) -> BTreeSet<String> {
        let mut visited = BTreeSet::new();
        let mut queue = vec![(function_key.to_string(), 0u32)];

        while let Some((current, depth)) = queue.pop() {
            if depth > max_depth || visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            if let Some(calls) = self.calls.get(&current) {
                for call in calls {
                    // Try to resolve the callee to a registered function.
                    for key in self.functions.keys() {
                        if key.ends_with(&format!("::{}", call.callee)) {
                            queue.push((key.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        visited
    }

    /// Returns the number of registered functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Returns the total number of call sites.
    pub fn call_count(&self) -> usize {
        self.calls.values().map(|v| v.len()).sum()
    }
}

/// L3 analysis result for a project.
#[derive(Debug, Clone, Default)]
pub struct L3AnalysisResult {
    /// Taint paths found.
    pub taint_paths: Vec<TaintPath>,
    /// Number of functions analyzed.
    pub functions_analyzed: u32,
    /// Call graph statistics.
    pub total_calls: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_graph_new_is_empty() {
        let cg = CallGraph::new();
        assert_eq!(cg.function_count(), 0);
        assert_eq!(cg.call_count(), 0);
    }

    #[test]
    fn add_function_and_call() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "src/main.ts".to_string(),
            name: "handleRequest".to_string(),
            line: 10,
        });
        cg.add_function(FunctionRef {
            file_path: "src/db.ts".to_string(),
            name: "queryDb".to_string(),
            line: 5,
        });
        cg.add_call(
            "src/main.ts::handleRequest",
            CallSite {
                callee: "queryDb".to_string(),
                line: 15,
                tainted_args: vec![0],
            },
        );

        assert_eq!(cg.function_count(), 2);
        assert_eq!(cg.call_count(), 1);
    }

    #[test]
    fn reachable_from_simple_chain() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "a.ts".to_string(),
            name: "a".to_string(),
            line: 1,
        });
        cg.add_function(FunctionRef {
            file_path: "b.ts".to_string(),
            name: "b".to_string(),
            line: 1,
        });
        cg.add_function(FunctionRef {
            file_path: "c.ts".to_string(),
            name: "c".to_string(),
            line: 1,
        });

        cg.add_call(
            "a.ts::a",
            CallSite {
                callee: "b".to_string(),
                line: 2,
                tainted_args: vec![],
            },
        );
        cg.add_call(
            "b.ts::b",
            CallSite {
                callee: "c".to_string(),
                line: 2,
                tainted_args: vec![],
            },
        );

        let reachable = cg.reachable_from("a.ts::a", 5);
        assert!(reachable.contains("a.ts::a"));
        assert!(reachable.contains("b.ts::b"));
        assert!(reachable.contains("c.ts::c"));
    }

    #[test]
    fn reachable_respects_depth_limit() {
        let mut cg = CallGraph::new();
        cg.add_function(FunctionRef {
            file_path: "a.ts".to_string(),
            name: "a".to_string(),
            line: 1,
        });
        cg.add_function(FunctionRef {
            file_path: "b.ts".to_string(),
            name: "b".to_string(),
            line: 1,
        });
        cg.add_function(FunctionRef {
            file_path: "c.ts".to_string(),
            name: "c".to_string(),
            line: 1,
        });

        cg.add_call(
            "a.ts::a",
            CallSite {
                callee: "b".to_string(),
                line: 2,
                tainted_args: vec![],
            },
        );
        cg.add_call(
            "b.ts::b",
            CallSite {
                callee: "c".to_string(),
                line: 2,
                tainted_args: vec![],
            },
        );

        // Depth 1: only a and b reachable.
        let reachable = cg.reachable_from("a.ts::a", 1);
        assert!(reachable.contains("a.ts::a"));
        assert!(reachable.contains("b.ts::b"));
        assert!(!reachable.contains("c.ts::c"));
    }

    #[test]
    fn taint_config_default() {
        let config = TaintConfig::default();
        assert_eq!(config.max_depth, 5);
    }

    #[test]
    fn l3_result_default() {
        let result = L3AnalysisResult::default();
        assert!(result.taint_paths.is_empty());
        assert_eq!(result.functions_analyzed, 0);
        assert_eq!(result.total_calls, 0);
    }

    #[test]
    fn add_source_and_sink() {
        let mut cg = CallGraph::new();
        cg.add_source(TaintSource {
            file_path: "src/api.ts".to_string(),
            function: "handlePost".to_string(),
            variable: "body".to_string(),
            line: 5,
            source_type: "user_input".to_string(),
        });
        cg.add_sink(TaintSink {
            file_path: "src/db.ts".to_string(),
            function: "query".to_string(),
            variable: "sql".to_string(),
            line: 10,
            sink_type: "sql_query".to_string(),
        });

        assert_eq!(cg.sources.len(), 1);
        assert_eq!(cg.sinks.len(), 1);
    }
}
