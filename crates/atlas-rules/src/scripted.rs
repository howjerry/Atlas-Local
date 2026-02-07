//! Rhai scripted rule engine for Atlas Local SAST.
//!
//! This module provides [`ScriptedRuleEngine`], which creates a sandboxed
//! [Rhai](https://rhai.rs) scripting environment for evaluating L2/L3 SAST
//! rules written as Rhai scripts.
//!
//! # How it works
//!
//! 1. A [`ScriptedRuleEngine`] is created with safety limits
//!    (max operations, max string size, etc.) to prevent runaway scripts.
//! 2. Rule scripts are compiled into [`rhai::AST`] objects via
//!    [`ScriptedRuleEngine::compile`].
//! 3. For each AST node to analyse, a [`NodeContext`] is converted into
//!    Rhai scope variables and the compiled script is evaluated via
//!    [`ScriptedRuleEngine::evaluate`].
//! 4. Scripts emit findings by calling the `emit_finding(msg)` function
//!    or by pushing messages onto the `findings` array variable that is
//!    injected into the scope.
//!
//! # Sandboxing
//!
//! The Rhai engine is configured with no access to the filesystem, network,
//! or any other external resources. Safety limits prevent infinite loops
//! and excessive memory consumption.
//!
//! # Example script
//!
//! ```rhai
//! // Detect dangerous function calls.
//! if node_type == "call_expression" && node_text.contains("unsafe_fn") {
//!     emit_finding("Dangerous function call detected");
//! }
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use rhai::packages::Package;
use rhai::{Array, Dynamic, Engine, Map, Scope, AST};
use tracing::debug;

// ---------------------------------------------------------------------------
// ScriptedRuleError
// ---------------------------------------------------------------------------

/// Errors arising from Rhai script compilation or evaluation.
#[derive(Debug, thiserror::Error)]
pub enum ScriptedRuleError {
    /// A Rhai script failed to compile.
    #[error("script compilation error: {0}")]
    Compilation(String),

    /// A Rhai script failed during evaluation.
    #[error("script evaluation error: {0}")]
    Evaluation(String),
}

// ---------------------------------------------------------------------------
// NodeContext
// ---------------------------------------------------------------------------

/// Context data for a single AST node, passed to a Rhai rule script.
///
/// All line and column values are **1-based** to match typical editor
/// conventions.
#[derive(Debug, Clone)]
pub struct NodeContext {
    /// The tree-sitter node type (e.g. `"call_expression"`).
    pub node_type: String,

    /// The source text covered by this node.
    pub node_text: String,

    /// 1-based start line.
    pub start_line: u32,

    /// 1-based end line.
    pub end_line: u32,

    /// 1-based start column.
    pub start_col: u32,

    /// End column.
    pub end_col: u32,

    /// Relative file path of the source file containing this node.
    pub file_path: String,

    /// Direct children of this node (same structure, recursive).
    pub children: Vec<NodeContext>,
}

impl NodeContext {
    /// Converts this context into a [`rhai::Dynamic`] map suitable for
    /// injection into a Rhai scope.
    fn to_dynamic(&self) -> Dynamic {
        let mut map = Map::new();

        map.insert("node_type".into(), self.node_type.clone().into());
        map.insert("node_text".into(), self.node_text.clone().into());
        map.insert(
            "start_line".into(),
            Dynamic::from(self.start_line as i64),
        );
        map.insert(
            "end_line".into(),
            Dynamic::from(self.end_line as i64),
        );
        map.insert(
            "start_col".into(),
            Dynamic::from(self.start_col as i64),
        );
        map.insert(
            "end_col".into(),
            Dynamic::from(self.end_col as i64),
        );
        map.insert("file_path".into(), self.file_path.clone().into());

        let children_array: Array =
            self.children.iter().map(|c| c.to_dynamic()).collect();
        map.insert("children".into(), children_array.into());

        map.into()
    }
}

// ---------------------------------------------------------------------------
// Engine construction helper
// ---------------------------------------------------------------------------

/// Creates a sandboxed Rhai [`Engine`] with the standard package and safety
/// limits, but no file I/O or network access.
fn make_sandboxed_engine() -> Engine {
    let mut engine = Engine::new_raw();

    // Register the standard package for core types, string operations,
    // iterators, and math -- but no I/O.
    let std_package = rhai::packages::StandardPackage::new();
    engine.register_global_module(std_package.as_shared_module());

    // Safety limits.
    engine.set_max_operations(100_000);
    engine.set_max_string_size(65_536);
    engine.set_max_array_size(4_096);
    engine.set_max_map_size(1_024);
    engine.set_max_call_levels(64);

    engine
}

// ---------------------------------------------------------------------------
// ScriptedRuleEngine
// ---------------------------------------------------------------------------

/// A sandboxed Rhai scripting engine for evaluating SAST rule scripts.
///
/// The engine is configured with safety limits to prevent runaway scripts
/// and does **not** expose any file I/O or network functionality.
pub struct ScriptedRuleEngine {
    /// Engine used for compilation. A separate engine is created for each
    /// evaluation call so that `emit_finding` can be registered with a
    /// fresh findings collector.
    engine: Engine,
}

impl ScriptedRuleEngine {
    /// Creates a new scripted rule engine with safety limits.
    ///
    /// The following limits are applied:
    ///
    /// | Limit              | Value    |
    /// |--------------------|----------|
    /// | `max_operations`   | 100 000  |
    /// | `max_string_size`  | 65 536   |
    /// | `max_array_size`   | 4 096    |
    /// | `max_map_size`     | 1 024    |
    /// | `max_call_levels`  | 64       |
    pub fn new() -> Self {
        let engine = make_sandboxed_engine();
        debug!("scripted rule engine created with safety limits");
        Self { engine }
    }

    /// Compiles a Rhai script source string into an [`AST`].
    ///
    /// # Errors
    ///
    /// Returns [`ScriptedRuleError::Compilation`] if the script contains
    /// syntax errors.
    pub fn compile(
        &self,
        script: &str,
    ) -> Result<AST, ScriptedRuleError> {
        self.engine
            .compile(script)
            .map_err(|e| ScriptedRuleError::Compilation(e.to_string()))
    }

    /// Evaluates a compiled script against the given [`NodeContext`].
    ///
    /// Node fields are injected into the Rhai scope as top-level variables
    /// (`node_type`, `node_text`, `start_line`, etc.) **and** as a single
    /// `node` map variable for structured access.
    ///
    /// A `findings` array is also placed in the scope. Scripts emit
    /// findings either by calling `emit_finding(msg)` or by directly
    /// pushing onto `findings`.
    ///
    /// # Returns
    ///
    /// A `Vec<String>` of all emitted finding messages.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptedRuleError::Evaluation`] if the script encounters
    /// a runtime error (including exceeding safety limits).
    pub fn evaluate(
        &self,
        ast: &AST,
        node: &NodeContext,
    ) -> Result<Vec<String>, ScriptedRuleError> {
        // Create a fresh engine for this evaluation so we can register
        // `emit_finding` with a per-call findings collector.
        let mut eval_engine = make_sandboxed_engine();

        // Shared findings collector.
        let findings: Rc<RefCell<Vec<String>>> =
            Rc::new(RefCell::new(Vec::new()));
        let findings_clone = Rc::clone(&findings);

        // Register `emit_finding` as a native function that pushes a
        // message into the shared collector.
        eval_engine.register_fn("emit_finding", move |msg: &str| {
            findings_clone.borrow_mut().push(msg.to_owned());
        });

        // Build the scope with node fields as top-level variables.
        let mut scope = Scope::new();
        scope.push("node_type", node.node_type.clone());
        scope.push("node_text", node.node_text.clone());
        scope.push("start_line", node.start_line as i64);
        scope.push("end_line", node.end_line as i64);
        scope.push("start_col", node.start_col as i64);
        scope.push("end_col", node.end_col as i64);
        scope.push("file_path", node.file_path.clone());

        // Children as a Rhai array of maps.
        let children_array: Array =
            node.children.iter().map(|c| c.to_dynamic()).collect();
        scope.push("children", children_array);

        // Also expose the full node as a single map.
        scope.push("node", node.to_dynamic());

        // A findings array in the scope so scripts can also do
        // `findings.push("msg")` directly.
        let scope_findings: Array = Vec::new();
        scope.push("findings", scope_findings);

        // Run the script.
        let run_result = eval_engine
            .run_ast_with_scope(&mut scope, ast)
            .map_err(|e| {
                ScriptedRuleError::Evaluation(e.to_string())
            });

        // Drop the engine to release its Rc reference to the findings
        // collector (held by the registered `emit_finding` closure).
        drop(eval_engine);

        // Propagate any evaluation error.
        run_result?;

        // Collect findings from the `emit_finding` function calls.
        let mut result = Rc::try_unwrap(findings)
            .expect(
                "findings Rc should have exactly one strong \
                 reference after evaluation engine is dropped",
            )
            .into_inner();

        // Also extract scope-based findings (from `findings.push()`).
        if let Some(scope_findings) =
            scope.get_value::<Array>("findings")
        {
            for val in scope_findings {
                if let Ok(s) = val.into_string() {
                    result.push(s);
                }
            }
        }

        Ok(result)
    }
}

impl Default for ScriptedRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal [`NodeContext`] with the given type and text.
    fn make_node(node_type: &str, node_text: &str) -> NodeContext {
        NodeContext {
            node_type: node_type.to_owned(),
            node_text: node_text.to_owned(),
            start_line: 1,
            end_line: 1,
            start_col: 1,
            end_col: 10,
            file_path: "test.ts".to_owned(),
            children: Vec::new(),
        }
    }

    /// Helper: create a [`NodeContext`] with explicit positions.
    fn make_node_with_pos(
        node_type: &str,
        node_text: &str,
        start_line: u32,
        end_line: u32,
        start_col: u32,
        end_col: u32,
        file_path: &str,
    ) -> NodeContext {
        NodeContext {
            node_type: node_type.to_owned(),
            node_text: node_text.to_owned(),
            start_line,
            end_line,
            start_col,
            end_col,
            file_path: file_path.to_owned(),
            children: Vec::new(),
        }
    }

    // -------------------------------------------------------------------
    // 1. Engine creation with safety limits
    // -------------------------------------------------------------------

    #[test]
    fn engine_creation_with_safety_limits() {
        let engine = ScriptedRuleEngine::new();
        // Verify the engine was created by compiling a trivial script.
        let ast = engine.compile("let x = 1;");
        assert!(ast.is_ok(), "engine should compile a trivial script");
    }

    // -------------------------------------------------------------------
    // 2. Compile valid script
    // -------------------------------------------------------------------

    #[test]
    fn compile_valid_script() {
        let engine = ScriptedRuleEngine::new();
        let script = r#"
            if node_type == "call_expression" {
                emit_finding("found call");
            }
        "#;
        let result = engine.compile(script);
        assert!(
            result.is_ok(),
            "valid script should compile successfully"
        );
    }

    // -------------------------------------------------------------------
    // 3. Compile invalid script returns error
    // -------------------------------------------------------------------

    #[test]
    fn compile_invalid_script_returns_error() {
        let engine = ScriptedRuleEngine::new();
        let script = "if { {{{{ not valid rhai";
        let result = engine.compile(script);
        assert!(
            result.is_err(),
            "invalid script should fail to compile"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScriptedRuleError::Compilation(_)),
            "error should be Compilation variant, got: {err}"
        );
        // The error message should contain something meaningful.
        assert!(
            !err.to_string().is_empty(),
            "error message should not be empty"
        );
    }

    // -------------------------------------------------------------------
    // 4. Evaluate script that emits no findings
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_script_emits_no_findings() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                let x = 1 + 2;
            "#,
            )
            .unwrap();

        let node = make_node("identifier", "foo");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert!(
            findings.is_empty(),
            "script that emits nothing should return empty findings"
        );
    }

    // -------------------------------------------------------------------
    // 5. Evaluate script that emits one finding
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_script_emits_one_finding() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(r#"emit_finding("found something");"#)
            .unwrap();

        let node = make_node("identifier", "x");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "found something");
    }

    // -------------------------------------------------------------------
    // 6. Evaluate script that emits multiple findings
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_script_emits_multiple_findings() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                emit_finding("finding one");
                emit_finding("finding two");
                emit_finding("finding three");
            "#,
            )
            .unwrap();

        let node = make_node("identifier", "x");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0], "finding one");
        assert_eq!(findings[1], "finding two");
        assert_eq!(findings[2], "finding three");
    }

    // -------------------------------------------------------------------
    // 7. Script can access node_type and node_text
    // -------------------------------------------------------------------

    #[test]
    fn script_accesses_node_type_and_node_text() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                if node_type == "call_expression" {
                    if node_text.contains("dangerous") {
                        emit_finding("Dangerous call detected");
                    }
                }
            "#,
            )
            .unwrap();

        // Should match.
        let node =
            make_node("call_expression", "dangerous(user_input)");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "Dangerous call detected");

        // Should NOT match (wrong node type).
        let node2 = make_node("identifier", "dangerous");
        let findings2 = engine.evaluate(&ast, &node2).unwrap();
        assert!(
            findings2.is_empty(),
            "non-matching node_type should emit nothing"
        );
    }

    // -------------------------------------------------------------------
    // 8. Script can access line numbers
    // -------------------------------------------------------------------

    #[test]
    fn script_accesses_line_numbers() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                if start_line == 42 && end_line == 44 {
                    emit_finding("found at expected lines");
                }
            "#,
            )
            .unwrap();

        let node = make_node_with_pos(
            "block",
            "{ ... }",
            42,
            44,
            5,
            6,
            "src/main.ts",
        );
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "found at expected lines");
    }

    // -------------------------------------------------------------------
    // 9. Script can access children array
    // -------------------------------------------------------------------

    #[test]
    fn script_accesses_children_array() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                if children.len() == 2 {
                    let first = children[0];
                    if first.node_type == "identifier" {
                        emit_finding(
                            "first child is identifier: "
                            + first.node_text
                        );
                    }
                }
            "#,
            )
            .unwrap();

        let child1 = NodeContext {
            node_type: "identifier".to_owned(),
            node_text: "my_func".to_owned(),
            start_line: 1,
            end_line: 1,
            start_col: 1,
            end_col: 5,
            file_path: "test.ts".to_owned(),
            children: Vec::new(),
        };
        let child2 = NodeContext {
            node_type: "arguments".to_owned(),
            node_text: "(x)".to_owned(),
            start_line: 1,
            end_line: 1,
            start_col: 5,
            end_col: 8,
            file_path: "test.ts".to_owned(),
            children: Vec::new(),
        };

        let node = NodeContext {
            node_type: "call_expression".to_owned(),
            node_text: "my_func(x)".to_owned(),
            start_line: 1,
            end_line: 1,
            start_col: 1,
            end_col: 8,
            file_path: "test.ts".to_owned(),
            children: vec![child1, child2],
        };

        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0],
            "first child is identifier: my_func"
        );
    }

    // -------------------------------------------------------------------
    // 10. Engine limits prevent infinite loops (max_operations)
    // -------------------------------------------------------------------

    #[test]
    fn engine_limits_prevent_infinite_loops() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                loop {
                    // This should be stopped by max_operations.
                }
            "#,
            )
            .unwrap();

        let node = make_node("identifier", "x");
        let result = engine.evaluate(&ast, &node);
        assert!(
            result.is_err(),
            "infinite loop should be stopped by max_operations"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ScriptedRuleError::Evaluation(_)),
            "error should be Evaluation variant, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // 11. NodeContext to Dynamic conversion preserves all fields
    // -------------------------------------------------------------------

    #[test]
    fn node_context_to_dynamic_preserves_all_fields() {
        let child = NodeContext {
            node_type: "identifier".to_owned(),
            node_text: "child_text".to_owned(),
            start_line: 5,
            end_line: 5,
            start_col: 10,
            end_col: 20,
            file_path: "child.ts".to_owned(),
            children: Vec::new(),
        };

        let node = NodeContext {
            node_type: "call_expression".to_owned(),
            node_text: "foo(bar)".to_owned(),
            start_line: 10,
            end_line: 12,
            start_col: 3,
            end_col: 11,
            file_path: "src/main.ts".to_owned(),
            children: vec![child],
        };

        let dynamic = node.to_dynamic();
        let map = dynamic.cast::<Map>();

        assert_eq!(
            map.get("node_type")
                .unwrap()
                .clone()
                .into_string()
                .unwrap(),
            "call_expression"
        );
        assert_eq!(
            map.get("node_text")
                .unwrap()
                .clone()
                .into_string()
                .unwrap(),
            "foo(bar)"
        );
        assert_eq!(
            map.get("start_line").unwrap().as_int().unwrap(),
            10
        );
        assert_eq!(
            map.get("end_line").unwrap().as_int().unwrap(),
            12
        );
        assert_eq!(
            map.get("start_col").unwrap().as_int().unwrap(),
            3
        );
        assert_eq!(
            map.get("end_col").unwrap().as_int().unwrap(),
            11
        );
        assert_eq!(
            map.get("file_path")
                .unwrap()
                .clone()
                .into_string()
                .unwrap(),
            "src/main.ts"
        );

        let children = map
            .get("children")
            .unwrap()
            .clone()
            .into_array()
            .unwrap();
        assert_eq!(children.len(), 1);

        let child_map = children[0].clone().cast::<Map>();
        assert_eq!(
            child_map
                .get("node_type")
                .unwrap()
                .clone()
                .into_string()
                .unwrap(),
            "identifier"
        );
        assert_eq!(
            child_map
                .get("node_text")
                .unwrap()
                .clone()
                .into_string()
                .unwrap(),
            "child_text"
        );
    }

    // -------------------------------------------------------------------
    // 12. Script with conditional logic (only emit when pattern matches)
    // -------------------------------------------------------------------

    #[test]
    fn script_conditional_emit_on_pattern_match() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                // Only flag specific dangerous calls.
                if node_type == "call_expression" {
                    if node_text.contains("unsafe_call(") {
                        emit_finding("unsafe_call() is dangerous");
                    }
                    if node_text.contains("risky_op(") {
                        emit_finding("risky_op() is dangerous");
                    }
                }
            "#,
            )
            .unwrap();

        // unsafe_call: should match first condition.
        let findings = engine
            .evaluate(
                &ast,
                &make_node("call_expression", "unsafe_call(x)"),
            )
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "unsafe_call() is dangerous");

        // risky_op: should match second condition.
        let findings = engine
            .evaluate(
                &ast,
                &make_node("call_expression", "risky_op(cmd)"),
            )
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "risky_op() is dangerous");

        // safe call: should match neither.
        let findings = engine
            .evaluate(
                &ast,
                &make_node("call_expression", "console.log(x)"),
            )
            .unwrap();
        assert!(findings.is_empty());

        // wrong node type: should match nothing.
        let findings = engine
            .evaluate(
                &ast,
                &make_node("identifier", "unsafe_call"),
            )
            .unwrap();
        assert!(findings.is_empty());
    }

    // -------------------------------------------------------------------
    // 13. Scope-based findings via direct push
    // -------------------------------------------------------------------

    #[test]
    fn scope_based_findings_via_push() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                findings.push("pushed finding");
            "#,
            )
            .unwrap();

        let node = make_node("identifier", "x");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "pushed finding");
    }

    // -------------------------------------------------------------------
    // 14. Mixed emit_finding and scope push
    // -------------------------------------------------------------------

    #[test]
    fn mixed_emit_and_scope_findings() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                emit_finding("via emit");
                findings.push("via push");
            "#,
            )
            .unwrap();

        let node = make_node("identifier", "x");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 2);
        // emit_finding findings come first, scope findings second.
        assert_eq!(findings[0], "via emit");
        assert_eq!(findings[1], "via push");
    }

    // -------------------------------------------------------------------
    // 15. Script can access file_path and column numbers
    // -------------------------------------------------------------------

    #[test]
    fn script_accesses_file_path_and_columns() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                if file_path == "src/lib.rs"
                    && start_col == 5
                    && end_col == 20
                {
                    emit_finding("correct location");
                }
            "#,
            )
            .unwrap();

        let node = make_node_with_pos(
            "identifier",
            "x",
            1,
            1,
            5,
            20,
            "src/lib.rs",
        );
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "correct location");
    }

    // -------------------------------------------------------------------
    // 16. Script can access the unified `node` map
    // -------------------------------------------------------------------

    #[test]
    fn script_accesses_node_map() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(
                r#"
                if node.node_type == "call_expression" {
                    emit_finding(
                        "node map works: " + node.node_text
                    );
                }
            "#,
            )
            .unwrap();

        let node =
            make_node("call_expression", "dangerous_func()");
        let findings = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0],
            "node map works: dangerous_func()"
        );
    }

    // -------------------------------------------------------------------
    // 17. Default trait implementation
    // -------------------------------------------------------------------

    #[test]
    fn default_creates_working_engine() {
        let engine = ScriptedRuleEngine::default();
        let ast = engine.compile("let x = 42;");
        assert!(
            ast.is_ok(),
            "default engine should compile a trivial script"
        );
    }

    // -------------------------------------------------------------------
    // 18. Evaluate does not leak findings between calls
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_does_not_leak_findings_between_calls() {
        let engine = ScriptedRuleEngine::new();
        let ast = engine
            .compile(r#"emit_finding("hello");"#)
            .unwrap();

        let node = make_node("identifier", "x");

        let findings1 = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(findings1.len(), 1);

        let findings2 = engine.evaluate(&ast, &node).unwrap();
        assert_eq!(
            findings2.len(),
            1,
            "second evaluation should not inherit findings \
             from the first"
        );
    }
}
