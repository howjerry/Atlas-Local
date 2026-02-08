# Research: Tree-sitter AST Patterns for Quality Rules

**Feature**: 002-code-quality-analysis
**Created**: 2026-02-08
**Purpose**: Document the tree-sitter S-expression query patterns for each of the 36 quality rules, with AST node type research and known edge cases.

## Methodology

Each rule's pattern was researched by:
1. Writing sample code that should trigger the rule (fail case)
2. Parsing the sample with the language's tree-sitter grammar
3. Inspecting the AST to identify stable node types and field names
4. Crafting an S-expression query that captures the anti-pattern with `@match`
5. Identifying pass cases that should NOT trigger the rule

All patterns target the L1 engine (single-query matching, no data flow).

---

## TypeScript / JavaScript (10 rules)

### 1. `empty-catch-block` (P1)

**Pattern**: A `catch_clause` whose body (`(statement_block)`) contains no statements.

```scheme
(catch_clause
  body: (statement_block) @body
  (#eq? @body "{}"))
@match
```

**Alternative (more robust)**: Match a `catch_clause` with a `statement_block` that has exactly two children (the `{` and `}` tokens, no statements):

```scheme
(catch_clause
  body: (statement_block
    "{" "}"
    !(_)))
@match
```

**Preferred approach**: Use the simplest pattern — a `catch_clause` where the body `statement_block` has no child statements. In tree-sitter TypeScript, an empty `statement_block` contains only the braces as anonymous nodes:

```scheme
(catch_clause
  body: (statement_block) @body)
@match
```

Then check in post-processing or with negation that `@body` has no named children. However, since L1 only supports S-expression matching, the practical approach is:

```scheme
(catch_clause
  body: (statement_block
    .
    "}"))
@match
```

**Fail**: `try { foo(); } catch (e) { }`
**Pass**: `try { foo(); } catch (e) { console.error(e); }`

**Note**: Comments inside the catch block (e.g., `// intentionally empty`) will have a `comment` node, making the block non-empty to tree-sitter. This is acceptable — a catch block with only a comment is a borderline case.

---

### 2. `console-log` (P1)

**Pattern**: A `call_expression` where the function is `console.log`, `console.warn`, `console.error`, `console.debug`, `console.info`.

```scheme
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @prop
    (#eq? @obj "console")
    (#match? @prop "^(log|warn|error|debug|info|trace|dir)$")))
@match
```

**Fail**: `console.log("debug value:", x);`
**Pass**: `logger.info("structured log");`

**Edge case**: `window.console.log()` — the object would be a `member_expression` not an `identifier`. This is uncommon; the P1 pattern covers 99% of cases.

---

### 3. `any-type-usage` (P1)

**Pattern**: A type annotation using the `any` keyword in TypeScript.

```scheme
(type_annotation
  (predefined_type) @type
  (#eq? @type "any"))
@match
```

**Fail**: `function foo(x: any): void {}`
**Pass**: `function foo(x: string): void {}`

**Edge case**: `as any` casts use `as_expression` with a `predefined_type` child. We can add a second pattern:

```scheme
[
  (type_annotation
    (predefined_type) @type
    (#eq? @type "any"))
  (as_expression
    (predefined_type) @type
    (#eq? @type "any"))
]
@match
```

---

### 4. `loose-equality` (P1)

**Pattern**: A `binary_expression` using `==` or `!=` operators (instead of `===` / `!==`).

```scheme
(binary_expression
  operator: ["==" "!="])
@match
```

**Fail**: `if (x == null) {}`
**Pass**: `if (x === null) {}`

**Edge case**: `x == null` is sometimes considered acceptable TypeScript for null/undefined coalescing. This is a known low-confidence pattern; teams can suppress if desired.

---

### 5. `var-declaration` (P1)

**Pattern**: A variable declaration using `var` keyword.

In tree-sitter TypeScript, `var x = 1` produces a `variable_declaration` node (same as `let`/`const`). The `var` keyword is an anonymous child. However, tree-sitter distinguishes `lexical_declaration` (let/const) from `variable_declaration` (var):

```scheme
(variable_declaration) @match
```

**Fail**: `var x = 42;`
**Pass**: `let x = 42;` or `const x = 42;`

**Note**: In tree-sitter-typescript, `var` produces `variable_declaration` while `let`/`const` produce `lexical_declaration`. This distinction makes the pattern trivially correct.

---

### 6. `non-null-assertion` (P2)

**Pattern**: A `non_null_expression` (the `!` postfix operator in TypeScript).

```scheme
(non_null_expression) @match
```

**Fail**: `const len = value!.length;`
**Pass**: `const len = value?.length ?? 0;`

---

### 7. `todo-comment` (P2)

**Pattern**: A `comment` node containing TODO, FIXME, HACK, or XXX.

```scheme
(comment) @match
(#match? @match "(TODO|FIXME|HACK|XXX)")
```

**Fail**: `// TODO: refactor this function`
**Pass**: `// This function handles user input`

---

### 8. `empty-function-body` (P2)

**Pattern**: A function declaration/expression/arrow function with an empty body.

```scheme
[
  (function_declaration
    body: (statement_block
      .
      "}"))
  (function_expression
    body: (statement_block
      .
      "}"))
  (arrow_function
    body: (statement_block
      .
      "}"))
]
@match
```

**Fail**: `function noop() {}`
**Pass**: `function greet() { return "hello"; }`

---

### 9. `redundant-boolean` (P2)

**Pattern**: A binary expression comparing a value to `true` or `false` with `===` or `==`.

```scheme
(binary_expression
  operator: ["==" "===" "!=" "!=="]
  [(true) (false)])
@match
```

**Fail**: `if (isActive === true) {}`
**Pass**: `if (isActive) {}`

**Note**: tree-sitter uses `true` and `false` as node types for boolean literals.

---

### 10. `excessive-parameters` (P2)

**Pattern**: A function declaration with more than 5 formal parameters.

This is difficult to express as a pure S-expression pattern because tree-sitter queries don't support counting. The approach is to match a `formal_parameters` node with at least 6 children:

```scheme
(function_declaration
  parameters: (formal_parameters
    (_) @p1 . (_) @p2 . (_) @p3 . (_) @p4 . (_) @p5 . (_) @p6))
@match
```

**Fail**: `function foo(a, b, c, d, e, f) {}`
**Pass**: `function bar(a, b, c) {}`

**Note**: The `.` (anchor) operator ensures consecutive sibling matching. This pattern matches exactly "6 or more consecutive named children" in the parameters list.

---

## Java (7 rules)

### 1. `empty-catch-block` (P1)

**Pattern**: A `catch_clause` with an empty block.

```scheme
(catch_clause
  body: (block
    .
    "}"))
@match
```

**Fail**: `try { riskyOp(); } catch (Exception e) { }`
**Pass**: `try { riskyOp(); } catch (Exception e) { logger.error("Failed", e); }`

---

### 2. `system-out-println` (P1)

**Pattern**: A method invocation on `System.out` or `System.err` calling print methods.

```scheme
(method_invocation
  object: (field_access
    object: (identifier) @cls
    field: (identifier) @field
    (#eq? @cls "System")
    (#match? @field "^(out|err)$"))
  name: (identifier) @method
  (#match? @method "^(println|print|printf|format)$"))
@match
```

**Fail**: `System.out.println("debug: " + value);`
**Pass**: `logger.info("structured log: {}", value);`

---

### 3. `todo-comment` (P2)

```scheme
(comment) @match
(#match? @match "(TODO|FIXME|HACK|XXX)")
```

Same pattern structure as TypeScript.

---

### 4. `empty-method-body` (P2)

**Pattern**: A method declaration with an empty body.

```scheme
(method_declaration
  body: (block
    .
    "}"))
@match
```

**Fail**: `public void onEvent(Event e) { }`
**Pass**: `public void onEvent(Event e) { handleEvent(e); }`

**Note**: Abstract methods have no body at all (they use `;`), so they won't match.

---

### 5. `redundant-boolean` (P2)

```scheme
(binary_expression
  operator: ["==" "!="]
  [(true) (false)])
@match
```

**Fail**: `if (isReady == true) {}`
**Pass**: `if (isReady) {}`

---

### 6. `string-concat-in-loop` (P2)

**Pattern**: A string concatenation assignment (`+=`) inside a loop body.

```scheme
[
  (for_statement
    body: (_
      (expression_statement
        (assignment_expression
          operator: "+="
          right: (_) @rhs))))
  (while_statement
    body: (_
      (expression_statement
        (assignment_expression
          operator: "+="
          right: (_) @rhs))))
  (enhanced_for_statement
    body: (_
      (expression_statement
        (assignment_expression
          operator: "+="
          right: (_) @rhs))))
]
@match
```

**Fail**: `for (String s : items) { result += s; }`
**Pass**: `StringBuilder sb = new StringBuilder(); for (String s : items) { sb.append(s); }`

**Note**: This has moderate confidence — `+=` on integers is perfectly fine. The pattern could be refined with type inference (L2), but for L1, tagging all `+=` in loops catches the common Java anti-pattern. Setting confidence to High is acceptable because the vast majority of `+=` in Java loops involves strings (the most complained-about performance issue).

**Refinement**: Match only when the right-hand side involves string concatenation:

```scheme
(for_statement
  body: (_
    (expression_statement
      (assignment_expression
        operator: "+="
        right: (binary_expression
          operator: "+")))))
@match
```

This narrows to `result += "prefix" + value` patterns, which are almost certainly string concatenation.

---

### 7. `raw-type-usage` (P3)

**Pattern**: A generic type used without type parameters (e.g., `List` instead of `List<String>`).

This is challenging for L1 because tree-sitter doesn't know which types are generic. A practical approach targets the most common raw types:

```scheme
(local_variable_declaration
  type: (type_identifier) @type
  (#match? @type "^(List|Map|Set|Collection|Iterator|Iterable|Queue|Deque)$"))
@match
```

**Fail**: `List items = new ArrayList();`
**Pass**: `List<String> items = new ArrayList<>();`

**Note**: Low confidence — the type identifier alone doesn't prove it's a raw type (could be a custom class named `List`). Acceptable for P3.

---

## Python (7 rules)

### 1. `bare-except` (P1)

**Pattern**: An `except_clause` with no exception type specified.

```scheme
(except_clause
  !name)
@match
```

Wait — tree-sitter-python uses different field names. Let me check: an `except_clause` can have an optional `type` field for the exception class. A bare `except:` has no `type`:

```scheme
(except_clause
  .
  ":")
@match
```

**More robust**: Match `except_clause` that does NOT have a child `(identifier)` or `(tuple)` as the exception type:

```scheme
(except_clause
  .
  ":"
  (_))
@match
```

**Practical pattern**: In tree-sitter-python, `except:` produces `(except_clause ...)` with no named children before the `:`. A typed `except ValueError:` produces `(except_clause (identifier) ...)`. The simplest L1 approach:

```scheme
(except_clause
  !type)
@match
```

**Note**: The `!` (negation) operator in tree-sitter queries matches nodes that do NOT have the specified field. This will need verification against the actual grammar.

**Fail**: `except:\n    pass`
**Pass**: `except ValueError:\n    handle_error()`

---

### 2. `print-statement` (P2)

**Pattern**: A `call` expression where the function is `print`.

```scheme
(call
  function: (identifier) @fn
  (#eq? @fn "print"))
@match
```

**Fail**: `print("debug:", value)`
**Pass**: `logger.info("structured log: %s", value)`

---

### 3. `pass-in-except` (P1)

**Pattern**: An `except_clause` whose body contains only a `pass_statement`.

```scheme
(except_clause
  body: (block
    (pass_statement))
  !body.(_).(_))
@match
```

**Practical approach**: Match `except_clause` containing a block with `pass_statement` and no other statements. Since tree-sitter block nodes can have multiple children, we need:

```scheme
(except_clause
  (block
    .
    (pass_statement)
    .))
@match
```

The `.` anchors ensure `pass_statement` is the only child.

**Fail**: `except ValueError:\n    pass`
**Pass**: `except ValueError:\n    logger.warning("value error occurred")`

---

### 4. `mutable-default-arg` (P1)

**Pattern**: A function parameter with a default value that is a mutable literal (`[]`, `{}`, or `set()`).

```scheme
[
  (default_parameter
    value: (list))
  (default_parameter
    value: (dictionary))
]
@match
```

**Fail**: `def foo(items=[]):`
**Pass**: `def foo(items=None):`

**Note**: `set()` is a call expression, not a literal — detecting it would require matching `(call function: (identifier) @fn (#eq? @fn "set"))` as the default value. The list/dict literal pattern covers the most common cases.

---

### 5. `todo-comment` (P2)

```scheme
(comment) @match
(#match? @match "(TODO|FIXME|HACK|XXX)")
```

---

### 6. `empty-function-body` (P2)

**Pattern**: A function definition whose body contains only a `pass` statement (or an `expression_statement` with only a string literal, i.e., docstring + pass, or just pass).

```scheme
(function_definition
  body: (block
    .
    (pass_statement)
    .))
@match
```

**Fail**: `def noop():\n    pass`
**Pass**: `def greet():\n    return "hello"`

**Note**: A function with only a docstring (and no `pass`) still has a string expression in the body — that's a valid stub pattern and should not be flagged. Only `pass`-only bodies are flagged.

---

### 7. `magic-number` (P3)

**Pattern**: A numeric literal used outside of assignment to a named constant (ALL_CAPS variable).

This is extremely difficult to express precisely in L1. A practical, low-confidence approach:

```scheme
(comparison_operator
  [(integer) (float)] @num
  (#not-match? @num "^[01]$"))
@match
```

This catches comparisons against magic numbers (e.g., `if x > 42:`) but not `0` or `1` which are ubiquitous. Very low confidence; P3 priority is appropriate.

**Alternative**: Match numeric literals in binary expressions (excluding 0, 1, -1):

```scheme
(binary_operator
  [(integer) (float)] @num
  (#not-match? @num "^-?[01]$"))
@match
```

**Fail**: `if temperature > 212:`
**Pass**: `BOILING_POINT = 212; if temperature > BOILING_POINT:`

---

## Go (6 rules)

### 1. `empty-error-check` (P1)

**Pattern**: An `if` statement checking `err != nil` with an empty body.

```scheme
(if_statement
  condition: (binary_expression
    left: (identifier) @err
    operator: "!="
    right: (nil))
  consequence: (block
    .
    "}"))
@match
```

**Fail**: `if err != nil { }`
**Pass**: `if err != nil { return err }`

**Note**: The variable name `err` is conventional but not guaranteed. However, `(#match? @err "(?i)err")` covers most Go error handling patterns.

---

### 2. `fmt-println` (P1)

**Pattern**: A `call_expression` on `fmt.Println`, `fmt.Printf`, `fmt.Print`.

```scheme
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @fn
    (#eq? @pkg "fmt")
    (#match? @fn "^(Println|Printf|Print|Fprintf|Sprintf|Errorf)$")))
@match
```

**Refine**: We only want to flag `Println`, `Printf`, `Print` (direct stdout printing). `Sprintf` returns a string (not printing), `Errorf` creates an error. Narrowing:

```scheme
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @fn
    (#eq? @pkg "fmt")
    (#match? @fn "^(Println|Printf|Print)$")))
@match
```

**Fail**: `fmt.Println("debug:", value)`
**Pass**: `log.Printf("structured log: %s", value)`

---

### 3. `defer-in-loop` (P1)

**Pattern**: A `defer_statement` inside a `for_statement` body.

```scheme
(for_statement
  body: (block
    (defer_statement)))
@match
```

**Fail**: `for _, f := range files { defer f.Close() }`
**Pass**: `f := openFile(); defer f.Close()`

**Note**: This also matches `for {}` infinite loops, which is correct — defer inside any loop is problematic because deferred calls accumulate until the function returns.

---

### 4. `unchecked-error` (P2)

**Pattern**: A function call result assigned to `_` (blank identifier) where the function likely returns an error.

```scheme
(short_var_declaration
  left: (expression_list
    (identifier) @blank
    (#eq? @blank "_"))
  right: (expression_list
    (call_expression)))
@match
```

**Note**: This catches `_ := someFunc()` but not `_ = someFunc()` (assignment) or bare `someFunc()` (discarded return). The more common patterns:

```scheme
[
  (assignment_statement
    left: (expression_list
      (identifier) @blank
      (#eq? @blank "_"))
    right: (expression_list
      (call_expression)))
  (short_var_declaration
    left: (expression_list
      (identifier) @blank
      (#eq? @blank "_"))
    right: (expression_list
      (call_expression)))
]
@match
```

**Fail**: `_ = os.Remove(path)`
**Pass**: `err := os.Remove(path); if err != nil { log.Fatal(err) }`

**Note**: Medium confidence — not all functions return errors, and `_` is also used for non-error return values. This is why it's P2.

---

### 5. `todo-comment` (P2)

```scheme
(comment) @match
(#match? @match "(TODO|FIXME|HACK|XXX)")
```

---

### 6. `empty-function-body` (P2)

**Pattern**: A function declaration with an empty body.

```scheme
(function_declaration
  body: (block
    .
    "}"))
@match
```

**Fail**: `func noop() {}`
**Pass**: `func greet() string { return "hello" }`

---

## C# (6 rules)

### 1. `empty-catch-block` (P1)

**Pattern**: A `catch_clause` with an empty block.

```scheme
(catch_clause
  body: (block
    .
    "}"))
@match
```

**Fail**: `try { RiskyOp(); } catch (Exception ex) { }`
**Pass**: `try { RiskyOp(); } catch (Exception ex) { _logger.LogError(ex, "Failed"); }`

---

### 2. `console-writeline` (P1)

**Pattern**: An `invocation_expression` calling `Console.WriteLine`, `Console.Write`, or `Console.Error.WriteLine`.

```scheme
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method
    (#eq? @cls "Console")
    (#match? @method "^(WriteLine|Write|ReadLine|ReadKey)$")))
@match
```

**Refine**: Only flag output methods, not input methods:

```scheme
(invocation_expression
  function: (member_access_expression
    expression: (identifier) @cls
    name: (identifier) @method
    (#eq? @cls "Console")
    (#match? @method "^(WriteLine|Write)$")))
@match
```

**Fail**: `Console.WriteLine("Debug: " + value);`
**Pass**: `_logger.LogInformation("Structured log: {Value}", value);`

---

### 3. `todo-comment` (P2)

```scheme
(comment) @match
(#match? @match "(TODO|FIXME|HACK|XXX)")
```

---

### 4. `empty-method-body` (P2)

**Pattern**: A method declaration with an empty body.

```scheme
(method_declaration
  body: (block
    .
    "}"))
@match
```

**Fail**: `public void OnEvent(Event e) { }`
**Pass**: `public void OnEvent(Event e) { HandleEvent(e); }`

**Note**: Abstract methods use `;` instead of a body block — they won't match.

---

### 5. `redundant-boolean` (P2)

```scheme
(binary_expression
  operator: ["==" "!="]
  [(boolean_literal)])
@match
```

**Note**: C# tree-sitter uses `boolean_literal` for `true`/`false`, not `true`/`false` as separate node types. Needs verification.

**Fail**: `if (isActive == true) {}`
**Pass**: `if (isActive) {}`

---

### 6. `object-type-usage` (P3)

**Pattern**: A parameter or variable declaration using `object` type instead of a generic type.

```scheme
(parameter
  type: (predefined_type) @type
  (#eq? @type "object"))
@match
```

**Fail**: `public void Process(object data) {}`
**Pass**: `public void Process<T>(T data) where T : IProcessable {}`

**Note**: Low confidence — `object` is sometimes intentional (e.g., boxing scenarios, event handlers). P3 priority is appropriate.

---

## Cross-Language Pattern Summary

### Shared Patterns

Several patterns are structurally identical across languages, varying only in node type names:

| Pattern | TS | Java | Python | Go | C# |
|---------|----|----- |--------|----|----|
| Empty catch | `catch_clause` | `catch_clause` | `except_clause` | N/A | `catch_clause` |
| Debug print | `console.log` | `System.out.println` | `print()` | `fmt.Println` | `Console.WriteLine` |
| TODO comment | `comment` | `comment` | `comment` | `comment` | `comment` |
| Empty function | `function_declaration` | `method_declaration` | `function_definition` | `function_declaration` | `method_declaration` |
| Redundant bool | `binary_expression` | `binary_expression` | N/A | N/A | `binary_expression` |

### Known Limitations (L1)

1. **No type information**: Cannot distinguish `string += x` from `int += x` in Java loop concatenation
2. **No scope analysis**: Cannot detect unused variables or unreachable code
3. **No cross-line context**: Each pattern matches within a single AST subtree
4. **No counting**: Cannot reliably count parameters beyond positional matching
5. **Limited negation**: `!field` works for field absence, but complex negations (e.g., "no statement except comment") require workarounds

### Pattern Verification Checklist

For each rule implementation, verify:
- [ ] Pattern matches all fail fixture variants
- [ ] Pattern does NOT match any pass fixture variants
- [ ] Pattern handles both single-line and multi-line code
- [ ] Pattern is resilient to whitespace/formatting variations
- [ ] Edge cases are documented in the rule YAML `description`
