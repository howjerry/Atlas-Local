## 1. 基礎設施：Language enum 與 adapter 框架

- [x] 1.1 在 `crates/atlas-lang/src/language.rs` 的 `Language` enum 新增 `Ruby`、`Php`、`Kotlin` 變體，更新 `from_extension()`、`extensions()`、`all()`、`Display` 等方法
- [x] 1.2 在 `crates/atlas-lang/Cargo.toml` 新增 `tree-sitter-ruby`、`tree-sitter-php`、`tree-sitter-kotlin-ng` 依賴
- [x] 1.3 建立 `crates/atlas-lang/src/ruby.rs`：實作 `RubyAdapter`（extensions: `rb`，comment prefix: `#`）
- [x] 1.4 建立 `crates/atlas-lang/src/php.rs`：實作 `PhpAdapter`（extensions: `php`，comment prefix: `//`，使用 `LANGUAGE_PHP`）
- [x] 1.5 建立 `crates/atlas-lang/src/kotlin.rs`：實作 `KotlinAdapter`（extensions: `kt`/`kts`，comment prefix: `//`）
- [x] 1.6 在 `crates/atlas-lang/src/lib.rs` 新增模組宣告與 re-exports，含 `register_*_adapter()` 函式
- [x] 1.7 在 `crates/atlas-core/src/engine.rs` 的 `ScanEngine::new()` 中註冊三個新 adapter
- [x] 1.8 確認編譯通過，新語言的檔案可被偵測與解析（66 tests passed）

## 2. Secrets 規則擴展

- [x] 2.1 建立 `rules/builtin/secrets/azure-storage-key.yaml` + fail/pass 測試夾具
- [x] 2.2 建立 `rules/builtin/secrets/gitlab-pat.yaml` + fail/pass 測試夾具
- [x] 2.3 建立 `rules/builtin/secrets/slack-webhook.yaml` + fail/pass 測試夾具
- [x] 2.4 建立 `rules/builtin/secrets/stripe-secret-key.yaml` + fail/pass 測試夾具
- [x] 2.5 建立 `rules/builtin/secrets/twilio-api-key.yaml` + fail/pass 測試夾具
- [x] 2.6 建立 `rules/builtin/secrets/sendgrid-api-key.yaml` + fail/pass 測試夾具
- [x] 2.7 建立 `rules/builtin/secrets/jwt-secret.yaml` + fail/pass 測試夾具
- [x] 2.8 建立 `rules/builtin/secrets/npm-token.yaml` + fail/pass 測試夾具
- [x] 2.9 建立 `rules/builtin/secrets/private-key-header.yaml` + fail/pass 測試夾具
- [x] 2.10 新增 `load_builtin_secrets_rules_from_disk()` 測試，斷言 15 條規則，全數通過

## 3. 現有語言：TypeScript 規則擴展（15 → 30）

- [x] 3.1 研究 TypeScript tree-sitter AST 節點結構（針對新增規則類型）
- [x] 3.2 建立 7 條新安全規則 YAML + fail/pass 測試夾具（insecure-random, weak-crypto, open-redirect, prototype-pollution, regex-dos, ssrf, hardcoded-secret）
- [x] 3.3 建立 8 條新品質規則 YAML + fail/pass 測試夾具（empty-conditional, nested-ternary, magic-number, excessive-parameters, string-concat-in-loop, redundant-boolean, empty-function-body, var-could-be-const）
- [x] 3.4 更新 `declarative.rs` 中 TypeScript 規則數量斷言（15 → 30），執行測試確認全數通過

## 4. 現有語言：Java 規則擴展（11 → 25）

- [x] 4.1 研究 Java tree-sitter AST 節點結構（針對新增規則類型）
- [x] 4.2 建立 6 條新安全規則 YAML + fail/pass 測試夾具（insecure-random, weak-crypto, open-redirect, ssrf, xxe, hardcoded-secret）
- [x] 4.3 建立 8 條新品質規則 YAML + fail/pass 測試夾具（empty-conditional, magic-number, nested-ternary, excessive-parameters, string-concat-in-loop, redundant-boolean, raw-type-usage, empty-method-body）
- [x] 4.4 更新 `declarative.rs` 中 Java 規則數量斷言（11 → 25），執行測試確認全數通過

## 5. 現有語言：Python 規則擴展（11 → 25）

- [x] 5.1 研究 Python tree-sitter AST 節點結構（針對新增規則類型）
- [x] 5.2 建立 6 條新安全規則 YAML + fail/pass 測試夾具（insecure-random, weak-crypto, open-redirect, ssrf, unsafe-deserialization, hardcoded-secret）
- [x] 5.3 建立 8 條新品質規則 YAML + fail/pass 測試夾具（empty-conditional, magic-number, nested-ternary, excessive-parameters, string-concat-in-loop, mutable-default-argument, empty-function-body, redundant-boolean）
- [x] 5.4 更新 `declarative.rs` 中 Python 規則數量斷言（11 → 25），執行測試確認全數通過

## 6. 現有語言：Go 規則擴展（9 → 20）

- [x] 6.1 研究 Go tree-sitter AST 節點結構（針對新增規則類型）
- [x] 6.2 建立 5 條新安全規則 YAML + fail/pass 測試夾具（insecure-random, weak-crypto, open-redirect, ssrf, hardcoded-secret）
- [x] 6.3 建立 6 條新品質規則 YAML + fail/pass 測試夾具（empty-conditional, magic-number, nested-ternary, excessive-parameters, string-concat-in-loop, redundant-boolean）
- [x] 6.4 更新 `declarative.rs` 中 Go 規則數量斷言（9 → 20），執行測試確認全數通過

## 7. 現有語言：C# 規則擴展（11 → 20）

- [x] 7.1 研究 C# tree-sitter AST 節點結構（針對新增規則類型）
- [x] 7.2 建立 3 條新安全規則 YAML + fail/pass 測試夾具（insecure-random, weak-crypto, open-redirect）
- [x] 7.3 建立 6 條新品質規則 YAML + fail/pass 測試夾具（empty-conditional, magic-number, nested-ternary, excessive-parameters, string-concat-in-loop, redundant-boolean）
- [x] 7.4 更新 `declarative.rs` 中 C# 規則數量斷言（11 → 20），執行測試確認全數通過

## 8. 新語言：Ruby 規則（25 條）

- [x] 8.1 使用 tree-sitter playground 研究 Ruby AST 節點結構，記錄關鍵節點名稱至 MEMORY.md
- [x] 8.2 建立 `rules/builtin/ruby/` 目錄結構
- [x] 8.3 建立 10 條安全規則 YAML + fail/pass 測試夾具（sql-injection, command-injection, xss, path-traversal, dynamic-code-execution, open-redirect, yaml-load, mass-assignment, weak-crypto, hardcoded-secret）
- [x] 8.4 建立 15 條品質規則 YAML + fail/pass 測試夾具（empty-rescue-block, puts-residual, todo-comment, empty-method-body, redundant-boolean, bare-rescue, global-variable, class-variable, magic-number, nested-ternary, excessive-parameters, string-concat-in-loop, empty-conditional, pp-debug, sleep-usage）
- [x] 8.5 在 `declarative.rs` 新增 `load_builtin_ruby_rules_from_disk()` 測試，斷言 25 條規則，執行測試確認全數通過

## 9. 新語言：PHP 規則（25 條）

- [x] 9.1 使用 tree-sitter playground 研究 PHP AST 節點結構，記錄關鍵節點名稱至 MEMORY.md
- [x] 9.2 建立 `rules/builtin/php/` 目錄結構
- [x] 9.3 建立 10 條安全規則 YAML + fail/pass 測試夾具（sql-injection, command-injection, xss, path-traversal, code-injection, unserialize, file-inclusion, weak-crypto, open-redirect, ssrf）
- [x] 9.4 建立 15 條品質規則 YAML + fail/pass 測試夾具（empty-catch-block, var-dump-residual, todo-comment, empty-function-body, loose-comparison, error-suppression, print-r-residual, magic-number, excessive-parameters, empty-conditional, redundant-boolean, global-statement, exit-usage, nested-ternary, bare-exception）
- [x] 9.5 在 `declarative.rs` 新增 `load_builtin_php_rules_from_disk()` 測試，斷言 25 條規則，執行測試確認全數通過

## 10. 新語言：Kotlin 規則（20 條）

- [x] 10.1 使用 tree-sitter playground 研究 Kotlin AST 節點結構，記錄關鍵節點名稱至 MEMORY.md
- [x] 10.2 建立 `rules/builtin/kotlin/` 目錄結構
- [x] 10.3 建立 8 條安全規則 YAML + fail/pass 測試夾具（sql-injection, command-injection, xss, path-traversal, insecure-random, weak-crypto, hardcoded-secret, insecure-deserialization）
- [x] 10.4 建立 12 條品質規則 YAML + fail/pass 測試夾具（empty-catch-block, println-residual, todo-comment, empty-function-body, redundant-boolean, unsafe-cast, magic-number, excessive-parameters, var-could-be-val, force-unwrap, empty-when-branch, string-concat-in-loop）
- [x] 10.5 在 `declarative.rs` 新增 `load_builtin_kotlin_rules_from_disk()` 測試，斷言 20 條規則，執行測試確認全數通過

## 11. 整合驗證

- [x] 11.1 執行 `cargo test` 全量測試，確認所有規則測試通過（205+ 規則零迴歸）
- [x] 11.2 執行 `cargo clippy` 確認無警告
- [x] 11.3 驗證各語言 OWASP Top 10 覆蓋率（每語言至少 5 個類別）
- [x] 11.4 驗證所有新安全規則含 `cwe_id` 與 `metadata.compliance`，所有新品質規則含 `metadata.quality_domain`
