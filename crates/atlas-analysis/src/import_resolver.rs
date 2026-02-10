//! 跨檔案 Import/Export 解析器。
//!
//! 從 tree-sitter AST 提取 import 聲明與 export 函數名稱，
//! 並解析相對模組路徑為專案內檔案路徑。

use std::collections::HashSet;
use std::path::Path;

use tree_sitter::{Node, Tree};

use crate::l3_interprocedural::ImportEntry;
use crate::l3_lang_config::L3LanguageConfig;

// ---------------------------------------------------------------------------
// Import/Export 提取
// ---------------------------------------------------------------------------

/// 從 AST 提取 import 條目（未解析模組路徑）。
pub fn extract_imports(
    tree: &Tree,
    source: &[u8],
    file_path: &str,
    config: &dyn L3LanguageConfig,
) -> Vec<ImportEntry> {
    let import_kinds = config.import_statement_kinds();
    if import_kinds.is_empty() {
        return Vec::new();
    }
    let mut entries = Vec::new();
    walk_for_kinds(tree.root_node(), import_kinds, &mut |node| {
        extract_import_from_node(node, source, file_path, &mut entries);
    });
    entries
}

/// 從 AST 提取 export 的函數名稱。
pub fn extract_exports(
    tree: &Tree,
    source: &[u8],
    config: &dyn L3LanguageConfig,
) -> Vec<String> {
    let export_kinds = config.export_kinds();
    if export_kinds.is_empty() {
        return Vec::new();
    }
    let mut names = Vec::new();
    walk_for_kinds(tree.root_node(), export_kinds, &mut |node| {
        extract_export_from_node(node, source, &mut names);
    });
    names
}

// ---------------------------------------------------------------------------
// 模組路徑解析
// ---------------------------------------------------------------------------

/// 解析模組路徑 — 將相對路徑轉為匹配的專案檔案路徑。
///
/// 嘗試多種副檔名（.ts, .tsx, .js, .jsx, .py）及 index 檔案。
/// `raw_module` 為原始模組指定符（如 `./userService` 或 `.services`）。
/// `importer_file` 為進行 import 的檔案路徑。
/// `known_files` 為專案中所有已知的檔案路徑集合。
pub fn resolve_module_path(
    raw_module: &str,
    importer_file: &str,
    known_files: &HashSet<String>,
) -> Option<String> {
    let importer_dir = Path::new(importer_file).parent()?;

    // 計算基本路徑
    let base = if raw_module.starts_with("./") || raw_module.starts_with("../") {
        // JavaScript/TypeScript 相對路徑
        let joined = importer_dir.join(raw_module);
        normalize_path(&joined)
    } else if raw_module.starts_with('.') {
        // Python relative import（如 ".services" 或 "..utils"）
        let stripped = raw_module.trim_start_matches('.');
        let dots = raw_module.len() - stripped.len();
        let mut dir = importer_dir.to_path_buf();
        // 每個額外的 dot 表示往上一層（第一個 dot = 當前目錄）
        for _ in 1..dots {
            dir = dir.parent().unwrap_or(Path::new("")).to_path_buf();
        }
        let module_path = stripped.replace('.', "/");
        if module_path.is_empty() {
            normalize_path(&dir)
        } else {
            normalize_path(&dir.join(&module_path))
        }
    } else {
        // 絕對模組名稱（Python dotted name 如 "services.user"）
        raw_module.replace('.', "/")
    };

    // 直接匹配（模組路徑已含副檔名）
    if known_files.contains(&base) {
        return Some(base);
    }

    // 嘗試常見副檔名
    for ext in &[".ts", ".tsx", ".js", ".jsx", ".py"] {
        let candidate = format!("{base}{ext}");
        if known_files.contains(&candidate) {
            return Some(candidate);
        }
    }

    // 嘗試 index 檔案（TypeScript/JavaScript）
    for suffix in &["/index.ts", "/index.js", "/index.tsx"] {
        let candidate = format!("{base}{suffix}");
        if known_files.contains(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// 解析 import 條目中的模組路徑，回傳更新後的 ImportEntry。
///
/// 將原始模組指定符轉為實際檔案路徑。
pub fn resolve_import_entries(
    entries: Vec<ImportEntry>,
    known_files: &HashSet<String>,
) -> Vec<ImportEntry> {
    entries
        .into_iter()
        .filter_map(|entry| {
            let resolved = resolve_module_path(
                &entry.source_module,
                &entry.file_path,
                known_files,
            )?;
            Some(ImportEntry {
                source_module: resolved,
                ..entry
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 語言分派
// ---------------------------------------------------------------------------

/// 根據節點類型分派到對應的 import 提取邏輯。
fn extract_import_from_node(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    entries: &mut Vec<ImportEntry>,
) {
    match node.kind() {
        "import_statement" => extract_ts_imports(node, source, file_path, entries),
        "import_from_statement" => extract_python_imports(node, source, file_path, entries),
        _ => {}
    }
}

/// 根據節點類型分派到對應的 export 提取邏輯。
fn extract_export_from_node(node: Node<'_>, source: &[u8], names: &mut Vec<String>) {
    match node.kind() {
        "export_statement" => extract_ts_exports(node, source, names),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// TypeScript import/export
// ---------------------------------------------------------------------------

/// TypeScript: `import { findUser } from './userService'`
fn extract_ts_imports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    entries: &mut Vec<ImportEntry>,
) {
    // 取得 source module 路徑
    let source_module = match get_ts_import_source(node, source) {
        Some(s) => s,
        None => return,
    };

    // 尋找 import_clause
    let import_clause = match find_child_by_kind(node, "import_clause") {
        Some(c) => c,
        None => return,
    };

    // named imports: import { a, b } from "..."
    if let Some(named_imports) = find_child_by_kind(import_clause, "named_imports") {
        let mut cursor = named_imports.walk();
        for child in named_imports.children(&mut cursor) {
            if child.kind() == "import_specifier" {
                let exported = child
                    .child_by_field_name("name")
                    .and_then(|n| node_text(n, source));
                let local = child
                    .child_by_field_name("alias")
                    .and_then(|n| node_text(n, source))
                    .or(exported);

                if let (Some(local), Some(exported)) = (local, exported) {
                    entries.push(ImportEntry {
                        file_path: file_path.to_string(),
                        imported_name: local.to_string(),
                        source_module: source_module.clone(),
                        exported_name: exported.to_string(),
                    });
                }
            }
        }
    }

    // default import: import Foo from "..."
    let mut cursor = import_clause.walk();
    for child in import_clause.children(&mut cursor) {
        if child.kind() == "identifier" {
            if let Some(name) = node_text(child, source) {
                entries.push(ImportEntry {
                    file_path: file_path.to_string(),
                    imported_name: name.to_string(),
                    source_module: source_module.clone(),
                    exported_name: "default".to_string(),
                });
            }
        }
    }
}

/// 從 TypeScript import_statement 取得 source module 路徑（去引號）。
fn get_ts_import_source(node: Node<'_>, source: &[u8]) -> Option<String> {
    let source_node = node.child_by_field_name("source")?;
    let raw = node_text(source_node, source)?;
    Some(strip_quotes(raw).to_string())
}

/// TypeScript: `export function findUser() {}` or `export { findUser }`
fn extract_ts_exports(node: Node<'_>, source: &[u8], names: &mut Vec<String>) {
    // export function foo() {} / export class Foo {}
    if let Some(decl) = node.child_by_field_name("declaration") {
        if let Some(name_node) = decl.child_by_field_name("name") {
            if let Some(text) = node_text(name_node, source) {
                names.push(text.to_string());
            }
        }
    }

    // export { foo, bar }
    if let Some(export_clause) = find_child_by_kind(node, "export_clause") {
        let mut cursor = export_clause.walk();
        for child in export_clause.children(&mut cursor) {
            if child.kind() == "export_specifier" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Some(text) = node_text(name_node, source) {
                        names.push(text.to_string());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Python import
// ---------------------------------------------------------------------------

/// Python: `from .services import process_data, helper`
fn extract_python_imports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    entries: &mut Vec<ImportEntry>,
) {
    // 取得 module_name
    let module_node = match node.child_by_field_name("module_name") {
        Some(n) => n,
        None => return,
    };
    let module_text = match node_text(module_node, source) {
        Some(t) => t.to_string(),
        None => return,
    };

    // 使用 cursor 遍歷，收集所有 field_name == "name" 的子節點
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.field_name() == Some("name") {
                let child = cursor.node();
                // 處理 aliased_import: from x import a as b
                if child.kind() == "aliased_import" {
                    let exported = child
                        .child_by_field_name("name")
                        .and_then(|n| node_text(n, source));
                    let local = child
                        .child_by_field_name("alias")
                        .and_then(|n| node_text(n, source));
                    if let (Some(exported), Some(local)) = (exported, local) {
                        entries.push(ImportEntry {
                            file_path: file_path.to_string(),
                            imported_name: local.to_string(),
                            source_module: module_text.clone(),
                            exported_name: exported.to_string(),
                        });
                    }
                } else if let Some(text) = node_text(child, source) {
                    entries.push(ImportEntry {
                        file_path: file_path.to_string(),
                        imported_name: text.to_string(),
                        source_module: module_text.clone(),
                        exported_name: text.to_string(),
                    });
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 輔助函式
// ---------------------------------------------------------------------------

/// 遞迴走訪 AST，對符合指定 kind 的節點執行回呼。
fn walk_for_kinds<F>(node: Node<'_>, kinds: &[&str], callback: &mut F)
where
    F: FnMut(Node<'_>),
{
    if kinds.contains(&node.kind()) {
        callback(node);
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_kinds(child, kinds, callback);
    }
}

/// 從 AST node 提取文字。
fn node_text<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    std::str::from_utf8(&source[node.byte_range()]).ok()
}

/// 搜尋某個 kind 的子節點。
fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|c| c.kind() == kind)
}

/// 去除字串前後的引號（單引號或雙引號）。
fn strip_quotes(s: &str) -> &str {
    let s = s.strip_prefix('"').unwrap_or(s);
    let s = s.strip_suffix('"').unwrap_or(s);
    let s = s.strip_prefix('\'').unwrap_or(s);
    s.strip_suffix('\'').unwrap_or(s)
}

/// 正規化路徑 — 處理 `.` 和 `..` 並統一使用 `/` 分隔符。
fn normalize_path(path: &Path) -> String {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(s) => {
                components.push(s.to_string_lossy().to_string());
            }
            _ => {}
        }
    }
    components.join("/")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3_lang_config::{PythonL3Config, TypeScriptL3Config};

    fn parse_ts(source: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("set language");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    fn parse_python(source: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("set language");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    // -----------------------------------------------------------------------
    // TypeScript import 測試
    // -----------------------------------------------------------------------

    #[test]
    fn ts_named_import() {
        let source = r#"import { findUser, createUser } from './userService';"#;
        let tree = parse_ts(source);
        let config: &dyn L3LanguageConfig = &TypeScriptL3Config;
        let entries = extract_imports(&tree, source.as_bytes(), "src/controller.ts", config);

        assert_eq!(entries.len(), 2, "Should extract 2 named imports, got: {entries:?}");
        assert_eq!(entries[0].imported_name, "findUser");
        assert_eq!(entries[0].exported_name, "findUser");
        assert_eq!(entries[0].source_module, "./userService");
        assert_eq!(entries[1].imported_name, "createUser");
    }

    #[test]
    fn ts_aliased_import() {
        let source = r#"import { findUser as getUser } from './userService';"#;
        let tree = parse_ts(source);
        let config: &dyn L3LanguageConfig = &TypeScriptL3Config;
        let entries = extract_imports(&tree, source.as_bytes(), "src/controller.ts", config);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].imported_name, "getUser");
        assert_eq!(entries[0].exported_name, "findUser");
    }

    #[test]
    fn ts_default_import() {
        let source = r#"import UserService from './userService';"#;
        let tree = parse_ts(source);
        let config: &dyn L3LanguageConfig = &TypeScriptL3Config;
        let entries = extract_imports(&tree, source.as_bytes(), "src/controller.ts", config);

        assert_eq!(entries.len(), 1, "Should extract default import, got: {entries:?}");
        assert_eq!(entries[0].imported_name, "UserService");
        assert_eq!(entries[0].exported_name, "default");
    }

    // -----------------------------------------------------------------------
    // TypeScript export 測試
    // -----------------------------------------------------------------------

    #[test]
    fn ts_export_function() {
        let source = r#"export function findUser(name: string) { return name; }"#;
        let tree = parse_ts(source);
        let config: &dyn L3LanguageConfig = &TypeScriptL3Config;
        let exports = extract_exports(&tree, source.as_bytes(), config);

        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0], "findUser");
    }

    #[test]
    fn ts_export_clause() {
        let source = r#"
function findUser() {}
function createUser() {}
export { findUser, createUser };
"#;
        let tree = parse_ts(source);
        let config: &dyn L3LanguageConfig = &TypeScriptL3Config;
        let exports = extract_exports(&tree, source.as_bytes(), config);

        assert_eq!(exports.len(), 2, "Should extract 2 exports, got: {exports:?}");
        assert!(exports.contains(&"findUser".to_string()));
        assert!(exports.contains(&"createUser".to_string()));
    }

    // -----------------------------------------------------------------------
    // Python import 測試
    // -----------------------------------------------------------------------

    #[test]
    fn python_from_import() {
        let source = "from services import process_data, validate";
        let tree = parse_python(source);
        let config: &dyn L3LanguageConfig = &PythonL3Config;
        let entries = extract_imports(&tree, source.as_bytes(), "app/views.py", config);

        assert_eq!(entries.len(), 2, "Should extract 2 imports, got: {entries:?}");
        assert_eq!(entries[0].imported_name, "process_data");
        assert_eq!(entries[0].source_module, "services");
        assert_eq!(entries[1].imported_name, "validate");
    }

    #[test]
    fn python_relative_import() {
        let source = "from .services import process_data";
        let tree = parse_python(source);
        let config: &dyn L3LanguageConfig = &PythonL3Config;
        let entries = extract_imports(&tree, source.as_bytes(), "app/views.py", config);

        assert_eq!(entries.len(), 1, "Should extract 1 import, got: {entries:?}");
        assert_eq!(entries[0].imported_name, "process_data");
        assert_eq!(entries[0].source_module, ".services");
    }

    #[test]
    fn python_aliased_import() {
        let source = "from services import process_data as pd";
        let tree = parse_python(source);
        let config: &dyn L3LanguageConfig = &PythonL3Config;
        let entries = extract_imports(&tree, source.as_bytes(), "app/views.py", config);

        assert_eq!(entries.len(), 1, "Should extract 1 aliased import, got: {entries:?}");
        assert_eq!(entries[0].imported_name, "pd");
        assert_eq!(entries[0].exported_name, "process_data");
    }

    // -----------------------------------------------------------------------
    // 模組路徑解析測試
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_ts_relative_path() {
        let known: HashSet<String> = [
            "src/userService.ts".to_string(),
            "src/controller.ts".to_string(),
        ]
        .into();

        let resolved = resolve_module_path("./userService", "src/controller.ts", &known);
        assert_eq!(resolved, Some("src/userService.ts".to_string()));
    }

    #[test]
    fn resolve_ts_parent_directory() {
        let known: HashSet<String> = [
            "lib/utils.ts".to_string(),
            "src/handlers/api.ts".to_string(),
        ]
        .into();

        let resolved = resolve_module_path("../../lib/utils", "src/handlers/api.ts", &known);
        assert_eq!(resolved, Some("lib/utils.ts".to_string()));
    }

    #[test]
    fn resolve_python_relative_import() {
        let known: HashSet<String> = [
            "app/services.py".to_string(),
            "app/views.py".to_string(),
        ]
        .into();

        let resolved = resolve_module_path(".services", "app/views.py", &known);
        assert_eq!(resolved, Some("app/services.py".to_string()));
    }

    #[test]
    fn resolve_python_absolute_import() {
        let known: HashSet<String> = [
            "services/user.py".to_string(),
        ]
        .into();

        let resolved = resolve_module_path("services.user", "app/views.py", &known);
        assert_eq!(resolved, Some("services/user.py".to_string()));
    }

    #[test]
    fn resolve_unknown_module_returns_none() {
        let known: HashSet<String> = [
            "src/existing.ts".to_string(),
        ]
        .into();

        let resolved = resolve_module_path("./nonexistent", "src/app.ts", &known);
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_index_file() {
        let known: HashSet<String> = [
            "src/utils/index.ts".to_string(),
        ]
        .into();

        let resolved = resolve_module_path("./utils", "src/app.ts", &known);
        assert_eq!(resolved, Some("src/utils/index.ts".to_string()));
    }

    // -----------------------------------------------------------------------
    // resolve_import_entries 整合測試
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_import_entries_filters_unknown() {
        let entries = vec![
            ImportEntry {
                file_path: "src/controller.ts".to_string(),
                imported_name: "findUser".to_string(),
                source_module: "./userService".to_string(),
                exported_name: "findUser".to_string(),
            },
            ImportEntry {
                file_path: "src/controller.ts".to_string(),
                imported_name: "unknown".to_string(),
                source_module: "./nonexistent".to_string(),
                exported_name: "unknown".to_string(),
            },
        ];

        let known: HashSet<String> = [
            "src/userService.ts".to_string(),
        ]
        .into();

        let resolved = resolve_import_entries(entries, &known);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].source_module, "src/userService.ts");
        assert_eq!(resolved[0].imported_name, "findUser");
    }

    // -----------------------------------------------------------------------
    // 不支援跨檔案的語言回傳空
    // -----------------------------------------------------------------------

    #[test]
    fn java_no_imports() {
        let source = r#"
import java.util.List;

public class Foo {
    public void bar() {}
}
"#;
        let tree = {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_java::LANGUAGE.into())
                .expect("set language");
            parser.parse(source.as_bytes(), None).expect("parse")
        };
        let config = crate::l3_lang_config::get_l3_config(atlas_lang::Language::Java).unwrap();
        let entries = extract_imports(&tree, source.as_bytes(), "Foo.java", config);
        assert!(entries.is_empty(), "Java should return empty imports for V1");
    }
}
