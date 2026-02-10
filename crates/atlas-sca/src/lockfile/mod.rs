//! 鎖檔解析模組 — 自動偵測並解析各生態系的依賴鎖檔。

pub mod npm;
pub mod cargo;
pub mod maven;
pub mod go;
pub mod python;
pub mod nuget;

use std::path::{Path, PathBuf};

use crate::{Dependency, ScaError};

// ---------------------------------------------------------------------------
// LockfileParser trait
// ---------------------------------------------------------------------------

/// 鎖檔解析器介面。每個生態系實作一個。
pub trait LockfileParser: Send + Sync {
    /// 解析鎖檔內容，回傳依賴清單。
    ///
    /// `path` 用於填入 `Dependency::lockfile_path`。
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError>;
}

// ---------------------------------------------------------------------------
// 鎖檔檔名 → 解析器對應
// ---------------------------------------------------------------------------

type ParserEntry = (&'static str, fn() -> Box<dyn LockfileParser>);

/// 已知的鎖檔檔名與其對應的解析器。
static LOCKFILE_PARSERS: &[ParserEntry] = &[
    ("package-lock.json", || Box::new(npm::NpmParser)),
    ("Cargo.lock", || Box::new(cargo::CargoParser)),
    ("pom.xml", || Box::new(maven::MavenParser)),
    ("gradle.lockfile", || Box::new(maven::GradleParser)),
    ("go.sum", || Box::new(go::GoParser)),
    ("requirements.txt", || Box::new(python::RequirementsParser)),
    ("Pipfile.lock", || Box::new(python::PipfileParser)),
    ("packages.lock.json", || Box::new(nuget::NugetParser)),
];

/// 在指定目錄中遞迴探索鎖檔，回傳 (路徑, 解析器) 對。
pub fn discover_lockfiles(dir: &Path) -> Vec<(PathBuf, Box<dyn LockfileParser>)> {
    let mut result = Vec::new();

    let walker = walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok);

    for entry in walker {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy();

        // 跳過 node_modules、vendor 等目錄中的鎖檔
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if path_str.contains("node_modules")
            || path_str.contains("/vendor/")
            || path_str.contains("/.git/")
        {
            continue;
        }

        for &(name, factory) in LOCKFILE_PARSERS {
            if file_name == name {
                result.push((path.to_path_buf(), factory()));
                break;
            }
        }
    }

    result
}
