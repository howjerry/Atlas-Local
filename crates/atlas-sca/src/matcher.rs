//! 版本匹配引擎 — 根據生態系比較安裝版本與受影響範圍。

use crate::Ecosystem;

/// 檢查安裝版本是否落在受影響的版本範圍內。
///
/// 根據生態系使用不同的比較策略：
/// - npm/Cargo/NuGet: semver crate 的 `VersionReq::matches`
/// - Go: semver + v prefix 處理
/// - Maven: 自訂比較器
/// - PyPI: 自訂比較器
pub fn version_matches(installed: &str, affected_range: &str, ecosystem: Ecosystem) -> bool {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::Cargo | Ecosystem::NuGet => {
            semver_matches(installed, affected_range)
        }
        Ecosystem::Go => {
            // Go 版本可能有 v prefix
            let clean = installed.strip_prefix('v').unwrap_or(installed);
            semver_matches(clean, affected_range)
        }
        Ecosystem::Maven => maven_matches(installed, affected_range),
        Ecosystem::PyPI => pypi_matches(installed, affected_range),
    }
}

/// 使用 semver crate 進行版本範圍比較。
fn semver_matches(installed: &str, range: &str) -> bool {
    let Ok(version) = semver::Version::parse(installed) else {
        // 無法解析為 semver，嘗試簡化比較
        return simple_less_than(installed, range);
    };

    let Ok(req) = semver::VersionReq::parse(range) else {
        // 無法解析範圍，嘗試簡化比較
        return simple_less_than(installed, range);
    };

    req.matches(&version)
}

/// Maven 版本比較：按 major.minor.patch.qualifier 數值排序。
fn maven_matches(installed: &str, range: &str) -> bool {
    // 支援簡單的 "< version" 格式
    simple_less_than(installed, range)
}

/// PyPI (PEP 440) 版本比較。
fn pypi_matches(installed: &str, range: &str) -> bool {
    // 支援 "< version" 和 "<= version" 格式
    simple_less_than(installed, range)
}

/// 簡化的 "< version" 比較：適用於各種版本格式。
///
/// 支援格式：`"< 1.2.3"`, `"<= 1.2.3"`, `"<1.2.3"`
fn simple_less_than(installed: &str, range: &str) -> bool {
    let range = range.trim();

    // 處理 "<=" 格式
    if let Some(upper) = range.strip_prefix("<=") {
        let upper = upper.trim();
        return compare_version_strings(installed, upper) <= std::cmp::Ordering::Equal;
    }

    // 處理 "<" 格式
    if let Some(upper) = range.strip_prefix('<') {
        let upper = upper.trim();
        return compare_version_strings(installed, upper) == std::cmp::Ordering::Less;
    }

    // 不支援的格式，保守回傳 false
    false
}

/// 逐段比較版本字串。
fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();

    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let a_part = a_parts.get(i).unwrap_or(&"0");
        let b_part = b_parts.get(i).unwrap_or(&"0");

        // 嘗試數值比較
        match (a_part.parse::<u64>(), b_part.parse::<u64>()) {
            (Ok(a_num), Ok(b_num)) => {
                let cmp = a_num.cmp(&b_num);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
            // 有非數值部分，做字串比較
            _ => {
                let cmp = a_part.cmp(b_part);
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
            }
        }
    }

    std::cmp::Ordering::Equal
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- semver 匹配 (npm/Cargo/NuGet) --

    #[test]
    fn semver_within_range() {
        assert!(version_matches("4.17.20", "< 4.17.21", Ecosystem::Npm));
    }

    #[test]
    fn semver_outside_range() {
        assert!(!version_matches("4.17.21", "< 4.17.21", Ecosystem::Npm));
    }

    #[test]
    fn semver_at_boundary() {
        assert!(!version_matches("4.17.21", "< 4.17.21", Ecosystem::Cargo));
    }

    #[test]
    fn semver_lte_at_boundary() {
        assert!(version_matches("4.17.21", "<= 4.17.21", Ecosystem::Npm));
    }

    #[test]
    fn semver_lte_below() {
        assert!(version_matches("4.17.20", "<= 4.17.21", Ecosystem::Npm));
    }

    #[test]
    fn semver_complex_range() {
        assert!(version_matches("1.0.0", ">= 0.9, < 1.1.0", Ecosystem::Cargo));
    }

    #[test]
    fn semver_prerelease() {
        // semver 規範：prerelease 版本不匹配 `< 1.0.0` 的 VersionReq
        assert!(!version_matches("1.0.0-beta.1", "< 1.0.0", Ecosystem::Npm));
        // 但匹配 `< 1.0.0-rc.1`（同 major.minor.patch 的 prerelease 比較）
        assert!(version_matches("1.0.0-beta.1", "< 1.0.0-rc.1", Ecosystem::Npm));
    }

    // -- Go 版本匹配 --

    #[test]
    fn go_with_v_prefix() {
        assert!(version_matches("v0.14.0", "< 0.15.0", Ecosystem::Go));
    }

    #[test]
    fn go_without_prefix() {
        assert!(version_matches("0.14.0", "< 0.15.0", Ecosystem::Go));
    }

    // -- Maven 版本匹配 --

    #[test]
    fn maven_less_than() {
        assert!(version_matches("3.12.0", "< 3.13.0", Ecosystem::Maven));
    }

    #[test]
    fn maven_not_affected() {
        assert!(!version_matches("3.13.0", "< 3.13.0", Ecosystem::Maven));
    }

    // -- PyPI 版本匹配 --

    #[test]
    fn pypi_less_than() {
        assert!(version_matches("2.31.0", "< 2.32.0", Ecosystem::PyPI));
    }

    #[test]
    fn pypi_not_affected() {
        assert!(!version_matches("2.32.0", "< 2.32.0", Ecosystem::PyPI));
    }

    // -- compare_version_strings --

    #[test]
    fn compare_equal() {
        assert_eq!(
            compare_version_strings("1.2.3", "1.2.3"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn compare_less() {
        assert_eq!(
            compare_version_strings("1.2.3", "1.2.4"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn compare_greater() {
        assert_eq!(
            compare_version_strings("2.0.0", "1.9.9"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_different_lengths() {
        assert_eq!(
            compare_version_strings("1.2", "1.2.0"),
            std::cmp::Ordering::Equal
        );
    }
}
