//! Inline suppression — 解析原始碼中的 `atlas-ignore` 註解指令。
//!
//! 語法支援：
//! ```text
//! // atlas-ignore                          — 忽略同行所有規則
//! // atlas-ignore[rule-id]                 — 忽略同行指定規則
//! // atlas-ignore[rule-id] reason          — 附原因
//! // atlas-ignore-next-line                — 忽略下一行所有規則
//! // atlas-ignore-next-line[rule-id]       — 忽略下一行指定規則
//! # atlas-ignore                           — Python/Ruby/Shell 風格
//! /* atlas-ignore */                       — 區塊註解風格
//! ```
//!
//! 解析策略：逐行字串掃描，不依賴 tree-sitter 或 regex（語言無關、零額外依賴）。

use crate::Finding;

// ---------------------------------------------------------------------------
// InlineSuppression
// ---------------------------------------------------------------------------

/// 一條 inline suppression 指令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineSuppression {
    /// 被抑制的行號（1-indexed）。
    pub suppressed_line: u32,
    /// 指定的規則 ID，`None` 代表抑制所有規則。
    pub rule_id: Option<String>,
    /// 開發者提供的原因說明。
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// 關鍵字常數
// ---------------------------------------------------------------------------

const KEYWORD: &str = "atlas-ignore";
const NEXT_LINE_SUFFIX: &str = "-next-line";

// ---------------------------------------------------------------------------
// parse_inline_suppressions
// ---------------------------------------------------------------------------

/// 解析原始碼中的 `atlas-ignore` 指令，回傳所有 suppression。
///
/// 遍歷每一行，搜尋 `atlas-ignore` 關鍵字：
/// - `atlas-ignore` → 抑制同一行
/// - `atlas-ignore-next-line` → 抑制下一行
pub fn parse_inline_suppressions(source: &str) -> Vec<InlineSuppression> {
    let mut suppressions = Vec::new();

    for (line_idx, line) in source.lines().enumerate() {
        let line_number = (line_idx + 1) as u32; // 1-indexed

        // 在行中尋找 "atlas-ignore" 關鍵字
        let Some(keyword_pos) = line.find(KEYWORD) else {
            continue;
        };

        // 確認前面有註解前綴（//, #, 或 /*）
        let before = &line[..keyword_pos];
        if !has_comment_prefix(before) {
            continue;
        }

        // 取得關鍵字之後的部分
        let after_keyword = &line[keyword_pos + KEYWORD.len()..];

        // 判斷是否為 next-line 模式
        let (is_next_line, rest) = if let Some(stripped) = after_keyword.strip_prefix(NEXT_LINE_SUFFIX) {
            (true, stripped)
        } else {
            (false, after_keyword)
        };

        // 解析可選的 [rule-id]
        let (rule_id, rest) = if rest.starts_with('[') {
            if let Some(bracket_end) = rest.find(']') {
                let id = rest[1..bracket_end].trim();
                let id = if id.is_empty() {
                    None
                } else {
                    Some(id.to_string())
                };
                (id, &rest[bracket_end + 1..])
            } else {
                (None, rest)
            }
        } else {
            (None, rest)
        };

        // 解析可選的原因（去除尾端 */ 和空白）
        let reason_text = rest.trim().trim_end_matches("*/").trim();
        let reason = if reason_text.is_empty() {
            None
        } else {
            Some(reason_text.to_string())
        };

        let suppressed_line = if is_next_line {
            line_number + 1
        } else {
            line_number
        };

        suppressions.push(InlineSuppression {
            suppressed_line,
            rule_id,
            reason,
        });
    }

    suppressions
}

/// 檢查字串尾端是否包含註解前綴（`//`, `#`, `/*`）。
fn has_comment_prefix(before: &str) -> bool {
    let trimmed = before.trim_end();
    trimmed.ends_with("//") || trimmed.ends_with('#') || trimmed.ends_with("/*")
}

// ---------------------------------------------------------------------------
// apply_inline_suppressions
// ---------------------------------------------------------------------------

/// 過濾 findings，根據 suppressions 回傳 `(retained, suppressed)`。
///
/// 匹配邏輯：
/// - suppression 的 `suppressed_line` 必須與 finding 的 `start_line` 相符。
/// - suppression 的 `rule_id` 為 `None` 時抑制所有規則，否則僅抑制指定規則。
pub fn apply_inline_suppressions(
    findings: Vec<Finding>,
    suppressions: &[InlineSuppression],
) -> (Vec<Finding>, Vec<Finding>) {
    let mut retained = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        let is_suppressed = suppressions.iter().any(|s| {
            s.suppressed_line == finding.line_range.start_line
                && (s.rule_id.is_none()
                    || s.rule_id.as_deref() == Some(&*finding.rule_id))
        });

        if is_suppressed {
            suppressed.push(finding);
        } else {
            retained.push(finding);
        }
    }

    (retained, suppressed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FindingBuilder, LineRange};
    use atlas_rules::{AnalysisLevel, Category, Confidence, Severity};

    fn make_finding(rule_id: &str, start_line: u32) -> Finding {
        FindingBuilder::new()
            .rule_id(rule_id)
            .severity(Severity::High)
            .category(Category::Security)
            .file_path("test.ts")
            .line_range(LineRange::new(start_line, 1, start_line, 40).unwrap())
            .snippet("vulnerable code")
            .description("test finding")
            .remediation("fix it")
            .analysis_level(AnalysisLevel::L1)
            .confidence(Confidence::High)
            .build()
            .unwrap()
    }

    // -- parse tests ----------------------------------------------------------

    #[test]
    fn parse_same_line_all_rules() {
        let source = "let x = unsafeOp(); // atlas-ignore\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].suppressed_line, 1);
        assert!(result[0].rule_id.is_none());
        assert!(result[0].reason.is_none());
    }

    #[test]
    fn parse_same_line_specific_rule() {
        let source = "doStuff(input); // atlas-ignore[atlas/security/csharp/path-traversal]\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].suppressed_line, 1);
        assert_eq!(
            result[0].rule_id.as_deref(),
            Some("atlas/security/csharp/path-traversal")
        );
    }

    #[test]
    fn parse_same_line_with_reason() {
        let source =
            "let token = \"eyJ...\"; // atlas-ignore[atlas/secrets/jwt-token] test fixture\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].rule_id.as_deref(),
            Some("atlas/secrets/jwt-token")
        );
        assert_eq!(result[0].reason.as_deref(), Some("test fixture"));
    }

    #[test]
    fn parse_next_line_all_rules() {
        let source = "// atlas-ignore-next-line\nlet x = unsafeOp();\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].suppressed_line, 2);
        assert!(result[0].rule_id.is_none());
    }

    #[test]
    fn parse_next_line_specific_rule() {
        let source =
            "// atlas-ignore-next-line[atlas/security/typescript/sql-injection]\ndb.query(input);\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].suppressed_line, 2);
        assert_eq!(
            result[0].rule_id.as_deref(),
            Some("atlas/security/typescript/sql-injection")
        );
    }

    #[test]
    fn parse_hash_comment_prefix() {
        let source = "run(cmd) # atlas-ignore[atlas/security/python/command-injection] safe\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].rule_id.as_deref(),
            Some("atlas/security/python/command-injection")
        );
        assert_eq!(result[0].reason.as_deref(), Some("safe"));
    }

    #[test]
    fn parse_block_comment_prefix() {
        let source = "doStuff(); /* atlas-ignore */\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].suppressed_line, 1);
        assert!(result[0].rule_id.is_none());
    }

    #[test]
    fn parse_multiple_suppressions() {
        let source = "// atlas-ignore-next-line\nline2();\nline3(); // atlas-ignore\n";
        let result = parse_inline_suppressions(source);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].suppressed_line, 2); // next-line 指向 line 2
        assert_eq!(result[1].suppressed_line, 3); // same-line on line 3
    }

    #[test]
    fn parse_no_suppressions() {
        let source = "let x = 1;\nlet y = 2;\n// normal comment\n";
        let result = parse_inline_suppressions(source);
        assert!(result.is_empty());
    }

    // -- apply tests ----------------------------------------------------------

    #[test]
    fn apply_suppresses_all_rules_on_line() {
        let findings = vec![
            make_finding("rule-a", 5),
            make_finding("rule-b", 5),
            make_finding("rule-c", 10),
        ];
        let suppressions = vec![InlineSuppression {
            suppressed_line: 5,
            rule_id: None,
            reason: None,
        }];

        let (retained, suppressed) = apply_inline_suppressions(findings, &suppressions);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].rule_id, "rule-c");
        assert_eq!(suppressed.len(), 2);
    }

    #[test]
    fn apply_suppresses_specific_rule_only() {
        let findings = vec![make_finding("rule-a", 5), make_finding("rule-b", 5)];
        let suppressions = vec![InlineSuppression {
            suppressed_line: 5,
            rule_id: Some("rule-a".to_string()),
            reason: None,
        }];

        let (retained, suppressed) = apply_inline_suppressions(findings, &suppressions);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].rule_id, "rule-b");
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].rule_id, "rule-a");
    }

    #[test]
    fn apply_no_suppressions_retains_all() {
        let findings = vec![make_finding("rule-a", 5)];
        let suppressions: Vec<InlineSuppression> = vec![];

        let (retained, suppressed) = apply_inline_suppressions(findings, &suppressions);
        assert_eq!(retained.len(), 1);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn apply_suppression_on_wrong_line_no_effect() {
        let findings = vec![make_finding("rule-a", 5)];
        let suppressions = vec![InlineSuppression {
            suppressed_line: 10,
            rule_id: None,
            reason: None,
        }];

        let (retained, suppressed) = apply_inline_suppressions(findings, &suppressions);
        assert_eq!(retained.len(), 1);
        assert!(suppressed.is_empty());
    }

    // -- 整合測試 --------------------------------------------------------------

    #[test]
    fn end_to_end_parse_and_apply() {
        let source = r#"line1();
// atlas-ignore-next-line[rule-a]
line3();
line4(); // atlas-ignore
line5();
"#;
        let suppressions = parse_inline_suppressions(source);
        assert_eq!(suppressions.len(), 2);

        let findings = vec![
            make_finding("rule-a", 3), // 被 next-line suppression 抑制
            make_finding("rule-b", 3), // rule-b 不在 suppression 範圍
            make_finding("rule-a", 4), // 被 same-line suppression（全部規則）抑制
            make_finding("rule-c", 5), // 不受影響
        ];

        let (retained, suppressed) = apply_inline_suppressions(findings, &suppressions);
        assert_eq!(suppressed.len(), 2); // rule-a@3 + rule-a@4
        assert_eq!(retained.len(), 2); // rule-b@3 + rule-c@5
    }
}
