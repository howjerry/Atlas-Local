//! Secret value masking for Atlas SAST report output.
//!
//! When findings have `category == Secrets`, the snippet field may contain
//! sensitive values (API keys, passwords, tokens). This module provides
//! masking utilities to redact secret content before it appears in any
//! output format (Atlas JSON, SARIF, JSONL).
//!
//! # Masking format
//!
//! Values with 8+ characters are masked as: first 4 chars + `****` + last 4 chars.
//! Shorter values are fully replaced with `****`.

/// Mask a secret value, revealing only the first 4 and last 4 characters.
///
/// # Rules
///
/// - If the value has fewer than 8 characters, the entire value is replaced
///   with `"****"` (no partial reveal for very short secrets).
/// - If the value has 8 or more characters, the result is
///   `first_4 + "****" + last_4`.
///
/// # Examples
///
/// ```
/// use atlas_report::masking::mask_secret;
///
/// assert_eq!(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE");
/// assert_eq!(mask_secret("short"), "****");
/// assert_eq!(mask_secret("12345678"), "1234****5678");
/// ```
#[must_use]
pub fn mask_secret(value: &str) -> String {
    if value.len() < 8 {
        "****".to_string()
    } else {
        let first4: String = value.chars().take(4).collect();
        let last4: String = value.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
        format!("{first4}****{last4}")
    }
}

/// Masks secret values within a code snippet.
///
/// This applies [`mask_secret`] to each line of the snippet that appears
/// to contain a secret assignment or literal. Lines containing `=`, `:`,
/// or common secret patterns have their right-hand-side values masked.
///
/// For simplicity and safety, when applied to findings with `category == Secrets`,
/// the entire snippet is masked by replacing any contiguous non-whitespace
/// token longer than 7 characters (that isn't a common keyword) with its
/// masked form. This is a conservative approach that avoids complex parsing.
///
/// In practice, the primary use case is that the finding's snippet contains
/// the secret value, and we mask it in place.
#[must_use]
pub fn mask_snippet(snippet: &str) -> String {
    snippet
        .lines()
        .map(mask_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Masks potential secret tokens in a single line.
///
/// Tokens longer than 7 characters that look like secret values (contain
/// letters/digits, not purely keywords) are masked.
fn mask_line(line: &str) -> String {
    // Find the assignment operator position (= or :) to only mask RHS
    if let Some(pos) = find_assignment(line) {
        let (lhs, rhs) = line.split_at(pos + 1);
        let masked_rhs = mask_tokens(rhs);
        format!("{lhs}{masked_rhs}")
    } else {
        // No assignment found, mask any long token-like strings
        mask_tokens(line)
    }
}

/// Finds the position of the first `=` or `:` that appears to be an
/// assignment operator (not inside quotes at the start).
fn find_assignment(line: &str) -> Option<usize> {
    let trimmed = line.trim();
    // Look for = or : that separates key from value
    for (i, ch) in trimmed.char_indices() {
        if ch == '=' || ch == ':' {
            // Map back to original line position
            let offset = line.len() - line.trim_start().len();
            return Some(offset + i);
        }
    }
    None
}

/// Masks tokens in a string that look like secret values.
fn mask_tokens(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch == '"' || ch == '\'' {
            // Handle quoted strings
            let quote = ch;
            let mut token = String::new();
            token.push(ch);
            chars.next();

            while let Some(&c) = chars.peek() {
                token.push(c);
                chars.next();
                if c == quote {
                    break;
                }
            }

            // Mask the content inside quotes if long enough
            if token.len() > 2 {
                let inner = &token[1..token.len() - 1];
                if inner.len() >= 8 {
                    let masked = mask_secret(inner);
                    result.push(quote);
                    result.push_str(&masked);
                    result.push(quote);
                } else if inner.len() >= 4 {
                    result.push(quote);
                    result.push_str("****");
                    result.push(quote);
                } else {
                    result.push_str(&token);
                }
            } else {
                result.push_str(&token);
            }
        } else if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '/' || ch == '+' {
            // Collect a token
            let mut token = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '/' || c == '+' || c == '.' {
                    token.push(c);
                    chars.next();
                } else {
                    break;
                }
            }

            if token.len() >= 8 && !is_common_keyword(&token) {
                result.push_str(&mask_secret(&token));
            } else {
                result.push_str(&token);
            }
        } else {
            result.push(ch);
            chars.next();
        }
    }

    result
}

/// Returns true if the token is a common programming keyword that should
/// not be masked.
fn is_common_keyword(token: &str) -> bool {
    matches!(
        token.to_lowercase().as_str(),
        "const"
            | "let"
            | "var"
            | "function"
            | "return"
            | "export"
            | "import"
            | "require"
            | "process"
            | "password"
            | "api_key"
            | "apikey"
            | "api-key"
            | "secret"
            | "token"
            | "database"
            | "username"
            | "connection"
            | "endpoint"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- mask_secret tests ----------------------------------------------------

    #[test]
    fn mask_secret_long_value() {
        assert_eq!(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE");
    }

    #[test]
    fn mask_secret_exactly_8_chars() {
        assert_eq!(mask_secret("12345678"), "1234****5678");
    }

    #[test]
    fn mask_secret_short_value() {
        assert_eq!(mask_secret("short"), "****");
    }

    #[test]
    fn mask_secret_7_chars() {
        assert_eq!(mask_secret("1234567"), "****");
    }

    #[test]
    fn mask_secret_empty() {
        assert_eq!(mask_secret(""), "****");
    }

    #[test]
    fn mask_secret_single_char() {
        assert_eq!(mask_secret("x"), "****");
    }

    #[test]
    fn mask_secret_jwt_token() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let masked = mask_secret(jwt);
        assert!(masked.starts_with("eyJh"));
        assert!(masked.ends_with("VCJ9"));
        assert!(masked.contains("****"));
    }

    // -- mask_snippet tests ---------------------------------------------------

    #[test]
    fn mask_snippet_assignment() {
        let snippet = r#"const API_KEY = "sk-1234567890abcdef1234567890abcdef";"#;
        let masked = mask_snippet(snippet);
        assert!(!masked.contains("1234567890abcdef1234567890abcdef"));
        assert!(masked.contains("****"));
        assert!(masked.contains("API_KEY"));
    }

    #[test]
    fn mask_snippet_multiline() {
        let snippet = "const KEY = \"AKIAIOSFODNN7EXAMPLE\";\nconst SECRET = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\";";
        let masked = mask_snippet(snippet);
        assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!masked.contains("wJalrXUtnFEMI"));
        assert!(masked.contains("****"));
    }

    #[test]
    fn mask_snippet_preserves_short_tokens() {
        let snippet = "let x = 42;";
        let masked = mask_snippet(snippet);
        // Short tokens should not be masked
        assert_eq!(masked, snippet);
    }

    #[test]
    fn mask_snippet_env_file_format() {
        let snippet = "DATABASE_URL=postgresql://user:password123456@localhost:5432/db";
        let masked = mask_snippet(snippet);
        assert!(!masked.contains("password123456"));
        assert!(masked.contains("****"));
        assert!(masked.contains("DATABASE_URL"));
    }

    #[test]
    fn mask_snippet_preserves_keywords() {
        let snippet = "const password = \"mysecretpassword123\";";
        let masked = mask_snippet(snippet);
        // "const" and "password" should not be masked (they're keywords)
        assert!(masked.contains("const"));
        assert!(masked.contains("password"));
        // But the value should be masked
        assert!(!masked.contains("mysecretpassword123"));
    }
}
