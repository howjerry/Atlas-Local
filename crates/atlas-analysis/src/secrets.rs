//! Secrets detection utilities for Atlas SAST.
//!
//! This module provides:
//!
//! - [`shannon_entropy`] -- computes Shannon entropy (bits per character) of a
//!   string, used to detect high-entropy secrets.
//! - [`is_high_entropy_secret`] -- determines if a string looks like a
//!   hardcoded secret based on length and entropy thresholds.
//! - [`is_suspicious_variable_name`] -- checks if a variable name matches
//!   patterns commonly used for secrets (api_key, password, token, etc.).
//!
//! These utilities are used by the scan engine to supplement L1 declarative
//! pattern matches for `category == Secrets` findings.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

/// Computes the Shannon entropy of `s` in bits per character.
///
/// Shannon entropy measures the randomness/information density of a string.
/// High-entropy strings (>4.5 bits/char for strings >20 chars) are likely
/// to be secrets, API keys, or cryptographic material.
///
/// Returns `0.0` for empty strings.
///
/// # Examples
///
/// ```
/// use atlas_analysis::secrets::shannon_entropy;
///
/// // Low entropy (repetitive)
/// assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
///
/// // Moderate entropy (English text)
/// let text_entropy = shannon_entropy("hello world");
/// assert!(text_entropy > 2.0 && text_entropy < 4.0);
/// ```
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq: HashMap<u8, usize> = HashMap::new();

    for &byte in s.as_bytes() {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let mut entropy = 0.0_f64;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Determines if a string looks like a high-entropy secret.
///
/// A string is considered a high-entropy secret candidate if:
/// - It is longer than 20 characters, AND
/// - Its Shannon entropy exceeds 4.5 bits per character.
///
/// These thresholds are tuned to catch API keys, tokens, and random secrets
/// while avoiding false positives on normal code identifiers and text.
#[must_use]
pub fn is_high_entropy_secret(s: &str) -> bool {
    const MIN_LENGTH: usize = 20;
    const MIN_ENTROPY: f64 = 4.5;

    s.len() > MIN_LENGTH && shannon_entropy(s) > MIN_ENTROPY
}

// ---------------------------------------------------------------------------
// Variable-name heuristics
// ---------------------------------------------------------------------------

/// Secret-indicating variable name patterns (lowercase).
///
/// If a variable name contains any of these substrings, and the assigned
/// value is a high-entropy string, the combination strongly suggests a
/// hardcoded secret.
const SUSPICIOUS_NAMES: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "auth",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "secret_key",
    "secretkey",
    "encryption_key",
    "signing_key",
    "jwt_secret",
    "db_password",
    "database_password",
    "connection_string",
];

/// Checks if a variable name matches patterns commonly used for secrets.
///
/// The check is case-insensitive and looks for substring matches against
/// a built-in list of suspicious names (e.g., `api_key`, `secret`, `token`,
/// `password`, `credential`, `auth`).
///
/// # Examples
///
/// ```
/// use atlas_analysis::secrets::is_suspicious_variable_name;
///
/// assert!(is_suspicious_variable_name("API_KEY"));
/// assert!(is_suspicious_variable_name("db_password"));
/// assert!(is_suspicious_variable_name("MY_SECRET_TOKEN"));
/// assert!(!is_suspicious_variable_name("username"));
/// assert!(!is_suspicious_variable_name("count"));
/// ```
#[must_use]
pub fn is_suspicious_variable_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    SUSPICIOUS_NAMES
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Checks if a string value combined with a variable name suggests a
/// hardcoded secret.
///
/// Returns `true` if:
/// - The variable name is suspicious (per [`is_suspicious_variable_name`]), AND
/// - The value is a high-entropy string (per [`is_high_entropy_secret`]).
///
/// This is the combined heuristic for contextual secret detection (T069).
#[must_use]
pub fn is_contextual_secret(variable_name: &str, value: &str) -> bool {
    is_suspicious_variable_name(variable_name) && is_high_entropy_secret(value)
}

// ---------------------------------------------------------------------------
// Known secret patterns (regex-like prefix checks)
// ---------------------------------------------------------------------------

/// Known secret prefixes that indicate a specific type of credential.
///
/// These are checked as simple string prefix matches, which is faster than
/// regex and sufficient for well-known token formats.
const KNOWN_PREFIXES: &[(&str, &str)] = &[
    ("AKIA", "AWS Access Key"),
    ("ASIA", "AWS Temporary Access Key"),
    ("ghp_", "GitHub Personal Access Token"),
    ("gho_", "GitHub OAuth Access Token"),
    ("ghs_", "GitHub Server-to-Server Token"),
    ("ghu_", "GitHub User-to-Server Token"),
    ("github_pat_", "GitHub Fine-Grained PAT"),
    ("xox", "Slack Token"),
    ("sk-", "OpenAI/Stripe Secret Key"),
    ("sk_live_", "Stripe Live Secret Key"),
    ("sk_test_", "Stripe Test Secret Key"),
    ("pk_live_", "Stripe Live Publishable Key"),
    ("pk_test_", "Stripe Test Publishable Key"),
    ("SG.", "SendGrid API Key"),
    ("eyJ", "JWT Token (Base64-encoded)"),
    ("AIza", "Google API Key"),
];

/// Checks if a string value matches a known secret prefix pattern.
///
/// Returns `Some(description)` if the value starts with a recognized
/// secret prefix, or `None` otherwise.
#[must_use]
pub fn matches_known_secret_prefix(value: &str) -> Option<&'static str> {
    for &(prefix, description) in KNOWN_PREFIXES {
        if value.starts_with(prefix) && value.len() > prefix.len() + 4 {
            return Some(description);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Shannon entropy tests -----------------------------------------------

    #[test]
    fn entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char() {
        assert_eq!(shannon_entropy("a"), 0.0);
    }

    #[test]
    fn entropy_repeated_char() {
        let entropy = shannon_entropy("aaaaaaaaaa");
        assert!(
            entropy < 0.01,
            "repeated chars should have near-zero entropy: {entropy}"
        );
    }

    #[test]
    fn entropy_two_chars_equal() {
        // "ab" repeated: 50/50 distribution = 1.0 bit
        let entropy = shannon_entropy("abababababababababab");
        assert!(
            (entropy - 1.0).abs() < 0.01,
            "equal two-char distribution should be ~1.0 bit: {entropy}"
        );
    }

    #[test]
    fn entropy_high_for_random_looking() {
        // A typical AWS key has high entropy
        let entropy = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(
            entropy > 3.5,
            "AWS key-like string should have high entropy: {entropy}"
        );
    }

    #[test]
    fn entropy_moderate_for_english() {
        let entropy = shannon_entropy("the quick brown fox jumps over the lazy dog");
        assert!(
            entropy > 2.0 && entropy < 4.5,
            "English text should have moderate entropy: {entropy}"
        );
    }

    #[test]
    fn entropy_very_high_for_hex() {
        // Random hex string
        let entropy = shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
        assert!(
            entropy > 3.5,
            "hex string should have high entropy: {entropy}"
        );
    }

    // -- High entropy secret tests -------------------------------------------

    #[test]
    fn high_entropy_random_secret() {
        // High-entropy random string (mixed case + digits + symbols)
        assert!(is_high_entropy_secret("xK9mN2pL5qR8sT1uV4wX7yZ0aB3cD6eF"));
    }

    #[test]
    fn high_entropy_short_string() {
        // Too short
        assert!(!is_high_entropy_secret("short"));
    }

    #[test]
    fn high_entropy_low_entropy_long_string() {
        // Long but low entropy (repeated)
        assert!(!is_high_entropy_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn high_entropy_normal_identifier() {
        // Normal code identifier
        assert!(!is_high_entropy_secret("myVariableName"));
    }

    // -- Variable name heuristics tests --------------------------------------

    #[test]
    fn suspicious_name_api_key() {
        assert!(is_suspicious_variable_name("API_KEY"));
        assert!(is_suspicious_variable_name("api_key"));
        assert!(is_suspicious_variable_name("MY_API_KEY"));
    }

    #[test]
    fn suspicious_name_password() {
        assert!(is_suspicious_variable_name("password"));
        assert!(is_suspicious_variable_name("DB_PASSWORD"));
        assert!(is_suspicious_variable_name("user_password"));
    }

    #[test]
    fn suspicious_name_token() {
        assert!(is_suspicious_variable_name("token"));
        assert!(is_suspicious_variable_name("AUTH_TOKEN"));
        assert!(is_suspicious_variable_name("access_token"));
    }

    #[test]
    fn suspicious_name_secret() {
        assert!(is_suspicious_variable_name("secret"));
        assert!(is_suspicious_variable_name("JWT_SECRET"));
        assert!(is_suspicious_variable_name("client_secret"));
    }

    #[test]
    fn suspicious_name_credential() {
        assert!(is_suspicious_variable_name("credential"));
        assert!(is_suspicious_variable_name("AWS_CREDENTIAL"));
    }

    #[test]
    fn suspicious_name_auth() {
        assert!(is_suspicious_variable_name("auth"));
        assert!(is_suspicious_variable_name("AUTH_HEADER"));
    }

    #[test]
    fn not_suspicious_normal_names() {
        assert!(!is_suspicious_variable_name("username"));
        assert!(!is_suspicious_variable_name("count"));
        assert!(!is_suspicious_variable_name("index"));
        assert!(!is_suspicious_variable_name("data"));
        assert!(!is_suspicious_variable_name("result"));
    }

    // -- Contextual secret tests ---------------------------------------------

    #[test]
    fn contextual_secret_api_key_with_value() {
        assert!(is_contextual_secret(
            "API_KEY",
            "sk-abc123def456ghi789jkl012mno345"
        ));
    }

    #[test]
    fn contextual_secret_wrong_name() {
        assert!(!is_contextual_secret(
            "username",
            "sk-abc123def456ghi789jkl012mno345"
        ));
    }

    #[test]
    fn contextual_secret_low_entropy_value() {
        assert!(!is_contextual_secret("API_KEY", "hello"));
    }

    // -- Known prefix tests --------------------------------------------------

    #[test]
    fn known_prefix_aws() {
        let result = matches_known_secret_prefix("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(result, Some("AWS Access Key"));
    }

    #[test]
    fn known_prefix_github_pat() {
        let result = matches_known_secret_prefix("ghp_1234567890abcdef1234567890abcdef12345678");
        assert_eq!(result, Some("GitHub Personal Access Token"));
    }

    #[test]
    fn known_prefix_github_oauth() {
        let result = matches_known_secret_prefix("gho_1234567890abcdef1234567890abcdef12345678");
        assert_eq!(result, Some("GitHub OAuth Access Token"));
    }

    #[test]
    fn known_prefix_jwt() {
        let result = matches_known_secret_prefix("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(result, Some("JWT Token (Base64-encoded)"));
    }

    #[test]
    fn known_prefix_google() {
        let result = matches_known_secret_prefix("AIzaSyABCDEFGHIJKLMN");
        assert_eq!(result, Some("Google API Key"));
    }

    #[test]
    fn known_prefix_no_match() {
        let result = matches_known_secret_prefix("normal_string");
        assert_eq!(result, None);
    }

    #[test]
    fn known_prefix_too_short() {
        // Prefix matches but value is too short to be a real key
        let result = matches_known_secret_prefix("AKIA");
        assert_eq!(result, None);
    }

    #[test]
    fn known_prefix_stripe_live() {
        let result = matches_known_secret_prefix("sk_live_1234567890abcdef");
        assert_eq!(result, Some("Stripe Live Secret Key"));
    }

    #[test]
    fn known_prefix_slack() {
        // Build test value dynamically to avoid triggering GitHub push protection
        let slack_token = format!("xox{}", "b-0000000000-0000000000-placeholder1234");
        let result = matches_known_secret_prefix(&slack_token);
        assert_eq!(result, Some("Slack Token"));
    }
}
