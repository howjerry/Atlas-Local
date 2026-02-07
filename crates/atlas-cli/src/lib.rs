//! Atlas CLI -- command-line interface for the Atlas Local SAST tool.
//!
//! This crate provides the CLI entry point, argument parsing, exit code
//! definitions, and orchestration logic that ties together the core engine,
//! rule evaluation, policy gates, reporting, and caching subsystems.

use std::fmt;

// ---------------------------------------------------------------------------
// Exit Codes  (FR-028)
// ---------------------------------------------------------------------------

/// Atlas process exit codes per specification FR-028.
///
/// These exit codes allow CI/CD pipelines and shell scripts to distinguish
/// between different termination reasons without parsing output.
///
/// | Code | Meaning                                     |
/// |------|---------------------------------------------|
/// | 0    | Scan completed, all policy gates passed      |
/// | 1    | Scan completed, one or more gates failed     |
/// | 2    | Engine error (parse failure, internal error) |
/// | 3    | License validation failed                    |
/// | 4    | Configuration error                         |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExitCode {
    /// Scan completed, all policy gates passed.
    Pass = 0,
    /// Scan completed, policy gate failed.
    GateFail = 1,
    /// Engine error (parse failure, internal error).
    EngineError = 2,
    /// License validation failed.
    LicenseError = 3,
    /// Configuration error (missing config, invalid YAML).
    ConfigError = 4,
}

impl ExitCode {
    /// Returns the numeric exit code as a `u8`.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns all exit code variants.
    #[must_use]
    pub const fn all() -> &'static [ExitCode] {
        &[
            Self::Pass,
            Self::GateFail,
            Self::EngineError,
            Self::LicenseError,
            Self::ConfigError,
        ]
    }

    /// Returns a human-readable description of this exit code.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Pass => "scan completed, all policy gates passed",
            Self::GateFail => "scan completed, policy gate failed",
            Self::EngineError => "engine error (parse failure, internal error)",
            Self::LicenseError => "license validation failed",
            Self::ConfigError => "configuration error (missing config, invalid YAML)",
        }
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exit code {} ({})", self.as_u8(), self.description())
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code.as_u8())
    }
}

/// Terminate the process with the given [`ExitCode`].
///
/// This function logs the exit reason at the appropriate tracing level
/// (info for [`ExitCode::Pass`], error for everything else) and then
/// returns the corresponding [`std::process::ExitCode`] suitable for use
/// as a `main` return value.
///
/// # Example
///
/// ```rust,no_run
/// use atlas_cli::ExitCode;
///
/// fn main() -> std::process::ExitCode {
///     // ... run scan ...
///     atlas_cli::terminate(ExitCode::Pass)
/// }
/// ```
pub fn terminate(code: ExitCode) -> std::process::ExitCode {
    match code {
        ExitCode::Pass => {
            tracing::info!(%code, "atlas exiting");
        }
        _ => {
            tracing::error!(%code, "atlas exiting with error");
        }
    }
    code.into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_numeric_values() {
        assert_eq!(ExitCode::Pass.as_u8(), 0);
        assert_eq!(ExitCode::GateFail.as_u8(), 1);
        assert_eq!(ExitCode::EngineError.as_u8(), 2);
        assert_eq!(ExitCode::LicenseError.as_u8(), 3);
        assert_eq!(ExitCode::ConfigError.as_u8(), 4);
    }

    #[test]
    fn exit_code_display() {
        let display = ExitCode::Pass.to_string();
        assert!(display.contains("0"));
        assert!(display.contains("all policy gates passed"));

        let display = ExitCode::GateFail.to_string();
        assert!(display.contains("1"));
        assert!(display.contains("policy gate failed"));

        let display = ExitCode::EngineError.to_string();
        assert!(display.contains("2"));
        assert!(display.contains("engine error"));

        let display = ExitCode::LicenseError.to_string();
        assert!(display.contains("3"));
        assert!(display.contains("license validation failed"));

        let display = ExitCode::ConfigError.to_string();
        assert!(display.contains("4"));
        assert!(display.contains("configuration error"));
    }

    #[test]
    fn exit_code_into_process_exit_code() {
        // Verify the From conversion compiles and produces the expected type.
        let process_code: std::process::ExitCode = ExitCode::Pass.into();
        // std::process::ExitCode does not expose its numeric value for
        // comparison, so we just verify the conversion does not panic.
        let _ = process_code;
    }

    #[test]
    fn exit_code_all_variants() {
        let all = ExitCode::all();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], ExitCode::Pass);
        assert_eq!(all[1], ExitCode::GateFail);
        assert_eq!(all[2], ExitCode::EngineError);
        assert_eq!(all[3], ExitCode::LicenseError);
        assert_eq!(all[4], ExitCode::ConfigError);
    }

    #[test]
    fn exit_code_descriptions_non_empty() {
        for code in ExitCode::all() {
            assert!(!code.description().is_empty());
        }
    }

    #[test]
    fn terminate_returns_process_exit_code() {
        // Verify terminate() compiles and returns the right type.
        let result = terminate(ExitCode::Pass);
        let _ = result;

        let result = terminate(ExitCode::EngineError);
        let _ = result;
    }

    #[test]
    fn exit_code_equality() {
        assert_eq!(ExitCode::Pass, ExitCode::Pass);
        assert_ne!(ExitCode::Pass, ExitCode::GateFail);
    }

    #[test]
    fn exit_code_debug() {
        // Verify Debug is derived properly.
        let debug = format!("{:?}", ExitCode::GateFail);
        assert_eq!(debug, "GateFail");
    }
}
