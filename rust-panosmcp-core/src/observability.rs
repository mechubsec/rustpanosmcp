//! Tracing and audit initialization via mecmcp-audit.

pub use mecmcp_audit::{
    Attribution, AuditConfig, AuditFileSink, AuditFormat, AuditRedaction, AuditScope, Principal,
    RedactError, init_tracing,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_with_defaults_succeeds() {
        let cfg = AuditConfig {
            format: AuditFormat::Text,
            audit_log_file: None,
            redaction: None,
            journald: false,
            otel: None,
        };
        assert!(init_tracing(&cfg).is_ok());
    }

    /// `init_tracing` must surface a bad audit-file path as `Err`, not swallow
    /// it. A wrapper here used to map the `Result` to `bool` with `.is_ok()`
    /// (`init_with_config`, since removed) — unused in this repo's own
    /// binary, but a live temptation for the next caller to start "audited"
    /// while actually writing nothing, which is exactly the MEC-22 fail-closed
    /// rule this repo is held to. Directory-at-the-target-path is a portable
    /// way to make `OpenOptions::create().append()` fail.
    #[test]
    fn init_tracing_propagates_audit_file_open_errors() {
        let directory = tempfile::tempdir().expect("temp dir");
        let unusable_path = directory.path().join("audit-as-directory");
        std::fs::create_dir(&unusable_path).expect("create directory in place of the audit file");

        let cfg = AuditConfig {
            format: AuditFormat::Json,
            audit_log_file: Some(unusable_path),
            redaction: None,
            journald: false,
            otel: None,
        };
        assert!(
            init_tracing(&cfg).is_err(),
            "init_tracing must return Err when the configured audit file cannot be opened"
        );
    }
}
