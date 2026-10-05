//! Fail-closed validation for combinations of remote-server arguments.
//!
//! # Convergence with the shared validator (mecmcp#358, MEC-981)
//!
//! This module used to carry a full private copy of the common rules
//! (auth requirement/conflict, loopback bind policy, TLS pairing, numeric
//! host, and allowed-host/allowed-origin shape). mecmcp#495 promoted those
//! rules into `mecmcp_runtime::cli_validate`, so [`validate`] now delegates
//! to it via [`shared_validate`] instead of re-implementing them.
//!
//! What remains here is the subset `mecmcp_runtime::cli::Cli` cannot check
//! because the fields don't exist on the shared surface yet: absolute paths
//! for this server's sensitive files (`--state-file`, `--tokens-file`,
//! `--tls-cert`, `--tls-key`), and this server's own request-body and rate
//! limits. Promoting those needs either a shared CLI-surface change (new
//! flags every consumer would carry) or a compatibility break (the other five
//! consumers currently start with relative paths), so mecmcp#495 left them
//! out on purpose; see that module's doc comment.

use crate::cli::{Cli, Transport};
use std::path::{Path, PathBuf};

const MIN_BODY_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
const MAX_RATE_PER_MINUTE: u32 = 100_000;

/// A CLI combination with no safe unambiguous interpretation.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CliRefusal {
    /// One of the rules enforced by `mecmcp_runtime::cli_validate` for every
    /// consumer: auth requirement/conflict, loopback bind policy, TLS
    /// pairing, numeric host, and allowed-host/allowed-origin shape.
    #[error(transparent)]
    Shared(#[from] mecmcp_runtime::cli_validate::CliRefusal),
    /// Sensitive files are anchored to absolute operator paths.
    #[error("{flag} path must be absolute")]
    AbsolutePathRequired {
        /// Flag whose value was relative.
        flag: &'static str,
    },
    /// Bounded denial-of-service setting failed.
    #[error("--request-body-limit must be between {MIN_BODY_BYTES} and {MAX_BODY_BYTES} bytes")]
    BodyLimit,
    /// A rate setting failed.
    #[error("{flag} must be between 1 and {MAX_RATE_PER_MINUTE}")]
    RateLimit {
        /// Flag whose value was outside the bound.
        flag: &'static str,
    },
}

/// Validate all serve arguments before inventory, secrets, sockets, or TLS load.
pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    if let Some(path) = &cli.state_file {
        require_absolute(path, "--state-file")?;
    }

    shared_validate(cli)?;

    if cli.transport == Transport::Stdio {
        return Ok(());
    }

    // `shared_validate` above already refused an incomplete TLS pair and the
    // `--tokens-file`/`--allow-no-auth` conflict, so by this point `tls_cert`
    // and `tls_key` are either both set or both absent, and if `tokens_file`
    // is set then `allow_no_auth` is false -- exactly the states the
    // absolute-path checks below used to gate on explicitly.
    if let (Some(cert), Some(key)) = (cli.tls_cert.as_ref(), cli.tls_key.as_ref()) {
        require_absolute(cert, "--tls-cert")?;
        require_absolute(key, "--tls-key")?;
    }
    if let Some(path) = &cli.tokens_file {
        require_absolute(path, "--tokens-file")?;
    }

    if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&cli.request_body_limit) {
        return Err(CliRefusal::BodyLimit);
    }
    validate_rate(cli.ip_rate_per_minute, "--ip-rate-per-minute")?;
    validate_rate(cli.token_rate_per_minute, "--token-rate-per-minute")?;
    Ok(())
}

/// Builds the shared `mecmcp_runtime::cli::Cli` view of this server's
/// arguments and runs `mecmcp_runtime::cli_validate::validate` over it.
///
/// Only the fields that function reads (`transport`, `host`, `tls_cert`,
/// `tls_key`, `tokens_file`, `allow_no_auth`, `allow_insecure_bind`,
/// `allowed_host`, `allowed_origin`) carry this server's real values. The
/// rest -- the management subcommand, device mapping, audit sinks, OTel, and
/// SSDF evidence flags -- are irrelevant to validation and filled with inert
/// placeholders; this server has its own subcommands and audit wiring that
/// the shared type knows nothing about.
fn shared_validate(cli: &Cli) -> Result<(), CliRefusal> {
    let shared = mecmcp_runtime::cli::Cli {
        command: None,
        device_mapping: PathBuf::new(),
        transport: cli.transport,
        host: cli.host.clone(),
        port: cli.port,
        tokens_file: cli.tokens_file.clone(),
        tls_cert: cli.tls_cert.clone(),
        tls_key: cli.tls_key.clone(),
        allow_no_auth: cli.allow_no_auth,
        allow_insecure_bind: cli.allow_insecure_bind,
        allowed_host: cli.allowed_host.clone(),
        allowed_origin: cli.allowed_origin.clone(),
        audit_format: String::new(),
        audit_log_file: None,
        audit_journald: false,
        otel_endpoint: None,
        otel_service_name: String::new(),
        evidence: mecmcp_runtime::cli::EvidenceArgs::default(),
        audit_redact: String::new(),
        audit_hmac_key_file: None,
        approval_digest_key_file: None,
    };
    mecmcp_runtime::cli_validate::validate(&shared)?;
    Ok(())
}

fn require_absolute(path: &Path, flag: &'static str) -> Result<(), CliRefusal> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(CliRefusal::AbsolutePathRequired { flag })
    }
}

fn validate_rate(value: u32, flag: &'static str) -> Result<(), CliRefusal> {
    if (1..=MAX_RATE_PER_MINUTE).contains(&value) {
        Ok(())
    } else {
        Err(CliRefusal::RateLimit { flag })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use mecmcp_runtime::cli_validate::CliRefusal as SharedRefusal;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("rust-panosmcp").chain(args.iter().copied()))
    }

    #[test]
    fn stdio_remains_local_and_valid() {
        assert!(validate(&parse(&[])).is_ok());
    }

    #[test]
    fn http_requires_exactly_one_auth_mode() {
        assert_eq!(
            validate(&parse(&["-t", "streamable-http"])),
            Err(CliRefusal::Shared(SharedRefusal::AuthRequired))
        );
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--allow-no-auth"
            ])),
            Err(CliRefusal::Shared(SharedRefusal::AuthConflict))
        );
        assert!(validate(&parse(&["-t", "streamable-http", "--allow-no-auth"])).is_ok());
    }

    #[test]
    fn host_must_be_numeric_and_no_auth_must_be_loopback() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--allow-no-auth",
                "-H",
                "localhost"
            ])),
            Err(CliRefusal::Shared(SharedRefusal::NonNumericHost { .. }))
        ));
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--allow-no-auth",
                "-H",
                "0.0.0.0"
            ])),
            Err(CliRefusal::Shared(SharedRefusal::NoAuthOffLoopback { .. }))
        ));
    }

    #[test]
    fn off_loopback_requires_transport_host_and_origin_controls() {
        let base = [
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/tokens.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
        ];
        assert!(matches!(
            validate(&parse(&base)),
            Err(CliRefusal::Shared(SharedRefusal::AllowedHostRequired { .. }))
        ));
        let mut with_host = base.to_vec();
        with_host.extend(["--allowed-host", "mcp.example.test"]);
        assert!(matches!(
            validate(&parse(&with_host)),
            Err(CliRefusal::Shared(SharedRefusal::AllowedOriginRequired { .. }))
        ));
        with_host.extend(["--allowed-origin", "https://client.example.test"]);
        assert!(validate(&parse(&with_host)).is_ok());
    }

    #[test]
    fn tls_pair_absolute_paths_and_limits_are_strict() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--tls-cert",
                "/tmp/cert.pem"
            ])),
            Err(CliRefusal::Shared(SharedRefusal::TlsPairIncomplete { .. }))
        ));
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--request-body-limit",
                "1"
            ])),
            Err(CliRefusal::BodyLimit)
        );
    }

    #[test]
    fn malformed_host_and_origin_policy_is_refused() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--allowed-host",
                "https://wrong-shape"
            ])),
            Err(CliRefusal::Shared(SharedRefusal::InvalidAllowedHost { .. }))
        ));
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--allowed-origin",
                "ftp://client.example.test"
            ])),
            Err(CliRefusal::Shared(SharedRefusal::InvalidAllowedOrigin { .. }))
        ));
    }

    /// `--state-file` must be absolute even on stdio, where the shared
    /// validator never runs any check at all.
    #[test]
    fn state_file_must_be_absolute_even_on_stdio() {
        assert_eq!(
            validate(&parse(&["--state-file", "relative/state.json"])),
            Err(CliRefusal::AbsolutePathRequired {
                flag: "--state-file"
            })
        );
    }

    /// `--tokens-file`/`--tls-cert`/`--tls-key` absolute checks still apply
    /// after delegating to the shared validator, not just the rules it owns.
    #[test]
    fn tokens_and_tls_paths_must_be_absolute() {
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "tokens.json",
            ])),
            Err(CliRefusal::AbsolutePathRequired {
                flag: "--tokens-file"
            })
        );
        assert_eq!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "--tls-cert",
                "cert.pem",
                "--tls-key",
                "/tmp/key.pem",
            ])),
            Err(CliRefusal::AbsolutePathRequired { flag: "--tls-cert" })
        );
    }

    /// Verified by sabotage: if `shared_validate` were skipped, this
    /// off-loopback plaintext bind with no `--allow-insecure-bind` would fall
    /// through to the body/rate checks and pass.
    #[test]
    fn shared_rules_still_gate_before_the_server_specific_ones() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/tokens.json",
                "-H",
                "0.0.0.0",
            ])),
            Err(CliRefusal::Shared(SharedRefusal::InsecureBindRequired { .. }))
        ));
    }
}
