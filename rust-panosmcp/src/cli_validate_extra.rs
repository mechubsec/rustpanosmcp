//! Validation for Pan-OS-specific resource limits not owned by mecmcp.

use crate::cli::Cli;
use std::path::Path;

const MIN_BODY_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
const MAX_RATE_PER_MINUTE: u32 = 100_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Refusal {
    #[error("{flag} path must be absolute")]
    AbsolutePath { flag: &'static str },
    #[error("--request-body-limit must be between {MIN_BODY_BYTES} and {MAX_BODY_BYTES} bytes")]
    BodyLimit,
    #[error("{flag} must be between 1 and {MAX_RATE_PER_MINUTE}")]
    RateLimit { flag: &'static str },
}

pub fn validate(cli: &Cli) -> Result<(), Refusal> {
    if let Some(path) = &cli.state_file {
        require_absolute(path, "--state-file")?;
    }
    if let Some(path) = &cli.tls_cert {
        require_absolute(path, "--tls-cert")?;
    }
    if let Some(path) = &cli.tls_key {
        require_absolute(path, "--tls-key")?;
    }
    if let Some(path) = &cli.tokens_file {
        require_absolute(path, "--tokens-file")?;
    }
    if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&cli.request_body_limit) {
        return Err(Refusal::BodyLimit);
    }
    validate_rate(cli.ip_rate_per_minute, "--ip-rate-per-minute")?;
    validate_rate(cli.token_rate_per_minute, "--token-rate-per-minute")?;
    Ok(())
}

fn require_absolute(path: &Path, flag: &'static str) -> Result<(), Refusal> {
    path.is_absolute()
        .then_some(())
        .ok_or(Refusal::AbsolutePath { flag })
}

fn validate_rate(value: u32, flag: &'static str) -> Result<(), Refusal> {
    (1..=MAX_RATE_PER_MINUTE)
        .contains(&value)
        .then_some(())
        .ok_or(Refusal::RateLimit { flag })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("rust-panosmcp").chain(args.iter().copied()))
    }

    #[test]
    fn resource_paths_must_be_absolute() {
        assert_eq!(
            validate(&parse(&["--state-file", "relative.json"])),
            Err(Refusal::AbsolutePath { flag: "--state-file" })
        );
    }

    #[test]
    fn limits_remain_bounded_locally() {
        assert_eq!(
            validate(&parse(&["--request-body-limit", "1"])),
            Err(Refusal::BodyLimit)
        );
        assert_eq!(
            validate(&parse(&["--ip-rate-per-minute", "0"])),
            Err(Refusal::RateLimit {
                flag: "--ip-rate-per-minute"
            })
        );
    }
}
