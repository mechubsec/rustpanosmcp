//! Digest-only token-store command implementation with PAN-OS mutation grants.

use crate::cli::TokenAction;
use rust_panosmcp_auth::{
    KnownNames, MutationAction, MutationGrant, ScopeSet, TokenStoreFile, TokenStoreFileError,
};
use std::io::Write;

/// Token command failure.
#[derive(Debug, thiserror::Error)]
pub enum TokenCommandError {
    /// Store persistence or validation failed.
    #[error(transparent)]
    Store(#[from] TokenStoreFileError),
    /// Scope syntax was ambiguous.
    #[error("invalid {field} scope: {message}")]
    Scope {
        /// Scope field.
        field: &'static str,
        /// Safe diagnostic.
        message: String,
    },
    /// Output or signal failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A shared token-command path failed.
    ///
    /// Two things route through `mecmcp-runtime`: provenance parsing, so both
    /// servers agree on what a provider or actor type means, and the whole of
    /// `set-scopes`, so there is one opinion about what counts as a widening.
    /// `token add` stays local because it also carries mutation grants and
    /// expiry, which the shared `add` does not model.
    #[error(transparent)]
    Shared(#[from] mecmcp_runtime::token_cmd::TokenCommandError),
}

/// Execute one token management command.
pub fn run(action: TokenAction, known_devices: &[String]) -> Result<(), TokenCommandError> {
    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            mutation_roots,
            mutation_actions,
            expires_at_unix,
            expires_in_secs,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => {
            // `Some` keeps device-name validation strict: this server always knows its
            // own inventory, so a token naming an unknown device is a typo, not a
            // legitimate forward reference. Add is the only operation that creates
            // new scopes, so it's the only one that needs to validate device names.
            let known = KnownNames {
                devices: Some(known_devices),
                tools: rust_panosmcp_auth::KNOWN_TOOLS,
            };
            let devices = parse_scope(devices, "devices")?;
            let tools = parse_scope(tools, "tools")?;
            let mutation = parse_mutation_grant(mutation_roots, mutation_actions)?;
            let expires_at = resolve_expiry(expires_at_unix, expires_in_secs)?;
            let provenance = mecmcp_runtime::token_cmd::parse_provenance(
                provider,
                provider_tier,
                on_behalf_of,
                actor_type,
            )?;
            let secret = TokenStoreFile::add_with_options(
                &tokens_file,
                &name,
                devices,
                tools,
                expires_at,
                mutation,
                provenance.provider,
                provenance.provider_tier,
                provenance.on_behalf_of,
                provenance.actor_type,
                // This server's `token add` CLI does not yet expose an
                // --oidc-issuer/--oidc-subject flag (MEC-994 W1 scope), so no
                // token created here is pre-bound to an IdP identity.
                None,
                &known,
            )?;
            writeln!(std::io::stdout().lock(), "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
        }
        TokenAction::List { tokens_file } => {
            // List is read-only and doesn't modify scopes, so no inventory validation needed.
            let file = TokenStoreFile::load(&tokens_file)?;
            let mut output = std::io::stdout().lock();
            writeln!(
                output,
                "NAME\tDEVICES\tTOOLS\tMUTATION\tCREATED_UNIX\tEXPIRES_UNIX"
            )?;
            for entry in file.store().entries() {
                let mutation = entry.grant.as_ref().map_or_else(
                    || "-".to_owned(),
                    |grant| {
                        let actions = grant
                            .actions
                            .iter()
                            .map(|action| match action {
                                MutationAction::Set => "set",
                                MutationAction::Delete => "delete",
                                MutationAction::Move => "move",
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("{}:{}", actions, grant.allowed_xpath_roots.join("|"))
                    },
                );
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    entry.name,
                    entry.devices.summary(),
                    entry.tools.summary(),
                    mutation,
                    entry.created_at.timestamp(),
                    entry
                        .expires_at
                        .map_or_else(|| "-".to_owned(), |value| value.timestamp().to_string())
                )?;
            }
        }
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            // Revoke doesn't create new scopes; it only removes an entry.
            // Skip device validation so revocation succeeds even when the inventory
            // is inaccessible (e.g., permission denied). This is critical: the failure
            // mode of a revocation path should be "credential is gone" not "credential
            // still works because the command failed".
            let known = KnownNames {
                devices: None,
                tools: rust_panosmcp_auth::KNOWN_TOOLS,
            };
            let removed = TokenStoreFile::revoke(&tokens_file, &name, &known)?;
            if removed {
                eprintln!("revoked '{name}'");
                signal_reload(server_pid)?;
            } else {
                eprintln!("token '{name}' did not exist");
            }
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            // Rotate doesn't create new scopes; it only replaces the secret while
            // preserving existing scopes. Skip device validation so rotation succeeds
            // even when the inventory is inaccessible.
            let known = KnownNames {
                devices: None,
                tools: rust_panosmcp_auth::KNOWN_TOOLS,
            };
            let secret = TokenStoreFile::rotate(&tokens_file, &name, &known)?;
            writeln!(std::io::stdout().lock(), "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
        }
        TokenAction::SetScopes {
            tokens_file,
            name,
            devices,
            tools,
            mutation_roots,
            mutation_actions,
            yes,
            server_pid,
        } => {
            // Straight through to the shared implementation, which owns the
            // before/after print, the widening confirmation and the audit
            // record. Reimplementing any of that here would give this server a
            // second opinion about what counts as an escalation.
            let grant = parse_mutation_grant(mutation_roots, mutation_actions)?;
            mecmcp_runtime::token_cmd::run_with_grant::<MutationGrant>(
                mecmcp_runtime::cli::TokenAction::SetScopes {
                    tokens_file,
                    name,
                    devices,
                    tools,
                    yes,
                    server_pid,
                },
                known_devices,
                rust_panosmcp_auth::KNOWN_TOOLS,
                grant,
            )?;
        }
    }
    Ok(())
}

fn parse_mutation_grant(
    roots: Vec<String>,
    actions: Vec<String>,
) -> Result<Option<MutationGrant>, TokenCommandError> {
    if roots.is_empty() && actions.is_empty() {
        return Ok(None);
    }
    if roots.is_empty() || actions.is_empty() {
        return Err(TokenCommandError::Scope {
            field: "mutation",
            message: "--mutation-root and --mutation-actions must be supplied together".to_owned(),
        });
    }
    let actions = actions
        .into_iter()
        .map(|action| match action.as_str() {
            "set" => Ok(MutationAction::Set),
            "delete" => Ok(MutationAction::Delete),
            "move" => Ok(MutationAction::Move),
            _ => Err(TokenCommandError::Scope {
                field: "mutation_actions",
                message: "only 'set', 'delete', and 'move' are supported".to_owned(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(MutationGrant {
        allowed_xpath_roots: roots,
        actions,
    }))
}

fn resolve_expiry(
    absolute: Option<u64>,
    lifetime: Option<u64>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, TokenCommandError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TokenCommandError::Scope {
            field: "expiry",
            message: "system clock is before Unix epoch".to_owned(),
        })?
        .as_secs();
    let expiry_unix = match (absolute, lifetime) {
        (Some(value), None) => Some(value),
        (None, Some(value)) => Some(now.checked_add(value).ok_or(TokenCommandError::Scope {
            field: "expiry",
            message: "expiry overflows Unix time".to_owned(),
        })?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting expiry options"),
    };
    if expiry_unix.is_some_and(|value| value <= now) {
        return Err(TokenCommandError::Scope {
            field: "expiry",
            message: "token expiry must be in the future".to_owned(),
        });
    }
    Ok(expiry_unix.and_then(|ts| chrono::DateTime::from_timestamp(ts as i64, 0)))
}

fn parse_scope(values: Vec<String>, field: &'static str) -> Result<ScopeSet, TokenCommandError> {
    if values.is_empty() {
        return Err(TokenCommandError::Scope {
            field,
            message: "at least one exact name or '*' is required".to_owned(),
        });
    }
    if values.iter().any(|value| value == "*") {
        if values.len() == 1 {
            return Ok(ScopeSet::Wildcard);
        }
        return Err(TokenCommandError::Scope {
            field,
            message: "'*' cannot be mixed with exact names".to_owned(),
        });
    }
    Ok(ScopeSet::Allowlist(values))
}

#[cfg(unix)]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    let Some(raw) = pid else {
        return Ok(());
    };
    let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server PID must be positive",
        )
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP)
        .map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    if pid.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SIGHUP reload is available only on Unix",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_is_exclusive() {
        assert!(matches!(
            parse_scope(vec!["*".to_owned()], "tools"),
            Ok(ScopeSet::Wildcard)
        ));
        assert!(parse_scope(vec!["*".to_owned(), "list_devices".to_owned()], "tools").is_err());
        assert!(parse_scope(Vec::new(), "tools").is_err());
    }
}
