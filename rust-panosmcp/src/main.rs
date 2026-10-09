//! Process entrypoint for local stdio and bearer-protected remote MCP.

use clap::Parser;
use mecmcp_secret::naming::{ServerNaming, known};
use mecmcp_secret::validate::{CredentialFileRole, CredentialFileSpec, validate_credential_files};
use rmcp::ServiceExt;
use rust_panosmcp::{
    PanosMcpServer, RuntimeState,
    cli::{Cli, Command, StateAction, StateDisposition, Transport},
    cli_validate,
    http_transport::{self, HttpOptions},
    token_cmd,
};
use rust_panosmcp_core::inventory::Inventory;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Layout for this server. `known::PANOS` is the deployed name
/// (`rust-panosmcp`), so these paths stay the ones already on disk.
fn server_naming() -> ServerNaming {
    ServerNaming::derive(known::PANOS)
}

/// Scan for stale secret files and warn if any are found.
///
/// Checks both /etc/rust-panosmcp and /var/lib/rust-panosmcp for superseded
/// tokens, retired TLS keys, and backup files. Warns but does not fail — a
/// stale file should not block startup.
fn check_stale_secrets(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    use mecmcp_auth::find_stale_secrets;

    let naming = server_naming();

    // Live files in the config directory that should not be flagged as stale.
    //
    // `tokens.json` IS listed here even though /etc is the legacy location. It has
    // to be: find_stale_secrets classifies a superseded file by its live-name
    // prefix, so dropping "tokens.json" would stop `tokens.json.pre-17` and friends
    // being recognised — and it would NOT cause the bare legacy store to be
    // reported, because the helper only knows backup suffixes, retired keys, and
    // prefixed superseded files. A bare `tokens.json` matches none of those.
    //
    // The legacy store is therefore reported explicitly, below.
    let config_live_files = [
        "devices.json",
        "devices.json.example",
        "audit-hmac.key",
        "tokens.json",
    ];

    // Live files in the state directory that should not be flagged as stale.
    let state_live_files = [
        "tokens.json",
        "mutation-state.json",
        "audit.jsonl",
        "evidence-outbox.ndjson",
        "evidence-ledger.ndjson",
    ];

    // Check the config directory. A device-mapping path with no parent falls
    // back to the deployed config dir; nothing else is substituted.
    let config_dir = cli
        .device_mapping
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| naming.config_dir.clone());
    let config_stale = find_stale_secrets(&config_dir, &config_live_files);

    // Check the state directory the same way.
    let state_dir = cli
        .state_file
        .as_ref()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| naming.state_dir.clone());
    let state_stale = find_stale_secrets(&state_dir, &state_live_files);

    // Also check for TLS key if configured
    let mut tls_stale = Vec::new();
    if let Some(ref key_path) = cli.tls_key
        && let Some(tls_dir) = key_path.parent()
    {
        // Only flag keys in the same directory, not the key itself.
        // TLS keys live under /etc, so use the config live list.
        let key_file_name = key_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("server.key");
        let mut extended_live = config_live_files.to_vec();
        extended_live.push(key_file_name);
        tls_stale = find_stale_secrets(tls_dir, &extended_live);
    }

    // The legacy token store itself. find_stale_secrets cannot classify a bare
    // live-named file, so detect it by path. #125 moved the store to /var/lib;
    // a copy left in /etc is a duplicated bearer-token secret on disk, and /etc
    // is read-only to the service under ProtectSystem=strict so it is not the
    // file being maintained.
    // Only when it is NOT the store this process is actually using. A source or
    // Phase 2 deployment may legitimately run with
    // `--tokens-file` pointing at the legacy config-dir copy; warning there would
    // tell an operator to securely erase their live credentials, and following
    // the advice would leave the next start with no tokens at all. A warning that
    // can destroy a working deployment is worse than the duplicate it reports.
    // This is a warning only. A missing canonical store is not loaded from here.
    let legacy_tokens = naming.config_dir.join("tokens.json");
    let configured_is_legacy = cli
        .tokens_file
        .as_deref()
        .is_some_and(|p| p.as_os_str() == legacy_tokens.as_os_str());
    if legacy_tokens.is_file() && !configured_is_legacy {
        tracing::warn!(
            path = %legacy_tokens.display(),
            "legacy token store present and NOT the configured store; migrate deliberately \
             and securely erase this copy — it may hold revoked credentials"
        );
    }

    let total_stale = config_stale.len() + state_stale.len() + tls_stale.len();
    if total_stale > 0 {
        tracing::warn!(
            "found {} potentially stale secret file(s) - review and remove manually if unused:",
            total_stale
        );
        for secret in config_stale.iter().chain(&state_stale).chain(&tls_stale) {
            tracing::warn!("  {} ({:?})", secret.path.display(), secret.reason);
        }
        tracing::warn!(
            "stale tokens may still hold revoked credentials; \
             retired TLS keys can decrypt captured traffic"
        );
    }

    Ok(())
}

/// Secret files whose modes are checked together, before any of them is loaded.
///
/// A startup that checks one file and exits reports the next loose mode only
/// on the next restart. [`validate_startup_credentials`] asks `mecmcp-secret`
/// to report every offender in this list at once.
///
/// Custom CA bundles are not here. The inventory loader accepts them on its
/// own rules; this list is only secret files.
struct StartupCredentialFiles<'a> {
    /// File-backed PAN-OS API keys named by the inventory. Each is required.
    api_key_files: &'a [PathBuf],
    /// Bearer-token store this process will load. Required when set.
    ///
    /// This is the configured `--tokens-file` for Streamable HTTP, never a
    /// path substituted because the canonical store is missing. stdio does
    /// not load a token store, so it passes `None` even when the flag is set.
    tokens: Option<&'a Path>,
    /// Audit HMAC key. Required when set; the caller creates a missing key first.
    audit_hmac_key: Option<&'a Path>,
    /// Listener TLS private key. Required when this process will load it.
    tls_key: Option<&'a Path>,
}

/// Check every secret file in one pass.
///
/// # Errors
/// Returns the aggregate [`mecmcp_secret::CredentialValidationError`] when any
/// listed file is missing or fails its mode check. The error names every
/// offender.
fn validate_startup_credentials(
    files: &StartupCredentialFiles<'_>,
) -> Result<(), mecmcp_secret::CredentialValidationError> {
    let mut specs = Vec::with_capacity(files.api_key_files.len() + 3);
    for path in files.api_key_files {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "PAN-OS API key",
            required: true,
        });
    }
    if let Some(path) = files.tokens {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "bearer token store",
            required: true,
        });
    }
    if let Some(path) = files.audit_hmac_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit HMAC key",
            required: true,
        });
    }
    if let Some(path) = files.tls_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "TLS private key",
            required: true,
        });
    }

    validate_credential_files(&specs)
}

/// Pre-provision the audit HMAC key file at `path` if it is absent or empty,
/// mirroring `packaging/lxc/install.sh`'s own key-generation step so every
/// entry point -- LXC install, systemd start, or a container's first run --
/// converges on the same keyed-audit posture instead of only the LXC path
/// doing it (mecmcp#376 / MEC-978). `--audit-redact` still defaults to empty
/// (redaction stays opt-in, see docs/AUDIT.md), so this alone does not turn
/// redaction on; it just means the key is already there the moment an
/// operator flips `--audit-redact ...=hmac` on, instead of failing with
/// `HmacKeyUnreadable` on that first restart.
///
/// `-s` (not `-e`): a zero-byte key file is indistinguishable from "never
/// generated" and would make every HMAC output constant, so rewriting it
/// here is a repair, not data loss. A non-empty file is never rotated --
/// that would silently break verification of every audit record signed
/// under the old key.
fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key)
        .map_err(|e| format!("generating audit HMAC key: OS entropy source unavailable: {e}"))?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("creating audit HMAC key file {}: {e}", path.display()))?;
        use std::io::Write as _;
        file.write_all(hex_key.as_bytes())
            .map_err(|e| format!("writing audit HMAC key file {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .map_err(|e| format!("writing audit HMAC key file {}: {e}", path.display()))?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Some(key_path) = cli.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path)?;
    }

    let audit_format = rust_panosmcp_core::observability::AuditFormat::parse(&cli.audit_format);
    let redaction = if let Some(ref policy) = cli.audit_redact {
        Some(rust_panosmcp_core::observability::AuditRedaction::parse(
            policy,
            cli.audit_hmac_key_file.as_deref(),
        )?)
    } else {
        None
    };
    let audit_cfg = rust_panosmcp_core::observability::AuditConfig {
        format: audit_format,
        audit_log_file: cli.audit_log_file.clone(),
        redaction,
        journald: cli.audit_journald,
        otel: None,
    };
    let audit_sink = rust_panosmcp_core::observability::init_tracing(&audit_cfg)?;

    if let Some(command) = cli.command {
        match command {
            Command::Token { action } => {
                let known_devices = Inventory::device_names(&cli.device_mapping)?;
                token_cmd::run(action, &known_devices)?;
            }
            Command::State {
                action:
                    StateAction::Resolve {
                        state_file,
                        operation_id,
                        disposition,
                        confirmation,
                    },
            } => {
                let disposition = match disposition {
                    StateDisposition::Committed => {
                        rust_panosmcp_core::mutation::RecoveryDisposition::Committed
                    }
                    StateDisposition::Discarded => {
                        rust_panosmcp_core::mutation::RecoveryDisposition::Discarded
                    }
                };
                // The shared recovery function takes the size cap explicitly, so a
                // deployment that raised max_state_bytes can still open the file
                // this repairs.
                let output = rust_panosmcp_core::mutation::resolve_persisted_operation(
                    &state_file,
                    &operation_id,
                    disposition,
                    &confirmation,
                    rust_panosmcp_core::mutation::PublicOperationLimits::default(),
                )?;
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
        }
        return Ok(());
    }

    // Report the refusal with `Display`, not `Debug`.
    //
    // `main` returns `Box<dyn Error>`, and Rust's default reporter prints the
    // `Debug` form. A bare `?` therefore printed `Error: AllowedOriginRequired`
    // — the enum variant, not the flag the operator has to add, and a string
    // that appears nowhere in the documentation because no message was ever
    // written to say it. Boxing `e.to_string()` instead is no better: `String`
    // Debug-prints with quotes.
    //
    // Every `CliRefusal` already carries an `#[error(...)]` naming the flag.
    // Printing it here is what actually puts it on stderr. Validation runs
    // before the inventory, secrets, sockets and TLS are loaded, so there is
    // nothing to unwind; exiting 1 matches what returning `Err` from `main`
    // already did. See mecmcp#358.
    if let Err(refusal) = cli_validate::validate(&cli) {
        eprintln!("Error: {refusal}");
        std::process::exit(1);
    }

    // Lab mode removes two-person control, so say so where an operator will
    // actually see it. Reading it off flags typed weeks ago is not visibility.
    if cli.lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets are approved on creation with no second principal. \
             Records carry approval_waiver=lab-mode. Do not run this against production devices."
        );
    }
    // Emit the plane-owned device protection posture on the normal log target,
    // not "audit": the audit stream carries one record per tool call with a fixed
    // schema (request_id, caller, tool, action, result), and a startup banner has
    // none of those fields. An audit-target banner pollutes the stream with
    // something no consumer can interpret as an action record.
    if cli.allow_plane_owned_writes {
        tracing::warn!(
            "allow-plane-owned-writes enabled: commit_panos_candidate on devices owned by \
             management planes (Panorama, Strata Cloud Manager) will proceed with a warning \
             instead of refusal. Changes to plane-owned devices may be overwritten at the \
             next push. This flag is for break-glass scenarios only."
        );
    } else {
        tracing::info!(
            "plane-owned device protection active: commit_panos_candidate refuses operations \
             on devices whose config_authority is not local or unknown"
        );
    }

    // commit_candidate on an operation with no change_set_id came from
    // stage_config directly, never through create/approve/apply_change_set --
    // there is no second-principal approval by construction. Refused by
    // default, identically over stdio and HTTP; --allow-direct-commit is the
    // break-glass override.
    let direct_commit = mecmcp_audit::DirectCommitPolicy::new(cli.allow_direct_commit);
    direct_commit.log_startup("rust-panosmcp");
    if !cli.allow_direct_commit {
        tracing::info!(
            "direct-commit tools disabled: commit_panos_candidate refuses an operation with no \
             change_set_id on stdio and HTTP alike. Use --allow-direct-commit to enable it."
        );
    }

    // Only the files this process will load. stdio ignores `--tokens-file` and
    // does not open a listener key; checking those here would refuse a start
    // that never reads them. There is no fallback when the configured token
    // path is missing.
    let tokens = (cli.transport == Transport::StreamableHttp)
        .then_some(cli.tokens_file.as_deref())
        .flatten();
    let tls_key = (cli.transport == Transport::StreamableHttp)
        .then_some(cli.tls_key.as_deref())
        .flatten();
    let api_key_files = Inventory::api_key_file_paths(&cli.device_mapping)?;
    if let Err(error) = validate_startup_credentials(&StartupCredentialFiles {
        api_key_files: &api_key_files,
        tokens,
        audit_hmac_key: cli.audit_hmac_key_file.as_deref(),
        tls_key,
    }) {
        // `main`'s default reporter prints `Debug`. The useful text is the
        // aggregate `Display`, which names every loose file at once.
        eprintln!("Error: {error}");
        std::process::exit(1);
    }

    // Built before the runtime because the coordinator inside it takes the
    // recorder, and started eagerly so a misconfiguration stops the server here
    // rather than at the first change.
    let evidence = match cli.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let transport = std::sync::Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    cli.evidence.ca_file(),
                    provider,
                )?,
            );
            Some(mecmcp_audit::EvidenceService::start_with_transport(
                config, transport,
            )?)
        }
        Ok(None) => None,
        Err(error) => return Err(format!("SSDF evidence configuration: {error}").into()),
    };

    let runtime = RuntimeState::load_with_state(
        &cli.device_mapping,
        tokens,
        cli.state_file.as_deref(),
        cli.lab_mode,
        Some(cli.approval_timeout_secs),
        cli.allow_plane_owned_writes,
        cli.allow_direct_commit,
        evidence
            .as_ref()
            .map(mecmcp_audit::EvidenceService::recorder),
    )?;
    tracing::info!(
        inventory = %runtime.inventory_path().display(),
        devices = runtime.snapshot().service.list_devices(None).devices.len(),
        authenticated = runtime.snapshot().tokens.is_some(),
        "validated PAN-OS runtime"
    );

    // Scan for stale secret files in config and state directories.
    check_stale_secrets(&cli)?;

    spawn_reload_handler(runtime.clone(), audit_sink)?;

    // Bound rather than propagated with `?`, so the evidence flush below runs
    // whichever way serving ended. `EvidenceService::Drop` deliberately does not
    // spool -- a Drop performing network I/O turns teardown into an
    // unpredictable stall -- so returning the error directly would lose every
    // proposal and approval the recorder still held, on exactly the controlled
    // failure the trail exists to describe.
    let served: Result<(), Box<dyn std::error::Error>> = async {
        match cli.transport {
            Transport::Stdio => {
                let service = PanosMcpServer::from_runtime(runtime)
                    .serve((tokio::io::stdin(), tokio::io::stdout()))
                    .await?;
                service.waiting().await?;
            }
            Transport::StreamableHttp => {
                let ip: IpAddr = cli.host.parse()?;
                let address = SocketAddr::new(ip, cli.port);
                let listener_tls = match (cli.tls_cert.as_deref(), cli.tls_key.as_deref()) {
                    (Some(cert), Some(key)) => {
                        let provider =
                            std::sync::Arc::new(rustls::crypto::ring::default_provider());
                        Some(mecmcp_transport::tls::load(cert, key, provider)?)
                    }
                    (None, None) => None,
                    _ => unreachable!("CLI refusal matrix validated the TLS pair"),
                };
                let options = HttpOptions {
                    port: cli.port,
                    tls: listener_tls.is_some(),
                    allow_insecure_bind: cli.allow_insecure_bind,
                    allowed_hosts: cli.allowed_host,
                    allowed_origins: cli.allowed_origin,
                    ip_rate_per_minute: cli.ip_rate_per_minute,
                    token_rate_per_minute: cli.token_rate_per_minute,
                    request_body_limit: cli.request_body_limit,
                    max_inflight_requests: cli.max_inflight_requests,
                    max_inflight_requests_per_token: cli.max_inflight_requests_per_token,
                    max_inflight_requests_per_target: cli.max_inflight_requests_per_target,
                    max_sessions: cli.max_sessions,
                    max_sessions_per_token: cli.max_sessions_per_token,
                };
                http_transport::serve(runtime, address, options, cli.enable_metrics, listener_tls)
                    .await?;
            }
        }
        Ok(())
    }
    .await;

    // Deliver what is still spooled before leaving. The drain ships on an
    // interval, so without this every record since the last tick waits for the
    // next start, and a segment still open has never been spooled at all.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

#[cfg(unix)]
fn spawn_reload_handler(
    runtime: RuntimeState,
    audit_sink: Option<rust_panosmcp_core::observability::AuditFileSink>,
) -> Result<(), std::io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            // Reopen the audit file first: this is the lossless half of log
            // rotation (rename the file, signal the process). A failed
            // reopen must not block the inventory/token reload below -- it
            // is a rotation problem, not an audit-init failure, so it
            // warn-logs and keeps the previous sink rather than treating the
            // server as unaudited.
            if let Some(sink) = &audit_sink {
                match sink.reopen() {
                    Ok(()) => {
                        tracing::info!(path = %sink.path().display(), "audit log reopened");
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            path = %sink.path().display(),
                            "audit log reopen failed; keeping previous sink"
                        );
                    }
                }
            }
            match runtime.reload() {
                Ok(()) => tracing::info!("atomically reloaded inventory and token store"),
                Err(error) => tracing::error!(%error, "reload refused; retaining previous runtime"),
            }
        }
    });
    Ok(())
}

#[cfg(not(unix))]
fn spawn_reload_handler(
    _runtime: RuntimeState,
    _audit_sink: Option<rust_panosmcp_core::observability::AuditFileSink>,
) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod audit_hmac_key_tests {
    use super::ensure_audit_hmac_key;

    /// The common case: no entry point has ever run here before (fresh
    /// container volume, fresh LXC install). A key must be created, be
    /// non-empty, and be mode 0600 so it is not group/world-readable.
    #[test]
    fn generates_a_key_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(!contents.is_empty(), "generated key file must not be empty");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be mode 0600");
        }
    }

    /// A key already exists (install.sh ran, or this is not the first
    /// container start against this volume). It must be left byte-for-byte
    /// untouched -- rotating it here would silently break verification of
    /// every audit record HMAC'd under the old key.
    #[test]
    fn does_not_rotate_an_existing_nonempty_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"existing-key-material").unwrap();

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"existing-key-material");
    }

    /// A zero-byte key file is indistinguishable from "never generated" (a
    /// truncated write, an `install -m 0600 /dev/null ...` placeholder, an
    /// interrupted first run) and would make every HMAC output constant. It
    /// must be repaired, not treated as already-present.
    #[test]
    fn repairs_an_empty_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"").unwrap();

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(!contents.is_empty(), "empty key file must be repaired");
    }

    /// Two independent calls must not produce the same key -- otherwise the
    /// "random" key is really a constant and every deployment's audit HMAC
    /// is forgeable by anyone who reads this test.
    #[test]
    fn successive_generations_differ() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.key");
        let path_b = dir.path().join("b.key");

        ensure_audit_hmac_key(&path_a).unwrap();
        ensure_audit_hmac_key(&path_b).unwrap();

        let a = std::fs::read(&path_a).unwrap();
        let b = std::fs::read(&path_b).unwrap();
        assert_ne!(a, b, "two generated keys must not collide");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod startup_credential_tests {
    use super::{StartupCredentialFiles, server_naming, validate_startup_credentials};
    use std::path::PathBuf;

    #[test]
    fn deployed_paths_stay_on_the_rust_panosmcp_layout() {
        let naming = server_naming();
        assert_eq!(naming.config_dir, PathBuf::from("/etc/rust-panosmcp"));
        assert_eq!(naming.state_dir, PathBuf::from("/var/lib/rust-panosmcp"));
        assert_eq!(naming.service_user, "rust-panosmcp");
    }

    #[cfg(unix)]
    fn write_file(dir: &std::path::Path, name: &str, mode: u32) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Two loose modes must come back together. The failure this guards is a
    /// startup that names the first file, exits, and only names the second
    /// after that restart.
    #[cfg(unix)]
    #[test]
    fn one_pass_reports_every_bad_mode() {
        let dir = tempfile::tempdir().unwrap();
        let api_key_files = vec![write_file(dir.path(), "api-key", 0o644)];
        let tokens = write_file(dir.path(), "tokens.json", 0o640);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            api_key_files: &api_key_files,
            tokens: Some(&tokens),
            audit_hmac_key: None,
            tls_key: None,
        })
        .expect_err("both files are looser than a secret file allows");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("api-key"), "{message}");
        assert!(message.contains("tokens.json"), "{message}");
        assert!(message.contains("0644"), "{message}");
        assert!(message.contains("0640"), "{message}");
    }

    /// Owner-only secret files pass together, including the HMAC key and the
    /// listener private key. A missing configured token path is not skipped.
    #[cfg(unix)]
    #[test]
    fn acceptable_modes_pass_and_a_missing_token_store_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let api_key_files = vec![write_file(dir.path(), "api-key", 0o600)];
        let tokens = write_file(dir.path(), "tokens.json", 0o600);
        let hmac = write_file(dir.path(), "audit-hmac.key", 0o600);
        let tls = write_file(dir.path(), "server.key", 0o600);

        validate_startup_credentials(&StartupCredentialFiles {
            api_key_files: &api_key_files,
            tokens: Some(&tokens),
            audit_hmac_key: Some(&hmac),
            tls_key: Some(&tls),
        })
        .expect("0600 secret files pass together");

        let missing = dir.path().join("missing-tokens.json");
        let error = validate_startup_credentials(&StartupCredentialFiles {
            api_key_files: &[],
            tokens: Some(&missing),
            audit_hmac_key: None,
            tls_key: None,
        })
        .expect_err("a missing configured token store is an error");
        let message = error.to_string();
        assert!(message.contains("missing-tokens.json"), "{message}");
        assert!(message.contains("1 credential file"), "{message}");
    }
}
