//! Bearer-protected MCP Streamable HTTP transport using mecmcp-transport 0.9.0.

use crate::{PanosMcpServer, RuntimeState};
use mecmcp_auth::{BearerSyntax, CallerCtx};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy, HttpServeError,
    HttpTransportBuildError, HttpTransportConfig, LimitsConfig, MalformedArgumentsPolicy,
    ReadinessCheck, ServePlan, TargetField, ToolScopePreflight, TransportIdentity,
    build_streamable_http_router, loopback_origins, serve_router,
};
use rust_panosmcp_auth::{MUTATION_TOOLS, MutationGrant};
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

/// Validated transport settings.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Listening port, used to build strict loopback Origin entries.
    pub port: u16,
    /// Whether the listener itself uses TLS.
    pub tls: bool,
    /// Operator accepted a plaintext off-loopback listener (`--allow-insecure-bind`).
    ///
    /// Must be carried through to the transport. Parsing the flag and never
    /// converting it is the defect class mecmcp#273 exists to close — a flag
    /// that is present but ignored. It took LXC 950 down on the sibling Junos
    /// server, where exactly this wiring was missing.
    pub allow_insecure_bind: bool,
    /// Additional exact Host authorities.
    pub allowed_hosts: Vec<String>,
    /// Additional exact browser origins.
    pub allowed_origins: Vec<String>,
    /// Per-source-IP requests per minute.
    pub ip_rate_per_minute: u32,
    /// Per-token requests per minute.
    pub token_rate_per_minute: u32,
    /// Maximum request body bytes.
    pub request_body_limit: usize,
    /// Maximum concurrent in-flight requests across all callers.
    pub max_inflight_requests: usize,
    /// Maximum concurrent in-flight requests per bearer token.
    pub max_inflight_requests_per_token: usize,
    /// Maximum concurrent in-flight requests per target device.
    pub max_inflight_requests_per_target: usize,
    /// Maximum concurrent MCP sessions.
    pub max_sessions: usize,
    /// Maximum concurrent MCP sessions per bearer token.
    pub max_sessions_per_token: usize,
}

/// Convert a documented per-minute request quota into the per-second
/// sustained refill rate mecmcp-transport's token bucket expects.
///
/// Rounds up rather than truncating, so a quota below 60/minute is never
/// silently disabled by integer division to zero (`0` means "unlimited" to
/// the bucket, i.e. fail open) -- the sustained rate this yields is within
/// one request/second of the documented quota, never coarser (MEC-528
/// class 4: passing the per-minute value straight through as the
/// per-second rate previously made the sustained limit up to 60x looser
/// than documented).
#[must_use]
fn per_minute_to_per_second(per_minute: u32) -> u64 {
    u64::from(per_minute).div_ceil(60)
}

/// Build the complete shared HTTP router with PAN-OS-owned identity and scope fields.
pub fn build_router(
    runtime: RuntimeState,
    options: HttpOptions,
    enable_metrics: bool,
    shutdown: CancellationToken,
) -> Result<ServePlan, HttpTransportBuildError> {
    let identity =
        TransportIdentity::new("panosmcp", "panos", "rust-panosmcp", ["device", "devices"]);

    // mecmcp-transport's token bucket takes a per-second refill rate, but
    // `--ip-rate-per-minute`/`--token-rate-per-minute` are documented and
    // configured as a per-*minute* quota. Passing the per-minute value
    // straight through as the per-second rate (as this used to) makes the
    // sustained limit 60x looser than documented -- e.g. the default
    // `ip_rate_per_minute = 120` became a 120-requests-per-*second* bucket
    // (MEC-528 class 4). Burst stays the full per-minute quota so a caller
    // can still spend it all in less than a minute; only the sustained
    // refill rate is converted.
    let limits = LimitsConfig {
        max_request_body_bytes: options.request_body_limit,
        max_requests_per_second_per_ip: per_minute_to_per_second(options.ip_rate_per_minute),
        max_request_burst_per_ip: u64::from(options.ip_rate_per_minute),
        max_requests_per_second_per_token: per_minute_to_per_second(options.token_rate_per_minute),
        max_request_burst_per_token: u64::from(options.token_rate_per_minute),
        max_sessions: options.max_sessions,
        max_sessions_per_token: options.max_sessions_per_token,
        max_inflight_requests: options.max_inflight_requests,
        max_inflight_requests_per_token: options.max_inflight_requests_per_token,
        max_inflight_requests_per_device: options.max_inflight_requests_per_target,
        // This server exposes no operator flag for a trusted reverse-proxy
        // CIDR list yet (mecmcp-transport#410 added the field). Empty keeps
        // prior behavior: the rate limiter keys on the direct peer address,
        // never an `X-Forwarded-For` header, which is the safe default in
        // the absence of a configured trusted proxy.
        trusted_proxies: Vec::new(),
        session_idle_timeout_secs: 300,
        session_max_lifetime_secs: 3600,
    };

    // Build complete Origin list including loopback
    let all_origins = loopback_origins(options.port, options.tls, options.allowed_origins.clone());
    let host_origin = HostOriginPolicy::enforced(options.allowed_hosts.clone(), all_origins);

    // Determine whether authentication is required based on token presence
    let snapshot = runtime.snapshot();
    let config = if snapshot.tokens.is_some() {
        let auth_runtime = runtime.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_runtime.snapshot();
            let store = snapshot.tokens.as_ref()?;
            let entry = store.authenticate(candidate)?;
            // The boundary inserts whatever grant type this closure produces,
            // so the context is built over `MutationGrant` and carries the
            // entry's grant. Dropping it here left every change-set write
            // refused as ungranted (#116).
            Some(CallerCtx::<MutationGrant> {
                token_name: entry.name.clone(),
                devices: entry.devices.clone(),
                tools: entry.tools.clone(),
                grant: entry.grant.clone(),
                provider: entry.provider.clone(),
                provider_tier: entry.provider_tier,
                on_behalf_of: entry.on_behalf_of.clone(),
                actor_type: entry.actor_type,
                oidc_subject: entry.oidc_subject.clone(),
                // This server does not implement MEC-994 W3's
                // `bind_approver` bearer preflight, so no request ever
                // carries a verified approver assertion yet.
                verified_approver: None,
                client_name: None,
                model_id: None,
                session_id: None,
                request_id: uuid::Uuid::new_v4(),
            })
        });
        let preflight = ToolScopePreflight::new(
            MUTATION_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let boundary =
            BearerBoundary::new(authenticator, BearerResponseProfile::detailed("panosmcp"))
                .with_preflight(preflight);
        HttpTransportConfig::authenticated(
            identity.clone(),
            limits.clone(),
            host_origin,
            shutdown,
            boundary,
        )
    } else {
        use mecmcp_transport::NoAuthAcknowledgement;
        HttpTransportConfig::unauthenticated(
            identity.clone(),
            limits.clone(),
            host_origin,
            shutdown,
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        )
    }
    .with_metrics(enable_metrics);

    let config = if options.allow_insecure_bind {
        use mecmcp_transport::InsecureBindAcknowledgement;
        config.with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind())
    } else {
        config
    };

    // `/readyz` flips to failing the first poll after PAN-OS rejects the
    // configured API key (unauthorized or session-timed-out) on any device,
    // rather than staying green while every tool call is silently refused.
    let auth_check_runtime = runtime.clone();
    let config = config.with_readiness_check(ReadinessCheck::new("panos_auth", move || {
        auth_check_runtime.snapshot().service.auth_health_check()
    }));
    drop(snapshot);

    let service_factory = move || {
        let server = PanosMcpServer::from_runtime(runtime.clone());
        Ok::<_, std::io::Error>(server)
    };

    build_streamable_http_router(service_factory, config)
}

/// Serve until shutdown or listener failure.
pub async fn serve(
    runtime: RuntimeState,
    address: SocketAddr,
    options: HttpOptions,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), HttpServeError> {
    let shutdown = CancellationToken::new();

    // Install signal handlers
    let signal_shutdown = shutdown.clone();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|e| HttpServeError::Serve { address, error: e })?;
        let mut sigint = signal(SignalKind::interrupt())
            .map_err(|e| HttpServeError::Serve { address, error: e })?;
        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM received");
                }
                _ = sigint.recv() => {
                    tracing::info!("SIGINT received");
                }
            }
            signal_shutdown.cancel();
        });
    }
    #[cfg(not(unix))]
    {
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Ctrl+C received");
            signal_shutdown.cancel();
        });
    }

    let plan = build_router(runtime, options, enable_metrics, shutdown).map_err(|error| {
        HttpServeError::Serve {
            address,
            error: std::io::Error::other(error.to_string()),
        }
    })?;

    // Graceful shutdown timeout: 10 seconds for in-flight requests/SSE streams.
    // LXC 608's systemd unit has TimeoutStopSec=30s, so this drain completes well
    // before systemd's SIGKILL. While any SSE stream is open (e.g., an MCP session),
    // shutdown takes the full timeout rather than ending immediately.
    let shutdown_timeout = std::time::Duration::from_secs(10);
    serve_router(plan, address, tls, shutdown_timeout).await
}

#[cfg(test)]
mod tests {
    use super::per_minute_to_per_second;
    use mecmcp_auth::{ScopeSet, TokenDigest, TokenEntry, TokenStore};

    /// MEC-528 class 4: the documented default of 120 requests/minute must
    /// become a 2-requests/second sustained rate (120/min), not 120/sec
    /// (7200/min) as it did when the per-minute value was passed straight
    /// through as the per-second rate.
    #[test]
    fn converts_documented_default_rates_exactly() {
        assert_eq!(per_minute_to_per_second(120), 2, "ip default: 120/min");
        assert_eq!(per_minute_to_per_second(240), 4, "token default: 240/min");
    }

    #[test]
    fn zero_stays_zero_so_the_dimension_stays_disabled() {
        assert_eq!(per_minute_to_per_second(0), 0);
    }

    /// A quota below 60/minute must round up to a nonzero per-second rate --
    /// truncating division would silently disable rate limiting entirely.
    #[test]
    fn sub_minute_quota_rounds_up_instead_of_disabling() {
        assert_eq!(per_minute_to_per_second(1), 1);
        assert_eq!(per_minute_to_per_second(30), 1);
        assert_eq!(per_minute_to_per_second(59), 1);
    }

    #[test]
    fn never_exceeds_a_60x_blowup_regardless_of_input() {
        for per_minute in [1_u32, 30, 59, 60, 61, 100, 120, 240, 1_000, u32::MAX] {
            let per_second = per_minute_to_per_second(per_minute);
            assert!(
                per_second.saturating_mul(60) < u64::from(per_minute) + 60,
                "per_minute={per_minute} converted to per_second={per_second}, \
                 sustained rate {}/min is more than one bucket-granularity step \
                 looser than documented",
                per_second * 60
            );
        }
    }

    #[test]
    fn token_store_fixture_authenticates_without_exposing_digest() {
        let store: TokenStore = TokenStore::try_new(vec![TokenEntry {
            name: "test".to_owned(),
            digest: TokenDigest::from_secret("secret"),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: chrono::DateTime::from_timestamp(1, 0).expect("timestamp"),
            expires_at: None,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Unknown,
            oidc_subject: None,
        }])
        .expect("store");
        assert_eq!(
            store.authenticate("secret").map(|entry| &entry.name),
            Some(&"test".to_owned())
        );
    }
}
