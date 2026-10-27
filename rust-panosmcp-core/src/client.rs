//! Reusable, bounded async PAN-OS XML API client.

use crate::{
    PanosMcpError, Result,
    inventory::{DeviceConfig, LoadedTlsTrust, MutationPolicy},
    xml::{
        JobStatus, PanosResponse, XmlLimits, parse_job_status, parse_panos_response,
        parse_pending_changes, validate_job_id, validate_read_only_op_command, validate_read_xpath,
    },
};
use futures_util::StreamExt;
use reqwest::{Certificate, Client, redirect::Policy};
use rustls::{
    CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

const API_PATH: &str = "api/";

/// PAN-OS XML API codes that mean the configured key stopped authenticating,
/// as opposed to a transient transport failure or an unrelated API error.
///
/// `22` is "session timed out", which the XML API also raises for an expired
/// API key. Code `16` ("unauthorized") is deliberately excluded: PAN-OS uses
/// it when a *valid* key's role lacks rights for the specific command sent,
/// which a correctly-scoped least-privilege key can trigger routinely. See
/// [`crate::xml::panos_api_code_name`].
const AUTH_FAILURE_CODES: [i32; 1] = [22];

/// HTTP statuses PAN-OS uses to reject a request before it can even reach
/// the XML API layer -- the shape a revoked, invalid, or otherwise
/// credential-rejected key actually returns (an HTTP 200 wrapping an XML
/// error code is not what a bad key produces).
const AUTH_FAILURE_HTTP_STATUSES: [u16; 2] = [401, 403];

/// Pooled PAN-OS API client for exactly one validated inventory device.
#[derive(Clone)]
pub struct PanosClient {
    config: Arc<DeviceConfig>,
    client: Client,
    api_url: reqwest::Url,
    concurrency: Arc<Semaphore>,
    /// Set to `false` on the most recent request's PAN-OS auth failure
    /// (unauthorized key or expired session), `true` on any successful
    /// response. Other errors (timeout, transport, non-auth API error)
    /// leave it unchanged -- they say nothing about the key's validity.
    auth_healthy: Arc<AtomicBool>,
}

impl fmt::Debug for PanosClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanosClient")
            .field("device", &self.config.metadata.name)
            .field("api_url", &self.api_url)
            .field("max_concurrency", &self.config.max_concurrency)
            .finish_non_exhaustive()
    }
}

impl PanosClient {
    /// Construct a reusable client from a fully validated device entry.
    pub fn new(config: Arc<DeviceConfig>) -> Result<Self> {
        let client = build_http_client(&config)?;
        let api_url = config
            .endpoint
            .join(API_PATH)
            .map_err(|error| PanosMcpError::Configuration(error.to_string()))?;
        Ok(Self {
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            config,
            client,
            api_url,
            auth_healthy: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Safe device name.
    #[must_use]
    pub fn device_name(&self) -> &str {
        &self.config.metadata.name
    }

    /// Whether the most recent request against this device authenticated.
    ///
    /// Starts `true`: an unreached device has not yet proven its key is bad,
    /// and `/readyz` should not fail before the first request goes out.
    #[must_use]
    pub fn is_auth_healthy(&self) -> bool {
        self.auth_healthy.load(Ordering::Relaxed)
    }

    /// Explicit candidate-mutation policy, if the operator enabled writes.
    #[must_use]
    pub fn mutation_policy(&self) -> Option<&MutationPolicy> {
        self.config.mutation.as_ref()
    }

    /// Who owns the authoritative configuration for this firewall.
    #[must_use]
    pub fn config_authority(&self) -> crate::inventory::PanosMcpConfigAuthority {
        self.config.config_authority
    }

    /// Canonical management endpoint used to serialize aliases of one appliance.
    #[must_use]
    pub(crate) fn mutation_lock_key(&self) -> String {
        self.config.endpoint.origin().ascii_serialization()
    }

    /// Execute a validated PAN-OS operational XML command.
    pub async fn operational(
        &self,
        command: &str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_read_only_op_command(command)?;
        self.post(
            vec![("type", "op".to_owned()), ("cmd", command.to_owned())],
            cancellation,
        )
        .await
    }

    /// Read running (`show`) or candidate (`get`) configuration at an XPath.
    pub async fn configuration(
        &self,
        candidate: bool,
        xpath: &str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_read_xpath(xpath)?;
        self.post(
            vec![
                ("type", "config".to_owned()),
                ("action", if candidate { "get" } else { "show" }.to_owned()),
                ("xpath", xpath.to_owned()),
            ],
            cancellation,
        )
        .await
    }

    /// Like [`configuration`](Self::configuration), but for entry listing:
    /// stops reading at `max_response_bytes` and returns the partial body
    /// with a truncation flag rather than failing the call.
    ///
    /// The caller scans the returned bytes for complete top-level `<entry>`
    /// elements rather than parsing them as one document, so a response cut
    /// mid-stream is exactly as useful as a complete one, just missing
    /// whatever came after the cut -- unlike every other PAN-OS reader here,
    /// which needs a well-formed document and must keep failing closed on
    /// one that got only partway downloaded.
    pub(crate) async fn configuration_entries(
        &self,
        candidate: bool,
        xpath: &str,
        cancellation: CancellationToken,
    ) -> Result<(Vec<u8>, bool)> {
        validate_read_xpath(xpath)?;
        self.send(
            vec![
                ("type", "config".to_owned()),
                ("action", if candidate { "get" } else { "show" }.to_owned()),
                ("xpath", xpath.to_owned()),
            ],
            cancellation,
            true,
        )
        .await
    }

    /// Ask PAN-OS whether the dedicated admin has any uncommitted candidate
    /// edit, anywhere in the configuration -- not just under the xpath roots
    /// this tool manages.
    ///
    /// This is a fixed, caller-input-free constant command, so it bypasses
    /// [`operational`](Self::operational)'s `<show>`-only validation rather
    /// than widening it: `<check>` is a distinct PAN-OS operational root with
    /// its own semantics, and accepting arbitrary `<check>` bodies from a
    /// caller is not something Phase 1 needs.
    pub(crate) async fn check_pending_changes(
        &self,
        cancellation: CancellationToken,
    ) -> Result<bool> {
        let response = self
            .post(
                vec![
                    ("type", "op".to_owned()),
                    (
                        "cmd",
                        "<check><pending-changes></pending-changes></check>".to_owned(),
                    ),
                ],
                cancellation,
            )
            .await?;
        parse_pending_changes(&response)
    }

    /// Execute a fixed, parameter-free `<request>`-rooted operational
    /// command.
    ///
    /// Same rationale as [`check_pending_changes`](Self::check_pending_changes):
    /// `<request>` is a distinct PAN-OS operational root from `<show>`, and
    /// this bypasses [`operational`](Self::operational)'s `<show>`-only gate
    /// rather than widening it, because every caller here passes one of a
    /// small set of `&'static str` constants -- never caller-supplied text.
    pub(crate) async fn fixed_op(
        &self,
        command: &'static str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        self.post(
            vec![("type", "op".to_owned()), ("cmd", command.to_owned())],
            cancellation,
        )
        .await
    }

    /// Execute an external-list `<request>` command for one named EDL.
    ///
    /// This is the one parameterised `<request>` path, which is why it is not
    /// [`fixed_op`](Self::fixed_op): its only variable parts are two enums
    /// and `name`, and `name` must pass [`validate_edl_name`] before it is
    /// interpolated, so the charset excludes every XML metacharacter and no
    /// escaping is needed.
    pub(crate) async fn edl_op(
        &self,
        verb: EdlVerb,
        edl_type: EdlType,
        name: &str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_edl_name(name)?;
        let command = format!(
            "<request><system><external-list><{verb}><type><{kind}><name>{name}</name></{kind}></type></{verb}></external-list></system></request>",
            verb = verb.tag(),
            kind = edl_type.tag(),
        );
        self.post(
            vec![("type", "op".to_owned()), ("cmd", command)],
            cancellation,
        )
        .await
    }

    /// Poll a PAN-OS `type=log` job with cancellation and bounded backoff.
    ///
    /// A log job's terminal state is nested under `<result><job><status>...`
    /// -- the same shape [`poll_job`](Self::poll_job)'s `parse_job_status`
    /// expects for a config/commit job -- but this uses
    /// [`crate::xml::log_job_is_finished`], which scans for `<status>`
    /// anywhere in the document rather than requiring that exact nesting,
    /// since the shape is based on documentation and hand-written fixtures,
    /// not a verified live-device response.
    ///
    /// On timeout or cancellation, best-effort sends `action=finish` for
    /// this job id so PAN-OS's small pool of concurrent log-query slots
    /// does not stay occupied by an abandoned job.
    pub(crate) async fn poll_log_job(
        &self,
        job_id: &str,
        deadline: Duration,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_job_id(job_id)?;
        let operation = async {
            let mut backoff = Duration::from_millis(200);
            loop {
                let response = self
                    .post(
                        vec![
                            ("type", "log".to_owned()),
                            ("action", "get".to_owned()),
                            ("job-id", job_id.to_owned()),
                        ],
                        cancellation.clone(),
                    )
                    .await?;
                if crate::xml::log_job_is_finished(&response)? {
                    return Ok(response);
                }
                let jitter = fastrand::u64(0..=100);
                tokio::select! {
                    () = cancellation.cancelled() => return Err(PanosMcpError::Cancelled),
                    () = time::sleep(backoff + Duration::from_millis(jitter)) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(3));
            }
        };
        match time::timeout(deadline, operation).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => {
                if matches!(err, PanosMcpError::Cancelled) {
                    self.best_effort_finish_log_job(job_id).await;
                }
                Err(err)
            }
            Err(_) => {
                self.best_effort_finish_log_job(job_id).await;
                Err(PanosMcpError::Timeout {
                    operation: "poll_log_job",
                })
            }
        }
    }

    /// Best-effort release of a `type=log` job PAN-OS is still holding a
    /// concurrent-query slot for, after this client gave up waiting on it.
    /// Uses a fresh cancellation token and a short timeout of its own so a
    /// wedged connection cannot turn an abandoned poll into a second hang;
    /// any failure here is swallowed, since the caller is already reporting
    /// the original timeout or cancellation.
    async fn best_effort_finish_log_job(&self, job_id: &str) {
        let finish = self.post(
            vec![
                ("type", "log".to_owned()),
                ("action", "finish".to_owned()),
                ("job-id", job_id.to_owned()),
            ],
            CancellationToken::new(),
        );
        let _ = time::timeout(Duration::from_secs(5), finish).await;
    }

    /// Poll a PAN-OS asynchronous job with cancellation and bounded backoff.
    pub async fn poll_job(
        &self,
        job_id: &str,
        deadline: Duration,
        cancellation: CancellationToken,
    ) -> Result<JobStatus> {
        validate_job_id(job_id)?;
        let command = format!("<show><jobs><id>{job_id}</id></jobs></show>");
        let operation = async {
            let mut backoff = Duration::from_millis(200);
            loop {
                let response = self.operational(&command, cancellation.clone()).await?;
                let status = parse_job_status(&response)?;
                if status.is_finished() {
                    return Ok(status);
                }
                let jitter = fastrand::u64(0..=100);
                tokio::select! {
                    () = cancellation.cancelled() => return Err(PanosMcpError::Cancelled),
                    () = time::sleep(backoff + Duration::from_millis(jitter)) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(3));
            }
        };
        match time::timeout(deadline, operation).await {
            Ok(result) => result,
            Err(_) => Err(PanosMcpError::Timeout {
                operation: "poll_job",
            }),
        }
    }

    /// Fetch a PAN-OS job's current response in one read, with no polling loop.
    ///
    /// Unlike [`poll_job`](Self::poll_job) this returns the full envelope
    /// rather than the summarized [`JobStatus`], so a caller that needs
    /// PAN-OS-specific nested detail -- such as a Panorama push job's
    /// per-target-firewall `<devices>` breakdown -- can parse it directly.
    pub async fn job_response(
        &self,
        job_id: &str,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        validate_job_id(job_id)?;
        let command = format!("<show><jobs><id>{job_id}</id></jobs></show>");
        self.operational(&command, cancellation).await
    }

    /// Submit already-validated fields for guarded configuration lifecycle operations.
    pub(crate) async fn post_fields(
        &self,
        fields: Vec<(&'static str, String)>,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        self.post(fields, cancellation).await
    }

    async fn post(
        &self,
        fields: Vec<(&'static str, String)>,
        cancellation: CancellationToken,
    ) -> Result<PanosResponse> {
        let outcome = async {
            let (bytes, _truncated) = self.send(fields, cancellation, false).await?;
            parse_panos_response(
                &bytes,
                XmlLimits {
                    max_bytes: self.config.max_response_bytes,
                    max_depth: 64,
                },
            )?
            .ensure_success(self.device_name())
        }
        .await;
        // `send`'s own bookkeeping only sees the transport layer, so it
        // cannot notice an API-level auth failure (code 22) that arrives as
        // a 200 OK wrapping an XML error. Re-record here with the fully
        // parsed outcome so that case still flips `auth_healthy`.
        self.record_auth_result(&outcome);
        outcome
    }

    /// Shared request/response plumbing behind [`post`](Self::post) and
    /// [`configuration_entries`](Self::configuration_entries).
    ///
    /// `truncate = false` reproduces `post`'s original behavior exactly: a
    /// response over `max_response_bytes` -- by header or by the stream
    /// actually exceeding it -- is `ResponseTooLarge`, never partial data.
    /// `truncate = true` instead stops at the limit and returns what was read
    /// so far with the flag set; callers of that mode must not treat the
    /// bytes as a complete document.
    async fn send(
        &self,
        mut fields: Vec<(&'static str, String)>,
        cancellation: CancellationToken,
        truncate: bool,
    ) -> Result<(Vec<u8>, bool)> {
        if let Some(vsys) = &self.config.metadata.vsys {
            fields.push(("vsys", vsys.clone()));
        }
        let operation = async {
            let _permit = self
                .concurrency
                .acquire()
                .await
                .map_err(|_| PanosMcpError::Cancelled)?;

            let mut api_key =
                reqwest::header::HeaderValue::from_str(self.config.api_key.expose_secret())
                    .map_err(|_| {
                        PanosMcpError::Secret(
                            "PAN-OS API key is not a valid header value".to_owned(),
                        )
                    })?;
            api_key.set_sensitive(true);
            let response = self
                .client
                .post(self.api_url.clone())
                .header("X-PAN-KEY", api_key)
                .form(&fields)
                .send()
                .await
                .map_err(|error| classify_transport(error, self.device_name()))?;

            if !response.status().is_success() {
                return Err(PanosMcpError::HttpStatus {
                    device: self.device_name().to_owned(),
                    status: response.status().as_u16(),
                });
            }
            if !truncate
                && response
                    .content_length()
                    .is_some_and(|length| length > self.config.max_response_bytes as u64)
            {
                return Err(PanosMcpError::ResponseTooLarge {
                    device: self.device_name().to_owned(),
                    limit: self.config.max_response_bytes,
                });
            }

            let mut bytes = Vec::new();
            let mut truncated = false;
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| classify_transport(error, self.device_name()))?;
                if bytes.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                    if truncate {
                        let remaining = self.config.max_response_bytes - bytes.len();
                        bytes.extend_from_slice(&chunk[..remaining]);
                        truncated = true;
                        break;
                    }
                    return Err(PanosMcpError::ResponseTooLarge {
                        device: self.device_name().to_owned(),
                        limit: self.config.max_response_bytes,
                    });
                }
                bytes.extend_from_slice(&chunk);
            }

            Ok((bytes, truncated))
        };

        let outcome = tokio::select! {
            () = cancellation.cancelled() => Err(PanosMcpError::Cancelled),
            result = time::timeout(self.config.request_timeout, operation) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(PanosMcpError::Timeout { operation: "panos_api" }),
                }
            }
        };
        // `send` only sees the transport layer: a 2xx here does not mean the
        // request authenticated, since PAN-OS can wrap an unrelated API
        // error (or even an auth failure such as code 22) inside an HTTP 200
        // body that `send` never parses. So only react to a failure here --
        // an `HttpStatus` rejection is itself proof of a bad credential --
        // and leave marking `auth_healthy` back to `true` to `post`, which
        // sees the fully parsed result.
        if let Err(error) = &outcome {
            self.record_auth_failure(error);
        }
        outcome
    }

    /// Update `auth_healthy` from a completed request's fully parsed outcome.
    fn record_auth_result<T>(&self, outcome: &Result<T>) {
        match outcome {
            Ok(_) => self.auth_healthy.store(true, Ordering::Relaxed),
            Err(error) => self.record_auth_failure(error),
        }
    }

    /// Flip `auth_healthy` to `false` if `error` is one of the specific
    /// shapes PAN-OS uses to reject a bad credential; leave it unchanged for
    /// every other error (timeout, transport, unrelated API error).
    fn record_auth_failure(&self, error: &PanosMcpError) {
        match error {
            PanosMcpError::Api { code, .. } if AUTH_FAILURE_CODES.contains(code) => {
                self.auth_healthy.store(false, Ordering::Relaxed);
            }
            PanosMcpError::HttpStatus { status, .. }
                if AUTH_FAILURE_HTTP_STATUSES.contains(status) =>
            {
                self.auth_healthy.store(false, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

fn build_http_client(config: &DeviceConfig) -> Result<Client> {
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.clone().install_default();
    let provider = Arc::new(provider);
    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(config.connect_timeout)
        .pool_idle_timeout(Duration::from_secs(300))
        .pool_max_idle_per_host(config.max_concurrency)
        .http1_only()
        .tls_version_min(reqwest::tls::Version::TLS_1_2);

    match &config.tls {
        LoadedTlsTrust::System => {}
        LoadedTlsTrust::CustomCa { pem, .. } => {
            let certificates =
                Certificate::from_pem_bundle(pem).map_err(|_| PanosMcpError::Tls {
                    device: config.metadata.name.clone(),
                    reason: "custom CA bundle is not valid PEM certificate data".to_owned(),
                })?;
            if certificates.is_empty() {
                return Err(PanosMcpError::Tls {
                    device: config.metadata.name.clone(),
                    reason: "custom CA bundle contains no certificates".to_owned(),
                });
            }
            builder = builder.tls_certs_only(certificates);
        }
        LoadedTlsTrust::LeafSha256(expected) => {
            let verifier = Arc::new(LeafPinVerifier {
                expected: *expected,
                provider: provider.clone(),
            });
            let mut tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| PanosMcpError::Tls {
                    device: config.metadata.name.clone(),
                    reason: format!("failed to enable TLS 1.2/1.3: {error}"),
                })?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            builder = builder.tls_backend_preconfigured(tls);
        }
    }

    builder.build().map_err(|error| PanosMcpError::Tls {
        device: config.metadata.name.clone(),
        reason: sanitized_reqwest_reason(&error).to_owned(),
    })
}

#[derive(Debug)]
struct LeafPinVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for LeafPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn classify_transport(error: reqwest::Error, device: &str) -> PanosMcpError {
    if error.is_timeout() {
        return PanosMcpError::Timeout {
            operation: "panos_api",
        };
    }
    PanosMcpError::Transport {
        device: device.to_owned(),
        reason: sanitized_reqwest_reason(&error).to_owned(),
    }
}

fn sanitized_reqwest_reason(error: &reqwest::Error) -> &'static str {
    if error.is_connect() {
        "connection or TLS handshake failed"
    } else if error.is_body() || error.is_decode() {
        "response body transfer failed"
    } else if error.is_builder() {
        "request construction failed"
    } else if error.is_request() {
        "request transmission failed"
    } else {
        "HTTP client failure"
    }
}

/// External-list `<request>` verb.
#[derive(Debug, Clone, Copy)]
pub(crate) enum EdlVerb {
    /// `stats`: validity and next refresh.
    Stats,
    /// `show`: entry counts and members.
    Show,
}

impl EdlVerb {
    fn tag(self) -> &'static str {
        match self {
            Self::Stats => "stats",
            Self::Show => "show",
        }
    }
}

/// External-list type element accepted by [`PanosClient::edl_op`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum EdlType {
    /// `ip` list.
    Ip,
    /// `domain` list.
    Domain,
}

impl EdlType {
    fn tag(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
        }
    }
}

/// Validate an EDL object name: 1-63 characters of `[A-Za-z0-9 ._-]`.
///
/// The PAN-OS object-name charset. It excludes every XML and log-filter
/// metacharacter (quotes, brackets, parentheses, `<`, `&`), so a name that
/// passes can be interpolated into an op command or a log query unescaped.
pub(crate) fn validate_edl_name(name: &str) -> Result<()> {
    let valid = (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-'));
    if valid {
        return Ok(());
    }
    Err(PanosMcpError::Policy {
        field: "external-list name",
        reason: "value must be 1-63 characters of A-Z a-z 0-9 space . _ -".to_owned(),
    })
}
