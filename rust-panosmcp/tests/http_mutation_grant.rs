//! A token's mutation grant must survive the HTTP bearer boundary.
//!
//! The change-set tools refuse a caller whose grant is absent. The grant lives
//! on the token entry, so it has to be carried into the caller context the
//! tool layer reads — see rustpanosmcp#116, where two constructors dropped it
//! and every HTTP change-set write was refused.

use axum::{
    body::Body,
    http::{Request, header},
};
use rust_panosmcp::{
    RuntimeState,
    http_transport::{HttpOptions, build_router},
};
use rust_panosmcp_auth::{KnownNames, MutationAction, MutationGrant, ScopeSet, TokenStoreFile};
use std::{fs, path::PathBuf};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const ADDRESS_ROOT: &str =
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address";

/// The refusal this test exists to keep from coming back.
const NO_GRANT: &str = "require a token-specific mutation grant";

struct Fixture {
    _directory: TempDir,
    runtime: RuntimeState,
    secret: String,
}

/// Build a runtime whose single token carries `grant`.
fn fixture(grant: Option<MutationGrant>) -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let key_path = directory.path().join("panos-api-key");
    fs::write(&key_path, "not-a-live-key").expect("API key fixture");
    make_private(&key_path);
    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"lab-fw","endpoint":"https://fw.example.test","api_key":{{"type":"file","path":"{}"}},"mutation":{{"admin":"admin","allowed_xpath_roots":["{}"]}}}}]}}"#,
            key_path.display(),
            ADDRESS_ROOT
        ),
    )
    .expect("inventory fixture");

    let token_path: PathBuf = directory.path().join("tokens.json");
    let known_devices = ["lab-fw".to_owned()];
    let known = KnownNames {
        devices: Some(&known_devices),
        tools: rust_panosmcp_auth::KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::add_with_options(
        &token_path,
        "writer",
        ScopeSet::Allowlist(vec!["lab-fw".to_owned()]),
        // A wildcard tool scope never covers a write tool, so the mutation
        // tools have to be named for the request to survive the preflight.
        ScopeSet::Allowlist(vec!["create_panos_change_set".to_owned()]),
        None,
        grant,
        None,
        None,
        None,
        None,
        None,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();
    let runtime = RuntimeState::load(&inventory_path, Some(&token_path)).expect("runtime");
    Fixture {
        _directory: directory,
        runtime,
        secret,
    }
}

/// Same shape as the other HTTP integration tests: the item exists on every
/// target so the fixture compiles, and only the mode change is Unix-gated.
fn make_private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private mode");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn options() -> HttpOptions {
    HttpOptions {
        port: 30031,
        tls: false,
        allow_insecure_bind: false,
        allowed_hosts: Vec::new(),
        allowed_origins: Vec::new(),
        ip_rate_per_minute: 1_000,
        token_rate_per_minute: 1_000,
        request_body_limit: 1024 * 1024,
        max_inflight_requests: 64,
        max_inflight_requests_per_token: 16,
        max_inflight_requests_per_target: 4,
        max_sessions: 128,
        max_sessions_per_token: 16,
    }
}

/// One stateless `tools/call`, so the test needs no session handshake.
fn create_change_set(authorization: &str) -> Request<Body> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"create_panos_change_set","arguments":{{"device":"lab-fw","expected_candidate_fingerprint":"sha256:{zeros}","actions":[{{"action":"set","xpath":"{root}","element":"<entry name='probe'><ip-netmask>192.0.2.1/32</ip-netmask></entry>"}}]}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"grant-test","version":"1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#,
        zeros = "0".repeat(64),
        root = ADDRESS_ROOT,
    );
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, "http://localhost:30031")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, authorization)
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "create_panos_change_set")
        .body(Body::from(body))
        .expect("request")
}

/// Send `request` against a live loopback server and return the response body.
async fn body_of(runtime: &RuntimeState, request: Request<Body>) -> String {
    let shutdown = CancellationToken::new();
    let plan = build_router(runtime.clone(), options(), false, shutdown.clone()).expect("router");
    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;

    let uri = format!("http://{}{}", served.address, request.uri().path());
    let client = reqwest::Client::new();
    let mut outgoing = client.request(request.method().clone(), &uri);
    for (name, value) in request.headers() {
        outgoing = outgoing.header(name, value);
    }
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("body");
    let response = outgoing.body(bytes).send().await.expect("request");
    let text = response.text().await.expect("response body");
    shutdown.cancel();
    text
}

fn address_grant() -> MutationGrant {
    MutationGrant {
        allowed_xpath_roots: vec![ADDRESS_ROOT.to_owned()],
        actions: vec![MutationAction::Set],
    }
}

/// The grant on the token entry has to reach the tool layer over HTTP.
///
/// The device is unreachable in this fixture, so the call cannot succeed — but
/// it must fail for a device reason, never for a missing grant.
#[tokio::test]
async fn a_granted_token_may_write_a_change_set_over_http() {
    let fixture = fixture(Some(address_grant()));
    let bearer = format!("Bearer {}", fixture.secret);

    let body = body_of(&fixture.runtime, create_change_set(&bearer)).await;

    assert!(
        !body.contains(NO_GRANT),
        "a token whose entry carries a mutation grant was refused as ungranted: {body}"
    );
}

/// The refusal still has to happen for a token that genuinely has no grant.
#[tokio::test]
async fn an_ungranted_token_may_not_write_a_change_set_over_http() {
    let fixture = fixture(None);
    let bearer = format!("Bearer {}", fixture.secret);

    let body = body_of(&fixture.runtime, create_change_set(&bearer)).await;

    assert!(
        body.contains(NO_GRANT),
        "a token with no mutation grant was allowed to write a change set: {body}"
    );
}
