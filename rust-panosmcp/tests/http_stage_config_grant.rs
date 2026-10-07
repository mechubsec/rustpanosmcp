//! MEC-528 class 2: `stage_panos_config` (the v0.1 write tool) must honor a
//! token's own `MutationGrant`, not just the device-wide inventory policy.
//!
//! Before this fix, a token holding a narrow mutation grant (e.g. one vsys)
//! but still permitted to call `stage_panos_config` could write anywhere in
//! the device's full `allowed_xpath_roots`, because `stage_config` only
//! checked the device policy and never consulted `caller.grant` -- unlike
//! `create_panos_change_set`/`apply_panos_change_set`, which do.
//!
//! MEC-528 F4: separately, an HTTP token permitted to call
//! `stage_panos_config` but whose entry carries *no* grant at all used to
//! reach `stage_config` with `grant = None`, which only checks the
//! device-wide policy -- unlike the v0.2 change-set tools, which already
//! refuse a grantless HTTP caller via `mutation_identity`.

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

/// Broader than the grant below: the device permits writes anywhere under
/// `vsys`, covering both `vsys1` and `vsys2`.
const DEVICE_ROOT: &str = "/config/devices/entry[@name='localhost.localdomain']/vsys";
/// The token's own grant: only `vsys1`'s address book.
const GRANT_ROOT: &str =
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address";
/// Within `DEVICE_ROOT` but outside `GRANT_ROOT`: a sibling vsys.
const OUTSIDE_GRANT: &str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/address/entry[@name='probe']";

const GRANT_DENIAL: &str = "outside this token's mutation grant";
/// The refusal F4 exists to keep from coming back: an HTTP token with no
/// grant at all must not reach the device-policy-only check in `stage_config`.
const NO_GRANT: &str = "require a token-specific mutation grant";

struct Fixture {
    _directory: TempDir,
    runtime: RuntimeState,
    secret: String,
}

fn fixture(grant: Option<MutationGrant>) -> Fixture {
    let directory = tempfile::tempdir().expect("temporary directory");
    let key_path = directory.path().join("panos-api-key");
    fs::write(&key_path, "not-a-live-key").expect("API key fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("private mode");
    }
    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"lab-fw","endpoint":"https://fw.example.test","api_key":{{"type":"file","path":"{}"}},"mutation":{{"admin":"admin","allowed_xpath_roots":["{}"]}}}}]}}"#,
            key_path.display(),
            DEVICE_ROOT
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
        "narrow-writer",
        ScopeSet::Allowlist(vec!["lab-fw".to_owned()]),
        ScopeSet::Allowlist(vec!["stage_panos_config".to_owned()]),
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

fn stage_config(authorization: &str, xpath: &str) -> Request<Body> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"stage_panos_config","arguments":{{"device":"lab-fw","expected_candidate_fingerprint":"sha256:{zeros}","action":"set","xpath":"{xpath}","element":"<entry name='probe'><ip-netmask>192.0.2.1/32</ip-netmask></entry>"}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"grant-test","version":"1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#,
        zeros = "0".repeat(64),
        xpath = xpath,
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
        .header("Mcp-Name", "stage_panos_config")
        .body(Body::from(body))
        .expect("request")
}

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

fn narrow_grant() -> MutationGrant {
    MutationGrant {
        allowed_xpath_roots: vec![GRANT_ROOT.to_owned()],
        actions: vec![MutationAction::Set],
    }
}

/// The defect this test exists to keep from coming back: a token's narrow
/// grant did not survive `stage_panos_config`, only the device-wide policy.
#[tokio::test]
async fn a_narrowly_granted_token_cannot_stage_outside_its_grant_via_v01_tool() {
    let fixture = fixture(Some(narrow_grant()));
    let bearer = format!("Bearer {}", fixture.secret);

    let body = body_of(&fixture.runtime, stage_config(&bearer, OUTSIDE_GRANT)).await;

    assert!(
        body.contains(GRANT_DENIAL),
        "a token was allowed to stage a write outside its own mutation grant, \
         even though the device policy alone would have permitted it: {body}"
    );
}

/// The same token staging inside its own grant must not be refused for a
/// grant reason (it may still fail for a device-reachability reason, since
/// this fixture points at no real firewall).
#[tokio::test]
async fn a_narrowly_granted_token_may_stage_inside_its_grant() {
    let fixture = fixture(Some(narrow_grant()));
    let bearer = format!("Bearer {}", fixture.secret);

    let body = body_of(
        &fixture.runtime,
        stage_config(
            &bearer,
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='probe']",
        ),
    )
    .await;

    assert!(
        !body.contains(GRANT_DENIAL),
        "a write inside the token's own grant was refused as ungranted: {body}"
    );
}

/// MEC-528 F4: an HTTP token that is permitted to call `stage_panos_config`
/// but whose entry carries no grant at all must be refused before
/// `stage_config`, the same way `create_panos_change_set` already refuses a
/// grantless HTTP caller -- not silently fall through to the device-wide
/// policy alone.
#[tokio::test]
async fn a_grantless_http_token_may_not_stage_via_v01_tool() {
    let fixture = fixture(None);
    let bearer = format!("Bearer {}", fixture.secret);

    let body = body_of(&fixture.runtime, stage_config(&bearer, GRANT_ROOT)).await;

    assert!(
        body.contains(NO_GRANT),
        "a grantless HTTP token was allowed to reach stage_config: {body}"
    );
}
