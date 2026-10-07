//! Full MCP-to-core-to-HTTPS mock path for every Phase 1 tool.

use axum::{
    Router,
    extract::{Form, State},
    http::HeaderMap,
    routing::post,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use rust_panosmcp::PanosMcpServer;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    tools::PanosService,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const KEY: &str = "mcp-e2e-pan-os-key";

#[derive(Default)]
struct MockState {
    requests: AtomicUsize,
    bad_headers: AtomicUsize,
}

struct MockEnvironment;

impl Environment for MockEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_MCP_E2E_KEY").then(|| KEY.to_owned())
    }
}

async fn api(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    state.requests.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("X-PAN-KEY")
        .is_none_or(|value| value.as_bytes() != KEY.as_bytes())
    {
        state.bad_headers.fetch_add(1, Ordering::SeqCst);
    }
    if form.get("type").map(String::as_str) == Some("config") {
        return "<response status=\"success\" code=\"19\"><result><config><devices/></config></result></response>".to_owned();
    }
    "<response status=\"success\" code=\"19\"><result><system><hostname>e2e-fw</hostname><model>PA-VM</model><serial>E2E001</serial><sw-version>11.2.4</sw-version></system></result></response>".to_owned()
}

fn arguments(value: Value) -> Map<String, Value> {
    value.as_object().expect("object arguments").clone()
}

async fn result_json(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    value: Value,
) -> (bool, Value) {
    let result = client
        .call_tool(CallToolRequestParams::new(name).with_arguments(arguments(value)))
        .await
        .expect("MCP tool call");
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .expect("text tool result")
        .text
        .as_str();
    (
        result.is_error.unwrap_or(false),
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned())),
    )
}

#[tokio::test]
async fn all_read_tools_reach_mock_https_and_mutating_op_is_refused() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().expect("temporary test directory");
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let cert_pem = cert.pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.clone().into_bytes(),
        signing_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("TLS config");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTPS mock");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("listener address");
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .route("/api/", post(api))
        .with_state(state.clone());
    let handle = axum_server::Handle::<SocketAddr>::new();
    let server_handle = handle.clone();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .expect("HTTPS server")
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .expect("mock server");
    });
    tokio::task::yield_now().await;

    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, cert_pem).expect("CA file");
    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"policy":{{"mode":"allowlist","allow":["show system info"]}},"devices":[{{"name":"e2e-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_MCP_E2E_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}}}]}}"#,
            address.port(),
            ca_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(inventory_path, &MockEnvironment)
        .expect("validated inventory");
    let handler = PanosMcpServer::new(PanosService::new(inventory).expect("PAN-OS service"));
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let mcp_server = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("MCP server")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("MCP client");

    let (error, devices) = result_json(&client, "list_devices", json!({})).await;
    assert!(!error);
    assert_eq!(devices["devices"][0]["name"], "e2e-fw");
    assert!(devices["devices"][0].get("api_key").is_none());

    let (error, facts) =
        result_json(&client, "gather_device_facts", json!({"device":"e2e-fw"})).await;
    assert!(!error);
    assert_eq!(facts["facts"]["hostname"], "e2e-fw");

    let (error, operation) = result_json(
        &client,
        "execute_panos_op",
        json!({"device":"e2e-fw","command":"<show><system><info/></system></show>"}),
    )
    .await;
    assert!(!error);
    assert_eq!(operation["status"], "success");

    let (error, config) = result_json(
        &client,
        "get_panos_config",
        json!({"device":"e2e-fw","source":"candidate","xpath":"/config/devices"}),
    )
    .await;
    assert!(!error);
    assert_eq!(config["source"], "candidate");

    let (error, device_groups) = result_json(
        &client,
        "list_panorama_device_groups",
        json!({"device":"e2e-fw"}),
    )
    .await;
    assert!(!error);
    assert_eq!(device_groups["device"], "e2e-fw");
    assert_eq!(
        device_groups["device_groups"],
        Value::Array(Vec::new()),
        "mock config response declares no device-group entries"
    );

    let (error, templates) = result_json(
        &client,
        "list_panorama_templates",
        json!({"device":"e2e-fw"}),
    )
    .await;
    assert!(!error);
    assert_eq!(templates["templates"], Value::Array(Vec::new()));

    let before_denial = state.requests.load(Ordering::SeqCst);
    let (error, denial) = result_json(
        &client,
        "execute_panos_op",
        json!({"device":"e2e-fw","command":"<request><restart><system/></restart></request>"}),
    )
    .await;
    assert!(error);
    assert!(
        denial
            .as_str()
            .is_some_and(|text| text.contains("root element must be 'show'"))
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), before_denial);
    assert_eq!(state.bad_headers.load(Ordering::SeqCst), 0);
    assert_eq!(state.requests.load(Ordering::SeqCst), 5);

    client.cancel().await.expect("MCP shutdown");
    mcp_server.abort();
    handle.shutdown();
}
