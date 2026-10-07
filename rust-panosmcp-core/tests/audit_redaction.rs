//! Audit redaction test - isolated to avoid global subscriber conflicts.
//!
//! This test calls init_tracing() which sets a process-global subscriber, conflicting
//! with the thread-local routing pattern used by other audit tests. It lives in its own
//! test binary to prevent cross-contamination.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use mecmcp_audit::{AuditConfig, AuditFormat, AuditRedaction, testutil::CapturingWriter};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{CandidateFingerprintInput, StageAction, StageConfigInput},
    observability::init_tracing,
    tools::PanosService,
};
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_AUDIT_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

#[derive(Debug)]
struct MockState {
    candidate: String,
}

async fn api(
    State(state): State<Arc<Mutex<MockState>>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    let request_type = form.get("type").map(String::as_str);
    let action = form.get("action").map(String::as_str);
    let command = form.get("cmd").map(String::as_str).unwrap_or_default();

    if request_type == Some("config") && action == Some("get") {
        let candidate = state.lock().expect("state").candidate.clone();
        return success(&format!("<result>{candidate}</result>"));
    }
    if request_type == Some("config") && action == Some("show") {
        return success("<result><config><shared><address/></shared></config></result>");
    }
    if request_type == Some("config") && action == Some("set") {
        state.lock().expect("state").candidate =
            "<config><shared><address><entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared></config>".to_owned();
        return success("<result><msg>set complete</msg></result>");
    }
    if command.contains("<show><system><info>") {
        return success(
            r#"<result><system><hostname>test-fw</hostname><model>PA-VM</model><sw-version>11.0.0</sw-version><serial>000000000000</serial><ip-address>192.0.2.100</ip-address><uptime>1234567</uptime></system></result>"#,
        );
    }
    if command.contains("<show><session><info>") {
        return success("<result><num-max>8192</num-max></result>");
    }
    if command == "<show><config><list><change-summary/></list></config></show>" {
        return success(
            "<result><journal><entry><xpath>/config/shared/address</xpath></entry></journal></result>",
        );
    }
    if command == "<validate><full></full></validate>" {
        return success("<result><job>101</job></result>");
    }
    if command.contains("<show><jobs><id>101</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result>",
        );
    }
    if command.contains("<show><jobs><id>102</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result>",
        );
    }
    if request_type == Some("commit") && action == Some("partial") {
        return success("<result><job>102</job></result>");
    }
    if command.contains("<revert><config><partial>") {
        return success("<result><msg>reverted</msg></result>");
    }
    if command == "<check><pending-changes></pending-changes></check>" {
        return success("<result>no</result>");
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
}

async fn fixture() -> PanosService {
    let directory = tempfile::tempdir().expect("tempdir");
    let issued = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let cert_path = directory.path().join("ca.pem");
    fs::write(&cert_path, issued.cert.pem()).expect("certificate file");
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        issued.cert.pem().into_bytes(),
        issued.signing_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("server TLS");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let state = Arc::new(Mutex::new(MockState {
        candidate: "<config><shared><address/></shared></config>".to_owned(),
    }));
    let app = Router::new()
        .route("/api/", post(api))
        .with_state(state.clone());
    let handle = axum_server::Handle::new();
    let task_handle = handle.clone();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .expect("TLS server")
            .handle(task_handle)
            .serve(app.into_make_service())
            .await
            .expect("mock server");
    });
    tokio::task::yield_now().await;

    let inventory_path = directory.path().join("devices.json");
    fs::write(
        &inventory_path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_AUDIT_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}},"mutation":{{"admin":"mcp-admin","allowed_xpath_roots":["/config/shared/address"],"allow_delete":true,"require_config_lock":false}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("audit test inventory");
    PanosService::new(inventory).expect("service")
}

#[tokio::test]
async fn redaction_applies_to_newly_audited_tools() {
    // Configure audit with HMAC redaction
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let key_file = temp_dir.path().join("hmac.key");
    fs::write(
        &key_file,
        b"test-redaction-secret-key-for-hmac-pseudonymization",
    )
    .expect("write key");

    let redaction =
        AuditRedaction::parse("devices=hmac", Some(&key_file)).expect("parse redaction policy");

    let cfg = AuditConfig {
        format: AuditFormat::Text,
        audit_log_file: None,
        redaction: Some(redaction),
        journald: false,
        otel: None,
    };
    init_tracing(&cfg).expect("init tracing with redaction");

    // This test uses set_default (thread-local) because init_tracing already installed
    // a global subscriber with redaction config. Thread-local set_default overrides the
    // global one for this thread's capture.
    let cap = CapturingWriter::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_ansi(false)
            .with_target(true)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );

    let service = fixture().await;
    let cancel = CancellationToken::new();

    // Call stage_panos_config, one of the newly-audited mutation tools that carries a device
    let fp = service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await
        .expect("fingerprint");

    let _ = service
        .stage_config(
            StageConfigInput {
                device: "test-fw".to_owned(),
                expected_candidate_fingerprint: fp.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"redaction-test\"><ip-netmask>192.0.2.88</ip-netmask></entry>"
                        .to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "test-owner",
            None,
            None,
            cancel,
        )
        .await;

    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let log = String::from_utf8_lossy(&bytes);

    // Find the stage_panos_config audit event
    let stage_event = log
        .lines()
        .find(|line| line.contains("tool=stage_panos_config"))
        .expect("stage_panos_config audit event must exist");

    // Assert devices field contains HMAC form
    assert!(
        stage_event.contains("devices=hmac:"),
        "stage_panos_config audit event must contain HMAC-redacted device, got:\n{}",
        stage_event
    );

    // Assert devices field does NOT contain plaintext device name
    assert!(
        !stage_event.contains("test-fw"),
        "stage_panos_config audit event must not contain plaintext device name 'test-fw', got:\n{}",
        stage_event
    );
}
