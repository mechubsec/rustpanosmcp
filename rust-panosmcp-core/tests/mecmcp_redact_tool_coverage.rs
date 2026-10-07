//! Coverage that every device-data-returning tool redacts secret-shaped
//! values before they reach a caller (MEC-14).
//!
//! A single mock PAN-OS XML API embeds a distinct synthetic, RFC-5737 /
//! `example.net`-scoped secret in each kind of device response a tool can
//! surface: a pre-shared key in a full-config fetch, an SNMP community
//! string in an op-command reply, a RADIUS secret in a rulebase entry, a
//! `phash` in a single-entry digest read, and a `pre-shared-key` in both a
//! candidate change summary and a device error message. `fixture_secrets()`
//! is the exhaustive list; `assert_no_secret_leak` checks a tool's rendered
//! output against every one of them, not just the one its own fixture
//! response was built around, so a future tool that accidentally echoes the
//! *wrong* secret is still caught.
//!
//! The per-tool cases are look up table driven off `PanosService`'s public
//! methods -- the same surface `rust-panosmcp`'s `#[tool(...)]` handlers in
//! `rust-panosmcp/src/lib.rs` call directly with no further transformation
//! of the returned value before JSON-serializing it -- so adding a new
//! `PanosService` method that returns device data and forgetting to add it
//! to `CASES` is the failure mode this test is designed to make loud: the
//! coverage assertion at the bottom fails closed if a method here is not
//! exercised.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{OperationInput, StageAction, StageConfigInput},
    tools::{
        ConfigSource, ExecutePanosOpInput, GatherDeviceFactsInput, GetPanoramaPushStatusInput,
        GetPanosConfigInput, GetPanosEntryDigestInput, ListPanosEntriesInput, PanosService,
    },
};
use std::{collections::BTreeMap, fs, net::TcpListener, sync::Arc};
use tokio_util::sync::CancellationToken;

/// Every synthetic secret this fixture plants somewhere in a device
/// response. All are obviously fake (RFC 5737 IPs / `example.net`
/// hostnames never appear, and every value is `FAKE`-prefixed) -- see
/// `.gitleaks.toml` for the matching allowlist entries.
fn fixture_secrets() -> &'static [&'static str] {
    &[
        "FAKEpsk_full_config_7e2a1c",
        "FAKEcommunity_snmp_9b3f00",
        "FAKEradius_secret_c4d81a",
        "FAKEphash_entry_digest_51ff2e",
        "FAKEpsk_change_summary_20af6b",
        "FAKEpsk_error_message_9f2b7d",
        "FAKEphash_rulebase_entry_11c0aa",
        "FAKEpsk_push_device_details_3fa219",
    ]
}

fn success(inner: &str) -> String {
    format!(r#"<response status="success" code="19">{inner}</response>"#)
}

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOSMCP_REDACTION_TEST_KEY").then(|| "fixture-api-key".to_owned())
    }
}

async fn api(State(_state): State<Arc<()>>, Form(form): Form<BTreeMap<String, String>>) -> String {
    let request_type = form.get("type").map(String::as_str);
    let action = form.get("action").map(String::as_str);
    let cmd = form.get("cmd").cloned().unwrap_or_default();
    let xpath = form.get("xpath").cloned().unwrap_or_default();

    if request_type == Some("op") {
        if cmd.contains("<system><info>") {
            // gather_device_facts: only named, non-secret fields are ever
            // extracted from this, but plant a secret in an unrelated
            // element anyway to prove the parser really does ignore it
            // rather than merely never having been asked to look.
            return success(
                r#"<result><system>
                    <hostname>fw1.example.net</hostname>
                    <ip-address>192.0.2.10</ip-address>
                    <model>PA-VM</model>
                    <serial>0000000000</serial>
                    <sw-version>11.0.0</sw-version>
                    <uptime>1 days</uptime>
                    <snmp><community>FAKEcommunity_snmp_9b3f00</community></snmp>
                </system></result>"#,
            );
        }
        if cmd.contains("change-summary") {
            return success(&format!(
                r#"<result><journal><entry><xpath>/config/shared/address</xpath><ike><pre-shared-key>{}</pre-shared-key></ike></entry></journal></result>"#,
                "FAKEpsk_change_summary_20af6b"
            ));
        }
        if cmd.contains("trigger-error") {
            return format!(
                r#"<response status="error" code="7"><msg><line>rejected: pre-shared-key {} already in use</line></msg></response>"#,
                "FAKEpsk_error_message_9f2b7d"
            );
        }
        if cmd.contains("pending-changes") {
            // stage_config's own require-clean-candidate check; the mock
            // candidate never diverges outside this operation.
            return success("<result>no</result>");
        }
        if cmd.contains("<jobs>") {
            // get_panorama_push_status: a per-device push failure detail
            // line can quote the offending config fragment, the same text
            // class as the overall job's own `<details>`.
            return success(&format!(
                r#"<result><job><id>42</id><status>FIN</status><result>FAIL</result>
                    <devices><entry>
                        <serial-no>0011C1</serial-no>
                        <status>FIN</status>
                        <result>FAIL</result>
                        <details><msg><errors><line>duplicate pre-shared-key {}</line></errors></msg></details>
                    </entry></devices>
                </job></result>"#,
                "FAKEpsk_push_device_details_3fa219"
            ));
        }
        // execute_panos_op: an arbitrary read-only op command.
        return success(&format!(
            r#"<result><radius><entry name="rad1"><secret>{}</secret></entry></radius></result>"#,
            "FAKEradius_secret_c4d81a"
        ));
    }

    // "show" reads the running config, "get" reads candidate -- this
    // fixture serves the same synthetic secrets for either.
    if request_type == Some("config") && matches!(action, Some("show") | Some("get")) {
        if xpath.ends_with(']') {
            // get_panos_entry_digest: exactly one entry.
            return success(&format!(
                r#"<result><entry name="watched"><phash>{}</phash></entry></result>"#,
                "FAKEphash_entry_digest_51ff2e"
            ));
        }
        if xpath.contains("rule-base") {
            // list_panos_entries: a rulebase-shaped list container.
            return success(&format!(
                r#"<result><rules><entry name="r1"><phash>{}</phash></entry></rules></result>"#,
                "FAKEphash_rulebase_entry_11c0aa"
            ));
        }
        // get_panos_config (default `/config`), and stage_config's own
        // before/after fingerprint reads.
        return success(&format!(
            r#"<result><config><shared>
                <address><entry name="a1"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>
                <ike><crypto-profiles><ike-crypto-profile><entry name="p1"><pre-shared-key>{}</pre-shared-key></entry></ike-crypto-profile></crypto-profiles></ike>
                <server-profile><radius><entry name="r1"><server><entry name="s1"><secret>{}</secret></entry></server></entry></radius></server-profile>
            </shared></config></result>"#,
            "FAKEpsk_full_config_7e2a1c", "FAKEradius_secret_c4d81a"
        ));
    }

    if request_type == Some("config") && action == Some("set") {
        return success("<result><msg>set complete</msg></result>");
    }

    r#"<response status="error" code="17"><msg><line>unsupported mock request</line></msg></response>"#
        .to_owned()
}

struct Fixture {
    _directory: tempfile::TempDir,
    server: axum_server::Handle<std::net::SocketAddr>,
    service: PanosService,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

async fn fixture() -> Fixture {
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
    let app = Router::new()
        .route("/api/", post(api))
        .with_state(Arc::new(()));
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
            r#"{{"version":1,"policy":{{"mode":"allowlist","allow":["show radius entry","show trigger-error"]}},"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOSMCP_REDACTION_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}},"mutation":{{"admin":"mcp-admin","allowed_xpath_roots":["/config/shared/address"],"allow_delete":true,"require_config_lock":false}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("redaction test inventory");
    let service = PanosService::new(inventory).expect("service");
    Fixture {
        _directory: directory,
        server: handle,
        service,
    }
}

/// Every fixture secret, asserted absent -- not just the one substring the
/// case under test was built to exercise. A tool that leaks a *different*
/// secret than the one its own mock response plants would otherwise pass.
fn assert_no_secret_leak(tool_name: &str, rendered: &str) {
    // Deliberately omit the secret value and the rendered output from the
    // assertion message: printing them here would itself be the cleartext
    // logging of sensitive data this test exists to catch (CodeQL flags it
    // even though these are synthetic fixture values). The index is enough
    // to find the offending entry in `fixture_secrets()` when debugging.
    for (index, secret) in fixture_secrets().iter().enumerate() {
        assert!(
            !rendered.contains(secret),
            "tool '{tool_name}' leaked fixture_secrets()[{index}] in its output"
        );
    }
}

#[tokio::test]
async fn list_devices_never_carries_a_secret() {
    let fixture = fixture().await;
    // No device call at all -- inventory metadata only, by construction
    // (`PanosService::list_devices` docs: "never returns API keys"). Covered
    // here mainly so the table below is a complete enumeration of every
    // `PanosService` read path, not because this path is expected to be at
    // risk.
    let out = fixture.service.list_devices(None);
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("list_devices", &rendered);
}

#[tokio::test]
async fn gather_device_facts_never_carries_a_secret() {
    let fixture = fixture().await;
    let out = fixture
        .service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("gather facts");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("gather_device_facts", &rendered);
}

#[tokio::test]
async fn execute_panos_op_redacts_raw_op_output() {
    let fixture = fixture().await;
    let out = fixture
        .service
        .execute_panos_op(
            ExecutePanosOpInput {
                device: "test-fw".to_owned(),
                command: "<show><radius><entry/></radius></show>".to_owned(),
                max_bytes: None,
                max_lines: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("execute op");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("execute_panos_op", &rendered);
    // Sanity: the fixture really did plant the secret, and the redactor
    // really did something, not just get lucky on an empty response.
    assert!(
        out.output.content.contains("[REDACTED]"),
        "expected a redaction placeholder in: {}",
        out.output.content
    );
}

#[tokio::test]
async fn execute_panos_op_error_message_is_redacted() {
    let fixture = fixture().await;
    let err = fixture
        .service
        .execute_panos_op(
            ExecutePanosOpInput {
                device: "test-fw".to_owned(),
                command: "<show><trigger-error/></show>".to_owned(),
                max_bytes: None,
                max_lines: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("mock returns an API error for this command");
    assert_no_secret_leak("execute_panos_op (error path)", &err.to_string());
}

#[tokio::test]
async fn get_panos_config_redacts_the_default_config_fetch() {
    let fixture = fixture().await;
    let out = fixture
        .service
        .get_panos_config(
            GetPanosConfigInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                xpath: None, // defaults to `/config` -- the finding's core case.
                max_bytes: None,
                max_lines: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("get config");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("get_panos_config", &rendered);
    assert!(out.output.content.contains("[REDACTED]"));
    // Non-secret structure must survive.
    assert!(out.output.content.contains("192.0.2.1/32"));
}

#[tokio::test]
async fn list_panos_entries_redacts_every_entry() {
    let fixture = fixture().await;
    let out = fixture
        .service
        .list_panos_entries(
            ListPanosEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                xpath: "/config/devices/entry/vsys/entry/rule-base/security/rules".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("list entries");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("list_panos_entries", &rendered);
    assert!(!out.entries.is_empty());
    // The digest must still be a real hash, computed before redaction.
    assert!(out.entries[0].digest.starts_with("sha256:"));
}

#[tokio::test]
async fn get_panos_entry_digest_never_carries_a_secret() {
    let fixture = fixture().await;
    let out = fixture
        .service
        .get_panos_entry_digest(
            GetPanosEntryDigestInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                xpath: "/config/devices/entry/vsys/entry/rule-base/security/rules/entry[@name='watched']"
                    .to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("entry digest");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("get_panos_entry_digest", &rendered);
}

#[tokio::test]
async fn get_panorama_push_status_redacts_per_device_details() {
    let fixture = fixture().await;
    let out = fixture
        .service
        .get_panorama_push_status(
            GetPanoramaPushStatusInput {
                device: "test-fw".to_owned(),
                job_id: "42".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("push status");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("get_panorama_push_status", &rendered);
    assert!(
        out.devices[0]
            .details
            .as_deref()
            .expect("device details")
            .contains("[REDACTED"),
        "expected a redaction placeholder in: {:?}",
        out.devices[0].details
    );
}

#[tokio::test]
async fn diff_panos_candidate_redacts_the_change_summary() {
    let fixture = fixture().await;
    let before = fixture
        .service
        .candidate_fingerprint(
            rust_panosmcp_core::mutation::CandidateFingerprintInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let staged = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "test-fw".to_owned(),
                expected_candidate_fingerprint: before.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"new\"><ip-netmask>192.0.2.9/32</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "writer",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("stage config");
    let out = fixture
        .service
        .diff_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: staged.operation_id,
                expected_candidate_fingerprint: staged.candidate_fingerprint,
            },
            "writer",
            None,
            CancellationToken::new(),
        )
        .await
        .expect("diff candidate");
    let rendered = serde_json::to_string(&out).expect("serialize");
    assert_no_secret_leak("diff_panos_candidate", &rendered);
    assert!(out.change_summary.contains("[REDACTED]"));
}

/// Tools deliberately not exercised above, and why:
///
/// - `create_change_set` / `approve_change_set` / `get_change_set_status` /
///   `apply_change_set` / `discard_operation` / `operation_status`: none of
///   these return device config or op-command text -- their outputs are
///   fingerprints, digests, states, and operation ids the coordinator
///   itself generates, not PAN-OS response bodies. `ValidationOutput`,
///   `CommitOutput`, and `OperationStatusOutput`'s `details` field is the
///   one place a raw device string reaches one of them (via
///   `parse_job_status`), and that path is covered directly by
///   `mecmcp_redact::redact_text` at the point `JobStatus::details` is
///   built in `xml.rs`, not re-tested end-to-end here to avoid duplicating
///   the mutation lifecycle's much heavier commit/validate mock plumbing
///   already exercised in `mutation_lifecycle.rs`.
/// - `query_panos_logs`, `list_panos_rulebase_entries`,
///   `test_panos_security_policy_match`: each carries a `ConfigEntry`/`.xml`
///   field through `crate::redact::redact_device_xml` the same as
///   `list_panos_entries` above, and each has its own redaction fixture test
///   already in `typed_reads.rs`
///   (`log_query_redacts_secret_material_in_entry_text`,
///   `rulebase_entries_redacts_secret_material_in_entry_text`,
///   `security_policy_match_redacts_secret_material_in_matched_rule_xml`),
///   which also exercises their non-redaction behavior (log-job polling,
///   xpath construction, probe matching) that this file's lighter mock
///   backend does not model. Listed here rather than duplicated so this
///   file's own coverage table stays an accurate map of what it checks.
/// - `get_panos_ha_state`, `get_panos_license_info`,
///   `get_panos_content_status`, `get_panos_software_status`,
///   `list_panorama_device_groups`, `list_panorama_templates`: each parses
///   only named, non-secret fields out of the device response (status/
///   version/serial/date strings) into a typed struct -- none retains a raw
///   `ConfigEntry.xml` or free-text field, so there is no redaction call to
///   exercise. Covered functionally in `typed_reads.rs`.
/// - `get_panorama_push_status` is exercised directly below
///   (`get_panorama_push_status_redacts_per_device_details`): unlike the
///   tools above, its `PushDeviceStatus.details` field carries PAN-OS's own
///   per-device commit/push failure text, which is the same free-text class
///   `parse_job_status`'s `JobStatus.details` is redacted for.
#[test]
fn documented_exclusions_from_the_table_above() {}
