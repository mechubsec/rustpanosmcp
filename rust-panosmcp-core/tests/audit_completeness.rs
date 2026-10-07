//! Structural audit coverage test: every tool in KNOWN_TOOLS must emit an audit event.
//!
//! This test ensures that adding a new tool to KNOWN_TOOLS without also adding audit
//! coverage causes a loud, named failure listing the missing tool.

mod common;

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use mecmcp_audit::testutil::CapturingWriter;
use rcgen::generate_simple_self_signed;
use rust_panosmcp_auth::{KNOWN_TOOLS, MutationAction, MutationGrant};
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{
        ApproveChangeSetInput, CandidateFingerprintInput, ChangeSetAction, ChangeSetStatusInput,
        CreateChangeSetInput, OperationInput, OperationStatusInput, StageAction, StageConfigInput,
    },
    tools::{
        ConfigSource, ExecutePanosOpInput, GatherDeviceFactsInput, GetPanoramaPushStatusInput,
        GetPanosConfigInput, GetPanosContentStatusInput, GetPanosEntryDigestInput,
        GetPanosHaStateInput, GetPanosLicenseInfoInput, GetPanosSoftwareStatusInput, IpProtocol,
        ListPanoramaDeviceGroupsInput, ListPanoramaTemplatesInput, ListPanosEntriesInput,
        ListPanosRulebaseEntriesInput, PanosLogType, PanosService, QueryPanosLogsInput,
        RulebaseKind, TestPanosSecurityPolicyMatchInput,
    },
};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::TcpListener,
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

// Serialize audit-capturing tests to prevent buffer contamination.
// The tracing subscriber is now process-global via thread-local routing, but these
// tests are #[tokio::test] with default current_thread runtime, so each future stays
// on the thread that installed its thread-local capture. If switched to multi_thread,
// the lock prevents a task from migrating to another thread's capture.
static AUDIT_TEST_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_AUDIT_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

#[derive(Debug)]
struct MockState {
    candidate: String,
    /// Every request form this mock has received, in arrival order -- lets a
    /// test assert on what was actually *sent* (MEC-759 acceptance criterion
    /// 2), not just on what the tool's parsed output contains.
    requests: Vec<BTreeMap<String, String>>,
}

async fn api(
    State(state): State<Arc<Mutex<MockState>>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    state.lock().expect("state").requests.push(form.clone());

    let request_type = form.get("type").map(String::as_str);
    let action = form.get("action").map(String::as_str);
    let command = form.get("cmd").map(String::as_str).unwrap_or_default();

    if request_type == Some("config") && matches!(action, Some("get") | Some("show")) {
        let xpath = form.get("xpath").map(String::as_str).unwrap_or_default();
        if xpath
            == "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='TMPL-1']/variable"
        {
            return success("<result><variable><entry name=\"$v\"/></variable></result>");
        }
        // PAN-OS reports "object not present" for a template with no
        // declared `variable` child at all -- a normal shape, not a failure,
        // that `read_panorama_template_variables` must turn into an empty
        // list rather than propagating the API error.
        if xpath
            == "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='TMPL-NoVars']/variable"
        {
            return r#"<response status="error" code="7"><msg><line>Object is not present</line></msg></response>"#.to_owned();
        }
        // Traps proving MEC-759's read-shape fix: a regression back to a
        // config `get`/`show` on the *whole* device-group/template container
        // would land here and get a fixture carrying a large sibling
        // subtree (a `pre-rulebase` device groups never need, and a full
        // templated zone config templates never need) that the current
        // two-phase read must never request in the first place.
        if xpath.ends_with("/device-group") {
            return success(
                "<result><device-group><entry name=\"DG-1\"><pre-rulebase><security><rules><entry name=\"deny-all\"/></rules></security></pre-rulebase><devices><entry name=\"0011C1\"/></devices></entry></device-group></result>",
            );
        }
        if xpath.ends_with("/template") {
            return success(
                "<result><template><entry name=\"TMPL-1\"><config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><zone><entry name=\"trust\"/></zone></entry></vsys></entry></devices></config><variable><entry name=\"$v\"/></variable></entry></template></result>",
            );
        }
        if action == Some("get") {
            let candidate = state.lock().expect("state").candidate.clone();
            return success(&format!("<result>{candidate}</result>"));
        }
        return success("<result><config><shared><address/></shared></config></result>");
    }
    if command == "<show><devicegroups></devicegroups></show>" {
        return success(
            "<result><devicegroups><entry name=\"DG-1\"><devices><entry name=\"0011C1\"/></devices></entry></devicegroups></result>",
        );
    }
    if command == "<show><templates></templates></show>" {
        // `TMPL-1'bad` proves MEC-759's injection guard: a device-group/
        // template name Panorama itself reports gets interpolated into an
        // xpath predicate this server builds, so a name containing a `'`
        // (which would unbalance that predicate) must be skipped rather than
        // turned into a request at all.
        return success(
            "<result><templates><entry name=\"TMPL-1\"><devices><entry name=\"0011C1\"/></devices></entry><entry name=\"TMPL-NoVars\"/><entry name=\"TMPL-1'bad\"/></templates></result>",
        );
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
    if command.contains("<show><jobs><id>777</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress><devices><entry name=\"0011C1\"><devicename>fw-01</devicename><status>FIN</status><result>OK</result></entry></devices></job></result>",
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
    if command.contains("<show><high-availability><state>") {
        return success("<result><enabled>no</enabled></result>");
    }
    if command.contains("<request><license><info>") {
        return success(
            "<result><licenses><entry><feature>PA-VM</feature><expired>no</expired></entry></licenses></result>",
        );
    }
    if command.contains("<request><content><upgrade><info>") {
        return success(
            "<result><content-updates><entry><version>1</version></entry></content-updates></result>",
        );
    }
    if command.contains("<request><system><software><info>") {
        return success(
            "<result><sw-updates><versions><entry><version>11.0.0</version></entry></versions></sw-updates></result>",
        );
    }
    if command.contains("<test><security-policy-match>") {
        return success(
            "<result><rules><entry name=\"allow-all\"><action>allow</action></entry></rules></result>",
        );
    }
    if request_type == Some("log") && action.is_none() {
        return success("<result><job>103</job></result>");
    }
    if request_type == Some("log") && action == Some("get") {
        return success(
            "<result><status>FIN</status><log><logs><entry><receive_time>now</receive_time></entry></logs></log></result>",
        );
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
}

async fn fixture() -> (PanosService, Arc<Mutex<MockState>>) {
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
        requests: Vec::new(),
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
    (PanosService::new(inventory).expect("service"), state)
}

/// Extract the "tool" field from each audit event in the captured log bytes.
fn extract_tool_names(captured_bytes: &[u8]) -> HashSet<String> {
    String::from_utf8_lossy(captured_bytes)
        .lines()
        .filter_map(|line| {
            if line.contains("tool=") {
                // Extract tool=<name> from the log line
                line.split("tool=")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .map(|s| s.to_owned())
            } else {
                None
            }
        })
        .collect()
}

#[tokio::test]
async fn all_tools_emit_audit_events() {
    let _lock = AUDIT_TEST_LOCK.lock().await;

    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let (service, mock_state) = fixture().await;
    let cancel = CancellationToken::new();

    // Exercise every tool once to trigger audit events
    let _ = service.list_devices(None);

    let _ = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .execute_panos_op(
            ExecutePanosOpInput {
                device: "test-fw".to_owned(),
                command: "<show><session><info></info></session></show>".to_owned(),
                max_bytes: None,
                max_lines: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_config(
            GetPanosConfigInput {
                device: "test-fw".to_owned(),
                xpath: Some("/config/shared/address".to_owned()),
                source: ConfigSource::Running,
                max_bytes: None,
                max_lines: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .list_panos_entries(
            ListPanosEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Candidate,
                xpath: "/config/shared/address".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_entry_digest(
            GetPanosEntryDigestInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Candidate,
                xpath: "/config/shared/address/entry[@name='test']".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let device_groups = service
        .list_panorama_device_groups(
            ListPanoramaDeviceGroupsInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await
        .expect("list_panorama_device_groups");
    assert_eq!(device_groups.device_groups.len(), 1);
    assert_eq!(device_groups.device_groups[0].name, "DG-1");
    assert_eq!(
        device_groups.device_groups[0].member_serials,
        vec!["0011C1".to_owned()]
    );

    let templates = service
        .list_panorama_templates(
            ListPanoramaTemplatesInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await
        .expect("list_panorama_templates");
    assert_eq!(templates.templates.len(), 2);
    assert_eq!(templates.templates[0].name, "TMPL-1");
    assert_eq!(templates.templates[0].variables, vec!["$v".to_owned()]);
    assert_eq!(templates.templates[1].name, "TMPL-NoVars");
    assert_eq!(
        templates.templates[1].variables,
        Vec::<String>::new(),
        "a template with no declared variable child is an empty list, not an error"
    );

    // MEC-759 acceptance criterion 2: assert on the requests actually sent,
    // not just on the parsed output -- the mock offers a full-container
    // `get`/`show` on `/device-group` and `/template` carrying a large
    // sibling subtree (a `pre-rulebase`, a full templated zone config) that
    // the pre-MEC-759 code used to fetch and that would have passed a
    // parse-output-only assertion even with the old, over-broad request.
    let sent_xpaths: Vec<String> = mock_state
        .lock()
        .expect("mock state")
        .requests
        .iter()
        .filter_map(|form| form.get("xpath").cloned())
        .collect();
    assert!(
        !sent_xpaths
            .iter()
            .any(|xpath| xpath.ends_with("/device-group") || xpath.ends_with("/template")),
        "list_panorama_device_groups/list_panorama_templates must never request \
         the whole device-group/template container: sent xpaths were {sent_xpaths:?}"
    );
    assert!(
        sent_xpaths.iter().any(|xpath| xpath
            == "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='TMPL-1']/variable"),
        "list_panorama_templates must read each template's variables via a \
         single-entry, name-qualified xpath: sent xpaths were {sent_xpaths:?}"
    );
    assert!(
        sent_xpaths.iter().any(|xpath| xpath
            == "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='TMPL-NoVars']/variable"),
        "list_panorama_templates must still request a template with no variables: \
         sent xpaths were {sent_xpaths:?}"
    );
    let sent_commands: Vec<String> = mock_state
        .lock()
        .expect("mock state")
        .requests
        .iter()
        .filter_map(|form| form.get("cmd").cloned())
        .collect();
    assert!(sent_commands.contains(&"<show><devicegroups></devicegroups></show>".to_owned()));
    assert!(sent_commands.contains(&"<show><templates></templates></show>".to_owned()));
    // The injection-guard trap above (`TMPL-1'bad`) must never reach a
    // request at all: it is skipped before any xpath is built from it.
    assert!(
        !sent_xpaths.iter().any(|xpath| xpath.contains("TMPL-1'bad")),
        "an unsafe device-group/template name must never be interpolated into \
         a request: sent xpaths were {sent_xpaths:?}"
    );

    let push_status = service
        .get_panorama_push_status(
            GetPanoramaPushStatusInput {
                device: "test-fw".to_owned(),
                job_id: "777".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await
        .expect("get_panorama_push_status");
    assert_eq!(push_status.job.status.as_deref(), Some("FIN"));
    assert_eq!(push_status.devices.len(), 1);

    let _ = service
        .list_panos_rulebase_entries(
            ListPanosRulebaseEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                kind: RulebaseKind::AddressObjects,
                vsys: "vsys1".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_ha_state(
            GetPanosHaStateInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_license_info(
            GetPanosLicenseInfoInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_content_status(
            GetPanosContentStatusInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .get_panos_software_status(
            GetPanosSoftwareStatusInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "192.0.2.10".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: Some(443),
                protocol: IpProtocol::Tcp,
                from_zone: None,
                to_zone: None,
                application: None,
                source_user: None,
                vsys: None,
            },
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Traffic,
                query: None,
                max_logs: None,
            },
            None,
            cancel.clone(),
        )
        .await;

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

    let grant = MutationGrant {
        allowed_xpath_roots: vec!["/config/shared/address".to_owned()],
        actions: vec![MutationAction::Set, MutationAction::Delete],
    };

    let change_set = service
        .create_change_set(
            CreateChangeSetInput {
                device: "test-fw".to_owned(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
                actions: vec![ChangeSetAction {
                    action: StageAction::Set,
                    xpath: "/config/shared/address".to_owned(),
                    element: Some(
                        "<entry name=\"test\"><ip-netmask>192.0.2.1</ip-netmask></entry>"
                            .to_owned(),
                    ),
                    destructive_confirmation: None,
                    move_position: None,
                    move_destination: None,
                }],
            },
            None,
            "owner",
            Some(&grant),
            cancel.clone(),
        )
        .await
        .expect("create_change_set");

    // Approval now requires a human principal (mecmcp's house rule: a human
    // approves), so this needs a real caller context rather than the stdio
    // `None` used elsewhere in this test -- stdio's implicit `ActorType::Unknown`
    // would be refused.
    let approver_ctx = rust_panosmcp_auth::CallerContext {
        token_name: "approver".to_owned(),
        devices: rust_panosmcp_auth::ScopeSet::Wildcard,
        tools: rust_panosmcp_auth::ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: rust_panosmcp_auth::ActorType::Human,
        oidc_subject: None,
        verified_approver: None,
        client_name: None,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
    };
    let _ = service
        .approve_change_set(
            ApproveChangeSetInput {
                device: "test-fw".to_owned(),
                change_set_id: change_set.change_set_id.clone(),
                expected_digest: change_set.digest.clone(),
            },
            Some(&approver_ctx),
            "approver",
        )
        .await;

    let _ = service
        .change_set_status(
            ChangeSetStatusInput {
                device: "test-fw".to_owned(),
                change_set_id: change_set.change_set_id.clone(),
            },
            None,
        )
        .await;

    // Apply produces an operation_id for subsequent lifecycle calls
    let apply_out = service
        .apply_change_set(
            rust_panosmcp_core::mutation::ApplyChangeSetInput {
                device: "test-fw".to_owned(),
                change_set_id: change_set.change_set_id,
                expected_digest: change_set.digest,
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            None,
            "owner",
            Some(&grant),
            cancel.clone(),
        )
        .await
        .expect("apply");

    let _ = service
        .diff_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .validate_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    let _ = service
        .operation_status(
            OperationStatusInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
            },
            "owner",
            None,
        )
        .await;

    // Call stage_config (will fail due to mock, but will emit audit event)
    let _ = service
        .stage_config(
            StageConfigInput {
                device: "test-fw".to_owned(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some("<entry name=\"test\"/>".to_owned()),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "owner",
            None,
            None,
            cancel.clone(),
        )
        .await;

    // Call commit_candidate (will fail, but will emit audit event)
    let _ = service
        .commit_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    // Call discard_candidate (will fail, but will emit audit event)
    let _ = service
        .discard_candidate(
            OperationInput {
                device: "test-fw".to_owned(),
                operation_id: apply_out.operation_id.clone(),
                expected_candidate_fingerprint: fp.candidate_fingerprint.clone(),
            },
            "owner",
            None,
            cancel.clone(),
        )
        .await;

    // Extract audit events
    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let audited_tools = extract_tool_names(&bytes);

    // The skipped `TMPL-1'bad` template is reported in the audit trail
    // rather than the (unchanged) output contract -- MEC-759 acceptance
    // criterion, "skip + report".
    assert!(
        String::from_utf8_lossy(&bytes).contains("skipped_template_names=1"),
        "list_panorama_templates must audit-report a skipped, unsafe template name"
    );

    // Compare with KNOWN_TOOLS
    let expected: HashSet<String> = KNOWN_TOOLS.iter().map(|s| s.to_string()).collect();
    let missing: Vec<_> = expected.difference(&audited_tools).collect();
    let extra: Vec<_> = audited_tools.difference(&expected).collect();

    assert!(
        missing.is_empty(),
        "Tools in KNOWN_TOOLS but not audited: {:?}",
        missing
    );
    assert!(
        extra.is_empty(),
        "Audited tools not in KNOWN_TOOLS: {:?}",
        extra
    );
}

#[tokio::test]
async fn no_double_emission() {
    let _lock = AUDIT_TEST_LOCK.lock().await;

    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let (service, _mock_state) = fixture().await;
    let cancel = CancellationToken::new();

    // Call one already-audited tool
    let _ = service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: "test-fw".to_owned(),
            },
            None,
            cancel,
        )
        .await;

    let bytes = cap.0.lock().expect("lock audit capture").clone();
    let log = String::from_utf8_lossy(&bytes);
    let count = log
        .lines()
        .filter(|line| line.contains("tool=gather_device_facts"))
        .count();

    assert_eq!(
        count, 1,
        "gather_device_facts emitted {} audit events, expected exactly 1",
        count
    );
}
