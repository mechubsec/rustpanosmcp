//! Guarded candidate lifecycle against a deterministic mock PAN-OS XML API.

mod common;

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_auth::{MutationAction, MutationGrant};
use rust_panosmcp_core::{
    inventory::{Environment, Inventory},
    mutation::{
        ApplyChangeSetInput, ApproveChangeSetInput, CandidateFingerprintInput, ChangeSetAction,
        ChangeSetStatusInput, CommitDisposition, CreateChangeSetInput, OperationInput,
        OperationStatusInput, StageAction, StageConfigInput,
    },
    tools::PanosService,
};
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

/// Serializes every test in this binary.
///
/// These tests emit audit events and one of them captures them with a
/// `tracing` subscriber. Audit emission is process-wide, so two tests running
/// concurrently interleave into the same capture and the assertions on it
/// become order-dependent — observed failing at `--test-threads=2` and above
/// while passing at 1. Hold this for the whole test body.
/// Async-aware so the guard can be held across the `await` points that make up
/// each test body; a `std::sync::Mutex` guard cannot cross an await.
static AUDIT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestEnvironment;

impl Environment for TestEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        (name == "PANOS_MUTATION_TEST_KEY").then(|| "fixture-api-key".to_owned())
    }
}

#[derive(Debug)]
struct MockState {
    running: String,
    candidate: String,
    locks_added: usize,
    locks_removed: usize,
    commit_fails: bool,
    lock_release_fails: bool,
    /// Commit requests the mock device received (Percy F4, MEC-352).
    commit_requests: usize,
    /// Overrides `check pending-changes`'s answer regardless of whether
    /// `candidate` differs from `running`.
    ///
    /// Models a foreign edit sitting outside every xpath root this tool
    /// queries via `get`/`show` -- invisible to a per-root fingerprint
    /// comparison, but still a real PAN-OS pending change (Percy F2,
    /// MEC-533).
    pending_changes_override: Option<bool>,
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
        // Real PAN-OS `get` (candidate) carries `total`/`count` on `<result>`
        // and a `code` attribute on `<response>` that `show` does not (Percy
        // F1, MEC-533) -- differing deliberately from the `show` envelope
        // below so a regression that hashes the full envelope instead of
        // asking `check pending-changes` fails loudly again.
        return format!(
            r#"<response status="success" code="19"><result total="1" count="1">{candidate}</result></response>"#
        );
    }
    if request_type == Some("config") && action == Some("show") {
        let running = state.lock().expect("state").running.clone();
        return format!(r#"<response status="success"><result>{running}</result></response>"#);
    }
    if command == "<check><pending-changes></pending-changes></check>" {
        let state = state.lock().expect("state");
        let pending = state
            .pending_changes_override
            .unwrap_or_else(|| state.candidate != state.running);
        return success(&format!(
            "<result>{}</result>",
            if pending { "yes" } else { "no" }
        ));
    }
    if request_type == Some("config") && action == Some("set") {
        state.lock().expect("state").candidate =
            "<config><shared><address><entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry></address></shared></config>".to_owned();
        return success("<result><msg>set complete</msg></result>");
    }
    if request_type == Some("config") && action == Some("delete") {
        state.lock().expect("state").candidate =
            "<config><shared><address/></shared></config>".to_owned();
        return success("<result><msg>delete complete</msg></result>");
    }
    if command.contains("<config-lock><add>") {
        state.lock().expect("state").locks_added += 1;
        return success("<result><msg>lock added</msg></result>");
    }
    if command.contains("<config-lock><remove>") {
        let mut state = state.lock().expect("state");
        if state.lock_release_fails {
            return r#"<response status="error" code="17"><msg><line>mock lock release failed</line></msg></response>"#.to_owned();
        }
        state.locks_removed += 1;
        return success("<result><msg>lock removed</msg></result>");
    }
    if command == "<show><config><list><change-summary/></list></config></show>" {
        return success(
            "<result><journal><entry><xpath>/config/shared/address</xpath><phash>$1$fakesalt$0123456789abcdefghijklmnopqrstuv</phash></entry></journal></result>",
        );
    }
    if command == "<validate><full></full></validate>" {
        return success("<result><job>101</job></result>");
    }
    if request_type == Some("commit") && action == Some("partial") {
        state.lock().expect("state").commit_requests += 1;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        return success("<result><job>102</job></result>");
    }
    if command.contains("<show><jobs><id>101</id>") {
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress><details>validation passed</details></job></result>",
        );
    }
    if command.contains("<show><jobs><id>102</id>") {
        let mut state = state.lock().expect("state");
        if state.commit_fails {
            return success(
                "<result><job><status>FIN</status><result>FAIL</result><progress>100</progress><details>commit refused by mock</details></job></result>",
            );
        }
        state.running = state.candidate.clone();
        return success(
            "<result><job><status>FIN</status><result>OK</result><progress>100</progress><details>commit passed</details></job></result>",
        );
    }
    if command.contains("<revert><config><partial>") {
        let mut state = state.lock().expect("state");
        state.candidate = state.running.clone();
        return success("<result><msg>reverted</msg></result>");
    }
    r#"<response status="error" code="17"><msg><line>unsupported mock request</line></msg></response>"#.to_owned()
}

fn success(inner: &str) -> String {
    format!(r#"<response status="success" code="19">{inner}</response>"#)
}

struct Fixture {
    _directory: tempfile::TempDir,
    inventory_path: std::path::PathBuf,
    state_path: std::path::PathBuf,
    state: Arc<Mutex<MockState>>,
    server: axum_server::Handle<std::net::SocketAddr>,
    service: PanosService,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

async fn fixture(commit_fails: bool, lock_release_fails: bool) -> Fixture {
    fixture_with_direct_commit(commit_fails, lock_release_fails, true).await
}

async fn fixture_with_direct_commit(
    commit_fails: bool,
    lock_release_fails: bool,
    allow_direct_commit: bool,
) -> Fixture {
    fixture_with_options(commit_fails, lock_release_fails, allow_direct_commit, false).await
}

async fn fixture_with_options(
    commit_fails: bool,
    lock_release_fails: bool,
    allow_direct_commit: bool,
    lab_mode: bool,
) -> Fixture {
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
        running: "<config><shared><address/></shared></config>".to_owned(),
        candidate: "<config><shared><address/></shared></config>".to_owned(),
        locks_added: 0,
        locks_removed: 0,
        commit_fails,
        lock_release_fails,
        commit_requests: 0,
        pending_changes_override: None,
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
            r#"{{"version":1,"devices":[{{"name":"mock-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_MUTATION_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}},"mutation":{{"admin":"mcp-admin","allowed_xpath_roots":["/config/shared/address"],"allow_delete":true,"require_config_lock":true}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("mutation inventory");
    let state_path = directory.path().join("mutation-state.json");
    let service = PanosService::new_with_options(
        inventory,
        Some(&state_path),
        lab_mode,
        None,
        false,
        allow_direct_commit,
        None,
    )
    .expect("service");
    Fixture {
        _directory: directory,
        inventory_path,
        state_path,
        state,
        server: handle,
        service,
    }
}

fn persisted_operation(fixture: &Fixture, operation_id: &str) -> serde_json::Value {
    let persisted: serde_json::Value = serde_json::from_slice(
        &fs::read(&fixture.state_path).expect("read persisted mutation state"),
    )
    .expect("parse persisted mutation state");
    persisted["state"]["operations"][operation_id].clone()
}

/// Rebuild a service from the persisted state file, simulating a process
/// restart.
///
/// The state file now carries an advisory lock held for the life of the
/// service that opened it (MEC-533), so a genuine restart -- the old process
/// exiting before the new one starts -- must be modelled by releasing
/// `fixture.service`'s lock first, not by opening a second live instance
/// alongside it. `fixture.service` is replaced with the recovered instance so
/// later calls in the same test keep working against it.
fn recovered_service(fixture: &mut Fixture) -> PanosService {
    let placeholder_inventory =
        Inventory::load_with_environment(&fixture.inventory_path, &TestEnvironment)
            .expect("placeholder inventory");
    let placeholder = PanosService::new(placeholder_inventory).expect("unlocked placeholder");
    drop(std::mem::replace(&mut fixture.service, placeholder));

    let inventory = Inventory::load_with_environment(&fixture.inventory_path, &TestEnvironment)
        .expect("recovered inventory");
    let recovered = PanosService::new_with_options(
        inventory,
        Some(&fixture.state_path),
        false,
        None,
        false,
        true,
        None,
    )
    .expect("recover persistent mutation state");
    fixture.service = recovered.clone();
    recovered
}

#[tokio::test]
async fn change_set_requires_exact_independent_approval_and_applies_as_one_operation() {
    let _serial = AUDIT_SERIAL.lock().await;
    // Set up audit capture for the entire test
    use mecmcp_audit::testutil::CapturingWriter;
    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let mut fixture = fixture(false, false).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let grant = MutationGrant {
        allowed_xpath_roots: vec!["/config/shared/address".to_owned()],
        actions: vec![MutationAction::Set, MutationAction::Delete],
    };
    let planned = fixture
        .service
        .create_change_set(
            CreateChangeSetInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint.clone(),
                actions: vec![
                    ChangeSetAction {
                        action: StageAction::Set,
                        xpath: "/config/shared/address".to_owned(),
                        element: Some(
                            "<entry name=\"one\"><ip-netmask>192.0.2.1</ip-netmask></entry>"
                                .to_owned(),
                        ),
                        destructive_confirmation: None,
                        move_position: None,
                        move_destination: None,
                    },
                    ChangeSetAction {
                        action: StageAction::Set,
                        xpath: "/config/shared/address".to_owned(),
                        element: Some(
                            "<entry name=\"two\"><ip-netmask>192.0.2.2</ip-netmask></entry>"
                                .to_owned(),
                        ),
                        destructive_confirmation: None,
                        move_position: None,
                        move_destination: None,
                    },
                ],
            },
            None,
            "writer",
            Some(&grant),
            CancellationToken::new(),
        )
        .await
        .expect("plan");
    assert_eq!(planned.state, "planned");
    assert_eq!(planned.actions.len(), 2);

    let approval = ApproveChangeSetInput {
        device: "mock-fw".to_owned(),
        change_set_id: planned.change_set_id.clone(),
        expected_digest: planned.digest.clone(),
    };
    assert!(
        fixture
            .service
            .approve_change_set(approval.clone(), None, "writer")
            .await
            .is_err(),
        "self approval must fail"
    );
    let mut wrong = approval.clone();
    wrong.expected_digest = format!("sha256:{}", "0".repeat(64));
    assert!(
        fixture
            .service
            .approve_change_set(wrong, None, "reviewer")
            .await
            .is_err(),
        "digest mismatch must fail"
    );
    // Perform the approval - audit events will be captured. A human
    // principal is required (mecmcp's house rule: a human approves); stdio's
    // implicit ActorType::Unknown, used above where the calls must fail
    // anyway, would be refused here too.
    let reviewer_ctx = rust_panosmcp_auth::CallerContext {
        token_name: "reviewer".to_owned(),
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
    let approved = fixture
        .service
        .approve_change_set(approval, Some(&reviewer_ctx), "reviewer")
        .await
        .expect("independent approval");

    // Extract captured audit output
    let audit_output = {
        let bytes = cap.0.lock().expect("lock audit capture").clone();
        String::from_utf8(bytes).expect("valid UTF-8 audit output")
    };

    // Verify audit contains the critical binding: change_set_id + digest + owner
    // The successful approval is the last audit event with result=ok
    let successful_approval = audit_output
        .lines()
        .rfind(|line| line.contains("approve_panos_change_set") && line.contains("result=ok"))
        .expect("successful approval audit event must exist");

    assert!(
        successful_approval.contains(&planned.change_set_id),
        "audit must contain change_set_id={}, got:\n{}",
        planned.change_set_id,
        successful_approval
    );
    assert!(
        successful_approval.contains(&planned.digest),
        "audit must contain digest={}, got:\n{}",
        planned.digest,
        successful_approval
    );
    assert!(
        successful_approval.contains("owner=writer"),
        "audit must identify the plan owner, got:\n{}",
        successful_approval
    );
    assert!(
        successful_approval.contains("result=ok"),
        "audit must confirm successful approval, got:\n{}",
        successful_approval
    );

    assert_eq!(approved.state, "approved");
    assert_eq!(approved.approver.as_deref(), Some("reviewer"));

    let recovered = recovered_service(&mut fixture);

    let apply = ApplyChangeSetInput {
        device: "mock-fw".to_owned(),
        change_set_id: planned.change_set_id.clone(),
        expected_digest: planned.digest,
        expected_candidate_fingerprint: initial.candidate_fingerprint,
    };
    assert!(
        recovered
            .apply_change_set(
                apply.clone(),
                None,
                "reviewer",
                Some(&grant),
                CancellationToken::new(),
            )
            .await
            .is_err(),
        "only the plan owner may apply"
    );
    let (first_apply, second_apply) = tokio::join!(
        recovered.apply_change_set(
            apply.clone(),
            None,
            "writer",
            Some(&grant),
            CancellationToken::new(),
        ),
        recovered.apply_change_set(
            apply,
            None,
            "writer",
            Some(&grant),
            CancellationToken::new(),
        ),
    );
    assert_ne!(
        first_apply.is_ok(),
        second_apply.is_ok(),
        "an approval must be single-use under concurrent apply"
    );
    let staged = first_apply.or(second_apply).expect("one apply succeeds");
    let status = recovered
        .change_set_status(
            ChangeSetStatusInput {
                device: "mock-fw".to_owned(),
                change_set_id: planned.change_set_id,
            },
            None,
        )
        .await
        .expect("status");
    assert_eq!(status.state, "applied");
    assert_eq!(
        status.operation_id.as_deref(),
        Some(staged.operation_id.as_str())
    );
    let operation_id = staged.operation_id.clone();
    recovered
        .discard_candidate(
            OperationInput {
                device: "mock-fw".to_owned(),
                operation_id: staged.operation_id,
                expected_candidate_fingerprint: staged.candidate_fingerprint,
            },
            "writer",
            None,
            CancellationToken::new(),
        )
        .await
        .expect("discard");
    let persisted = persisted_operation(&fixture, &operation_id);
    assert_eq!(persisted["state"], "discarded");
    assert_eq!(persisted["config_lock_held"], false);
    // Drop this handle's clone of the state-file lock before recovering
    // again -- `fixture.service` holds the other clone, and `recovered_service`
    // only releases the one in `fixture.service`.
    drop(recovered);
    let restarted = recovered_service(&mut fixture);
    assert_eq!(
        restarted
            .operation_status(
                OperationStatusInput {
                    device: "mock-fw".to_owned(),
                    operation_id,
                },
                "writer",
                None
            )
            .await
            .expect("discard status after restart")
            .state,
        "discarded"
    );
}

/// Lab mode auto-approves a change set with a waiver (`approver: null`,
/// `approval_waiver: "lab-mode"`) rather than inventing an approver. `apply`
/// must recognize that waiver as satisfying "independent approval" instead
/// of refusing every lab-mode change set (MEC-2687).
#[tokio::test]
async fn lab_mode_waived_change_set_applies_without_an_approver() {
    let fixture = fixture_with_options(false, false, true, true).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let grant = MutationGrant {
        allowed_xpath_roots: vec!["/config/shared/address".to_owned()],
        actions: vec![MutationAction::Set, MutationAction::Delete],
    };
    let planned = fixture
        .service
        .create_change_set(
            CreateChangeSetInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint.clone(),
                actions: vec![ChangeSetAction {
                    action: StageAction::Set,
                    xpath: "/config/shared/address".to_owned(),
                    element: Some(
                        "<entry name=\"one\"><ip-netmask>192.0.2.1</ip-netmask></entry>".to_owned(),
                    ),
                    destructive_confirmation: None,
                    move_position: None,
                    move_destination: None,
                }],
            },
            None,
            "writer",
            Some(&grant),
            CancellationToken::new(),
        )
        .await
        .expect("lab-mode auto-approval");
    assert_eq!(planned.state, "approved", "lab mode auto-approves");
    assert_eq!(planned.approver, None, "lab mode invents no approver");
    assert_eq!(planned.approval_waiver.as_deref(), Some("lab-mode"));

    let apply = ApplyChangeSetInput {
        device: "mock-fw".to_owned(),
        change_set_id: planned.change_set_id.clone(),
        expected_digest: planned.digest,
        expected_candidate_fingerprint: initial.candidate_fingerprint,
    };
    let staged = fixture
        .service
        .apply_change_set(
            apply,
            None,
            "writer",
            Some(&grant),
            CancellationToken::new(),
        )
        .await
        .expect("a lab-mode waiver must satisfy the independent-approval check");

    let status = fixture
        .service
        .change_set_status(
            ChangeSetStatusInput {
                device: "mock-fw".to_owned(),
                change_set_id: planned.change_set_id,
            },
            None,
        )
        .await
        .expect("status");
    assert_eq!(status.state, "applied");
    assert_eq!(
        status.operation_id.as_deref(),
        Some(staged.operation_id.as_str())
    );
}

/// House rule: a human approves. An agent principal -- distinct from the
/// owner, so separation of duties alone would let this through -- must still
/// be refused as the second approver.
#[tokio::test]
async fn approve_change_set_by_agent_actor_is_refused() {
    let _serial = AUDIT_SERIAL.lock().await;
    let fixture = fixture(false, false).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let grant = MutationGrant {
        allowed_xpath_roots: vec!["/config/shared/address".to_owned()],
        actions: vec![MutationAction::Set, MutationAction::Delete],
    };
    let planned = fixture
        .service
        .create_change_set(
            CreateChangeSetInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
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
            "writer",
            Some(&grant),
            CancellationToken::new(),
        )
        .await
        .expect("plan");

    let agent_ctx = rust_panosmcp_auth::CallerContext {
        token_name: "agent-reviewer".to_owned(),
        devices: rust_panosmcp_auth::ScopeSet::Wildcard,
        tools: rust_panosmcp_auth::ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: rust_panosmcp_auth::ActorType::Agent,
        oidc_subject: None,
        verified_approver: None,
        client_name: None,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
    };
    let result = fixture
        .service
        .approve_change_set(
            ApproveChangeSetInput {
                device: "mock-fw".to_owned(),
                change_set_id: planned.change_set_id,
                expected_digest: planned.digest,
            },
            Some(&agent_ctx),
            "agent-reviewer",
        )
        .await;

    let err = result.expect_err("an agent actor must not be able to approve");
    assert!(
        err.to_string().contains("must be a human principal"),
        "got: {err}"
    );
}

#[tokio::test]
async fn stage_diff_validate_detached_commit_and_discard_are_guarded() {
    let _serial = AUDIT_SERIAL.lock().await;
    let mut fixture = fixture(false, false).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let mismatch = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: "sha256:stale".to_owned(),
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(mismatch.is_err());

    let staged = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let operation = OperationInput {
        device: "mock-fw".to_owned(),
        operation_id: staged.operation_id.clone(),
        expected_candidate_fingerprint: staged.candidate_fingerprint.clone(),
    };
    assert!(
        fixture
            .service
            .commit_candidate(operation.clone(), "token-a", None, CancellationToken::new())
            .await
            .is_err(),
        "commit must refuse an unvalidated operation"
    );
    let diff = fixture
        .service
        .diff_candidate(operation.clone(), "token-a", None, CancellationToken::new())
        .await
        .expect("diff");
    assert!(diff.change_summary.contains("/config/shared/address"));
    // MEC-528 low / MEC-14: change-summary output must go through the same
    // mecmcp-redact pass as read tools, since it echoes device-side XML
    // verbatim.
    assert!(
        !diff.change_summary.contains("$1$fakesalt"),
        "diff_candidate must redact secret material in the change summary, got: {}",
        diff.change_summary
    );
    assert!(diff.change_summary.contains("[REDACTED]"));
    let validated = fixture
        .service
        .validate_candidate(operation.clone(), "token-a", None, CancellationToken::new())
        .await
        .expect("validate");
    assert!(validated.succeeded);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let commit = fixture
        .service
        .commit_candidate(operation, "token-a", None, cancelled)
        .await
        .expect("detached commit");
    assert_eq!(commit.disposition, CommitDisposition::Detached);
    let mut terminal = None;
    for _ in 0..100 {
        let status = fixture
            .service
            .operation_status(
                OperationStatusInput {
                    device: "mock-fw".to_owned(),
                    operation_id: staged.operation_id.clone(),
                },
                "token-a",
                None,
            )
            .await
            .expect("status");
        if status.state == "committed" {
            terminal = Some(status);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(terminal.expect("commit reconciled").job_id.is_some());
    let committed = persisted_operation(&fixture, &staged.operation_id);
    assert_eq!(committed["state"], "committed");
    assert_eq!(committed["config_lock_held"], false);
    assert_eq!(
        recovered_service(&mut fixture)
            .operation_status(
                OperationStatusInput {
                    device: "mock-fw".to_owned(),
                    operation_id: staged.operation_id.clone(),
                },
                "token-a",
                None
            )
            .await
            .expect("commit status after restart")
            .state,
        "committed"
    );

    let current = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");
    let xpath = "/config/shared/address/entry[@name='phase3']".to_owned();
    let deletion = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: current.candidate_fingerprint,
                action: StageAction::Delete,
                xpath: xpath.clone(),
                element: None,
                destructive_confirmation: Some(format!("DELETE {xpath}")),
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("delete stage");
    let deletion_id = deletion.operation_id.clone();
    fixture
        .service
        .discard_candidate(
            OperationInput {
                device: "mock-fw".to_owned(),
                operation_id: deletion.operation_id,
                expected_candidate_fingerprint: deletion.candidate_fingerprint,
            },
            "token-a",
            None,
            CancellationToken::new(),
        )
        .await
        .expect("discard");
    let discarded = persisted_operation(&fixture, &deletion_id);
    assert_eq!(discarded["state"], "discarded");
    assert_eq!(discarded["config_lock_held"], false);
    let state = fixture.state.lock().expect("state");
    assert_eq!(state.candidate, state.running);
    assert_eq!(state.locks_added, state.locks_removed);
}

/// `commit_candidate` on an operation with no `change_set_id` came from
/// `stage_config` directly -- there is no second-principal approval to point
/// to. Without `--allow-direct-commit`, it must be refused before the device
/// is ever touched, identically whether the caller is a stdio session (no
/// context at all) or an authenticated one, and the refusal must be audited.
#[tokio::test]
async fn commit_candidate_without_change_set_is_refused_without_the_flag() {
    let _serial = AUDIT_SERIAL.lock().await;
    use mecmcp_audit::testutil::CapturingWriter;
    let cap = CapturingWriter::default();
    let _guard = common::install_audit_capture(cap.clone());

    let fixture = fixture_with_direct_commit(false, false, false).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
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
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"gate\"><ip-netmask>192.0.2.9</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let operation = OperationInput {
        device: "mock-fw".to_owned(),
        operation_id: staged.operation_id.clone(),
        expected_candidate_fingerprint: staged.candidate_fingerprint.clone(),
    };
    fixture
        .service
        .diff_candidate(operation.clone(), "token-a", None, CancellationToken::new())
        .await
        .expect("diff");
    fixture
        .service
        .validate_candidate(operation.clone(), "token-a", None, CancellationToken::new())
        .await
        .expect("validate");

    let authenticated_ctx = rust_panosmcp_auth::CallerContext {
        token_name: "writer".to_owned(),
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

    // stdio: no caller context at all.
    let stdio_result = fixture
        .service
        .commit_candidate(operation.clone(), "token-a", None, CancellationToken::new())
        .await;
    // "HTTP": an authenticated caller, full scope, human actor -- none of
    // which the gate reads, so it must be refused on the same terms.
    let http_result = fixture
        .service
        .commit_candidate(
            operation,
            "token-a",
            Some(&authenticated_ctx),
            CancellationToken::new(),
        )
        .await;

    for (label, result) in [("stdio", &stdio_result), ("http", &http_result)] {
        let err = result
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{label}: direct-commit must be refused without the flag"));
        assert!(
            err.to_string().contains("allow-direct-commit"),
            "{label}: refusal must name the flag: {err}"
        );
    }

    // The gate refused before the device was touched: the mock firewall must
    // have received zero commit requests (Percy F4, MEC-352).
    assert_eq!(
        fixture.state.lock().expect("state").commit_requests,
        0,
        "a refused direct commit must never reach the device"
    );

    // The refusal is audited as an authorization denial naming the reason,
    // not overwritten into a generic `result=error` (Percy F2, MEC-352).
    let audit_output = {
        let bytes = cap.0.lock().expect("lock audit capture").clone();
        String::from_utf8(bytes).expect("valid UTF-8 audit output")
    };
    let commit_audits: Vec<&str> = audit_output
        .lines()
        .filter(|line| line.contains("tool=commit_panos_candidate"))
        .collect();
    assert_eq!(
        commit_audits.len(),
        2,
        "both the stdio and http commit attempts must be audited: {audit_output}"
    );
    for line in commit_audits {
        assert!(
            line.contains("authorization=denied") && line.contains("direct_commit_disabled"),
            "the refusal must be audited as a denial naming the reason: {line}"
        );
        assert!(
            !line.contains("result=error"),
            "the denial must not be overwritten by the generic error path: {line}"
        );
    }
}

#[tokio::test]
async fn failed_commit_remains_recoverable_by_discard() {
    let _serial = AUDIT_SERIAL.lock().await;
    let fixture = fixture(true, false).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
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
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let operation = OperationInput {
        device: "mock-fw".to_owned(),
        operation_id: staged.operation_id.clone(),
        expected_candidate_fingerprint: staged.candidate_fingerprint.clone(),
    };
    assert!(
        fixture
            .service
            .validate_candidate(operation.clone(), "token-a", None, CancellationToken::new())
            .await
            .expect("validation")
            .succeeded
    );
    let commit = fixture
        .service
        .commit_candidate(operation.clone(), "token-a", None, CancellationToken::new())
        .await
        .expect("terminal failed commit");
    assert_eq!(commit.succeeded, Some(false));
    let status = fixture
        .service
        .operation_status(
            OperationStatusInput {
                device: "mock-fw".to_owned(),
                operation_id: staged.operation_id,
            },
            "token-a",
            None,
        )
        .await
        .expect("status");
    assert_eq!(status.state, "failed");
    fixture
        .service
        .discard_candidate(operation, "token-a", None, CancellationToken::new())
        .await
        .expect("failed commit discard");
    let state = fixture.state.lock().expect("state");
    assert_eq!(state.candidate, state.running);
    assert_eq!(state.locks_added, state.locks_removed);
}

#[tokio::test]
async fn discard_lock_release_failure_is_persisted_as_indeterminate() {
    let _serial = AUDIT_SERIAL.lock().await;
    let mut fixture = fixture(false, true).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
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
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let error = fixture
        .service
        .discard_candidate(
            OperationInput {
                device: "mock-fw".to_owned(),
                operation_id: staged.operation_id.clone(),
                expected_candidate_fingerprint: staged.candidate_fingerprint,
            },
            "token-a",
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("failed lock release must fail discard reconciliation");
    assert!(error.to_string().contains("lock release"));
    let persisted = persisted_operation(&fixture, &staged.operation_id);
    assert_eq!(persisted["state"], "indeterminate");
    assert_eq!(persisted["config_lock_held"], true);
    assert!(
        persisted["details"]
            .as_str()
            .expect("recovery details")
            .contains("discard succeeded but PAN-OS configuration lock release failed")
    );
    let restarted = recovered_service(&mut fixture);
    assert_eq!(
        restarted
            .operation_status(
                OperationStatusInput {
                    device: "mock-fw".to_owned(),
                    operation_id: staged.operation_id,
                },
                "token-a",
                None
            )
            .await
            .expect("indeterminate status after restart")
            .state,
        "indeterminate"
    );
}

#[tokio::test]
async fn committed_job_with_lock_release_failure_requires_reconciliation() {
    let _serial = AUDIT_SERIAL.lock().await;
    let mut fixture = fixture(false, true).await;
    let initial = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
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
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: initial.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"phase3\"><ip-netmask>192.0.2.3</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect("stage");
    let operation = OperationInput {
        device: "mock-fw".to_owned(),
        operation_id: staged.operation_id.clone(),
        expected_candidate_fingerprint: staged.candidate_fingerprint,
    };
    assert!(
        fixture
            .service
            .validate_candidate(operation.clone(), "token-a", None, CancellationToken::new())
            .await
            .expect("validation")
            .succeeded
    );
    let error = fixture
        .service
        .commit_candidate(operation, "token-a", None, CancellationToken::new())
        .await
        .expect_err("successful commit with failed unlock must require reconciliation");
    assert!(error.to_string().contains("lock release"));
    let persisted = persisted_operation(&fixture, &staged.operation_id);
    assert_eq!(persisted["state"], "indeterminate");
    assert_eq!(persisted["config_lock_held"], true);
    assert_eq!(persisted["job_id"], "102");
    assert!(
        persisted["details"]
            .as_str()
            .expect("recovery details")
            .contains("commit succeeded but PAN-OS configuration lock release failed")
    );
    assert_eq!(
        recovered_service(&mut fixture)
            .operation_status(
                OperationStatusInput {
                    device: "mock-fw".to_owned(),
                    operation_id: staged.operation_id,
                },
                "token-a",
                None
            )
            .await
            .expect("indeterminate commit after restart")
            .state,
        "indeterminate"
    );
}

/// A candidate that already diverges from the running configuration --
/// someone else's uncommitted edits sitting in the same candidate, outside
/// this tool's own change tracking -- must refuse `stage_config` and
/// `create_change_set` rather than stack a new change on top of them.
///
/// The caller's `expected_candidate_fingerprint` alone cannot catch this: it
/// is captured by freshly reading the (already dirty) candidate, so it
/// trivially matches. Only a comparison against the running configuration
/// exposes the foreign edit.
#[tokio::test]
async fn dirty_candidate_with_foreign_pending_changes_is_refused() {
    let _serial = AUDIT_SERIAL.lock().await;
    let fixture = fixture(false, false).await;

    // Simulate a foreign admin's uncommitted edit landing directly in the
    // candidate, bypassing this service entirely (e.g. GUI or CLI session).
    fixture.state.lock().expect("state").candidate =
        "<config><shared><address><entry name=\"rogue\"><ip-netmask>192.0.2.9</ip-netmask></entry></address></shared></config>"
            .to_owned();

    // A caller who freshly observes the now-dirty candidate gets a
    // fingerprint that matches it exactly -- the per-operation guard alone
    // would let this through.
    let dirty = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");

    let stage_error = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: dirty.candidate_fingerprint.clone(),
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"legit\"><ip-netmask>192.0.2.10</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("stage_config must refuse a candidate with foreign pending changes");
    assert!(
        stage_error.to_string().contains("pending changes"),
        "refusal must name the dirty candidate: {stage_error}"
    );
    assert_eq!(
        fixture.state.lock().expect("state").candidate,
        "<config><shared><address><entry name=\"rogue\"><ip-netmask>192.0.2.9</ip-netmask></entry></address></shared></config>",
        "a refused stage must not touch the device"
    );

    let change_set_error = fixture
        .service
        .create_change_set(
            CreateChangeSetInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: dirty.candidate_fingerprint,
                actions: vec![ChangeSetAction {
                    action: StageAction::Set,
                    xpath: "/config/shared/address".to_owned(),
                    element: Some(
                        "<entry name=\"legit\"><ip-netmask>192.0.2.10</ip-netmask></entry>"
                            .to_owned(),
                    ),
                    destructive_confirmation: None,
                    move_position: None,
                    move_destination: None,
                }],
            },
            None,
            "token-a",
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err("create_change_set must refuse a candidate with foreign pending changes");
    assert!(
        change_set_error.to_string().contains("pending changes"),
        "refusal must name the dirty candidate: {change_set_error}"
    );
}

/// A foreign edit sitting entirely outside every root this tool manages
/// still lands in the eventual partial commit, because PAN-OS scopes a
/// partial commit by admin, not by xpath (Percy F2, MEC-533).
///
/// The candidate is byte-identical to running under `/config/shared/address`
/// -- the only root this tool ever reads -- so a fingerprint comparison
/// scoped to `allowed_xpath_roots` would see a clean diff and let this
/// through. Only a whole-config `check pending-changes` catches it.
#[tokio::test]
async fn foreign_pending_change_outside_allowed_roots_is_refused() {
    let _serial = AUDIT_SERIAL.lock().await;
    let fixture = fixture(false, false).await;

    // Simulate PAN-OS reporting a pending change (e.g. under `/config/devices`)
    // that this mock's single candidate/running string can't represent
    // directly, since `candidate` and `running` stay equal throughout.
    fixture
        .state
        .lock()
        .expect("state")
        .pending_changes_override = Some(true);

    let clean = fixture
        .service
        .candidate_fingerprint(
            CandidateFingerprintInput {
                device: "mock-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("fingerprint");

    let stage_error = fixture
        .service
        .stage_config(
            StageConfigInput {
                device: "mock-fw".to_owned(),
                expected_candidate_fingerprint: clean.candidate_fingerprint,
                action: StageAction::Set,
                xpath: "/config/shared/address".to_owned(),
                element: Some(
                    "<entry name=\"legit\"><ip-netmask>192.0.2.11</ip-netmask></entry>".to_owned(),
                ),
                destructive_confirmation: None,
                move_position: None,
                move_destination: None,
            },
            "token-a",
            None,
            None,
            CancellationToken::new(),
        )
        .await
        .expect_err(
            "stage_config must refuse when PAN-OS reports pending changes anywhere, \
             even outside the roots this tool queries",
        );
    assert!(
        stage_error.to_string().contains("pending changes"),
        "refusal must name the dirty candidate: {stage_error}"
    );
}

/// Percy F4 (MEC-533 re-review): a second process must not be able to open
/// the same state file while the first is still live. Enforced by
/// `mecmcp_changeset::ChangesetCoordinator`'s own exclusive, whole-lifetime
/// ownership lock (MEC-540) rather than a lock of this crate's own (MEC-1158
/// removed the latter: a second, redundant lock on the same sibling file
/// self-deadlocked against the coordinator's new per-write lock).
#[tokio::test]
async fn second_service_on_the_same_state_file_is_refused() {
    let _serial = AUDIT_SERIAL.lock().await;
    let fixture = fixture(false, false).await;

    let inventory = Inventory::load_with_environment(&fixture.inventory_path, &TestEnvironment)
        .expect("second inventory");
    let second = PanosService::new_with_options(
        inventory,
        Some(&fixture.state_path),
        false,
        None,
        false,
        true,
        None,
    );
    assert!(
        second.is_err(),
        "a second PanosService must not be able to open the same state file while the first is live"
    );
}
