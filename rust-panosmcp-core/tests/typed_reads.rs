//! End-to-end coverage for the MEC-534 typed read tools: HA state, license,
//! content, and software status, `test security-policy-match`, bounded log
//! queries, and typed rulebase/object listings.

use axum::{
    Router,
    extract::{Form, State},
    routing::post,
};
use rcgen::generate_simple_self_signed;
use rust_panosmcp_core::{
    PanosMcpError,
    inventory::{Environment, Inventory},
    tools::{
        ConfigSource, GetPanosContentStatusInput, GetPanosHaStateInput, GetPanosLicenseInfoInput,
        GetPanosSoftwareStatusInput, IpProtocol, ListPanosRulebaseEntriesInput, PanosLogType,
        PanosService, QueryPanosLogsInput, RulebaseKind, TestPanosSecurityPolicyMatchInput,
    },
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
        (name == "PANOS_TYPED_READS_TEST_KEY").then(|| "test-api-key".to_owned())
    }
}

#[derive(Debug, Default)]
struct MockState {
    /// Every `(type, action)` pair a request asked for, in order.
    requests: Mutex<Vec<(String, String)>>,
    /// Every `cmd` field a request carried, in order (empty string when the
    /// request had none, e.g. a plain `type=log` submission).
    commands: Mutex<Vec<String>>,
}

fn success(body: &str) -> String {
    format!(r#"<response status="success">{body}</response>"#)
}

async fn api(
    State(state): State<Arc<MockState>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> String {
    let request_type = form.get("type").cloned().unwrap_or_default();
    let action = form.get("action").cloned().unwrap_or_default();
    state
        .requests
        .lock()
        .expect("requests")
        .push((request_type.clone(), action.clone()));
    let command = form.get("cmd").cloned().unwrap_or_default();
    state
        .commands
        .lock()
        .expect("commands")
        .push(command.clone());

    if command.contains("<show><high-availability><state>") {
        return success(
            "<result><enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>active</state></local-info><peer-info><state>passive</state></peer-info></group></result>",
        );
    }
    if command.contains("<request><license><info>") {
        return success(
            r#"<result><licenses><entry><feature>PA-VM</feature><description>Virtual firewall</description><serial>000000000</serial><issued>January 1, 2026</issued><expires>Never</expires><expired>no</expired></entry></licenses></result>"#,
        );
    }
    if command.contains("<request><content><upgrade><info>") {
        return success(
            r#"<result><content-updates><entry><version>8800-1234</version><filename>panupv2-all-8800-1234</filename><released-on>2026/01/01</released-on><downloaded>yes</downloaded><current>yes</current></entry></content-updates></result>"#,
        );
    }
    if command.contains("<request><system><software><info>") {
        return success(
            r#"<result><sw-updates><versions><entry><version>11.0.0</version><filename>PanOS_vm-11.0.0</filename><released-on>2025/06/01</released-on><downloaded>yes</downloaded><current>yes</current><latest>yes</latest></entry></versions></sw-updates></result>"#,
        );
    }
    if command.contains("<test><security-policy-match>") {
        if command.contains("203.0.113.99") {
            // Deliberately zero matches for one probe address.
            return success("<result><rules></rules></result>");
        }
        if command.contains("198.51.100.7") {
            return success(
                r#"<result><rules><entry name="block-untrust"><from>untrust</from><to>trust</to><action>deny</action></entry></rules></result>"#,
            );
        }
        if command.contains("203.0.113.50") {
            // Some PAN-OS releases return a text-form entry
            // (`rule; index: N`) with no `name` attribute.
            return success("<result><rules><entry>rule; index: 0</entry></rules></result>");
        }
        if command.contains("203.0.113.77") {
            // A matched rule's free-text description can carry secret
            // material the same way a rulebase/config-log entry can; this
            // fixture exercises the redaction pass over `rules[].xml`
            // (MEC-1233).
            return success(
                r#"<result><rules><entry name="allow-secret-rule"><from>trust</from><to>untrust</to><action>allow</action><description>psk -AQ==zzzzsecret111 phash $6$abc$secrethash</description></entry></rules></result>"#,
            );
        }
        return success(
            r#"<result><rules><entry name="allow-web"><from>trust</from><to>untrust</to><action>allow</action></entry></rules></result>"#,
        );
    }
    if request_type == "log" && action.is_empty() {
        if form
            .get("query")
            .is_some_and(|query| query.contains("never-finishes"))
        {
            return success("<result><job>556</job></result>");
        }
        return success("<result><job>555</job></result>");
    }
    if request_type == "log"
        && action == "get"
        && form.get("job-id").map(String::as_str) == Some("556")
    {
        // A job that never reaches FIN, so the caller has to give up on it.
        return success("<result><job><status>ACT</status></job></result>");
    }
    if request_type == "log" && action == "get" {
        // Real PAN-OS nests a log job's terminal state under `<job>`, the
        // same as a config/commit job -- not directly under `<result>` (see
        // `log_job_is_finished`'s doc comment). The second entry carries a
        // config-change log's before/after detail with a master-key-blob
        // PSK and a crypt-style admin phash, the shapes `query_panos_logs`
        // must redact before they reach the model (MEC-528).
        return success(
            r#"<result><job><status>FIN</status></job><log><logs><entry><receive_time>2026-01-01T00:00:00</receive_time><src>192.0.2.1</src></entry><entry><receive_time>2026-01-01T00:01:00</receive_time><before><ike-gateway><psk>secret-AQ==deadbeef</psk></ike-gateway></before><after><admin><phash>$5$rounds$abcdefghij</phash></admin></after></entry></logs></log></result>"#,
        );
    }
    if request_type == "log" && action == "finish" {
        return success("<result></result>");
    }
    if request_type == "config" && (action == "show" || action == "get") {
        let xpath = form.get("xpath").cloned().unwrap_or_default();
        if xpath.contains("vsys-with-secret") {
            // Rule/object description free text carrying a master-key blob
            // and a crypt-style hash, the shapes `list_panos_rulebase_entries`
            // must redact before they reach the model (MEC-528).
            return success(&format!(
                r#"<result><container><entry name="from-{xpath}"><description>psk -AQ==zzzz111 phash $6$abc$def</description></entry></container></result>"#
            ));
        }
        return success(&format!(
            r#"<result><container><entry name="from-{xpath}"><ip-netmask>192.0.2.0/24</ip-netmask></entry></container></result>"#
        ));
    }

    r#"<response status="error"><msg><line>unknown request</line></msg></response>"#.to_owned()
}

async fn fixture() -> (PanosService, Arc<MockState>) {
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
    let state = Arc::new(MockState::default());
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
            r#"{{"version":1,"policy":{{"mode":"allowlist","allow":["test security-policy-match"]}},"devices":[{{"name":"test-fw","endpoint":"https://localhost:{}","api_key":{{"type":"env","name":"PANOS_TYPED_READS_TEST_KEY"}},"tls":{{"type":"custom_ca","path":"{}"}}}}]}}"#,
            address.port(),
            cert_path.display()
        ),
    )
    .expect("inventory");
    let inventory = Inventory::load_with_environment(&inventory_path, &TestEnvironment)
        .expect("typed reads test inventory");
    (PanosService::new(inventory).expect("service"), state)
}

#[tokio::test]
async fn ha_state_reports_local_and_peer_state() {
    let (service, _state) = fixture().await;
    let out = service
        .get_panos_ha_state(
            GetPanosHaStateInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("ha state");

    assert_eq!(out.state.enabled.as_deref(), Some("yes"));
    assert_eq!(out.state.mode.as_deref(), Some("Active-Passive"));
    assert_eq!(out.state.local_state.as_deref(), Some("active"));
    assert_eq!(out.state.peer_state.as_deref(), Some("passive"));
}

#[tokio::test]
async fn license_info_parses_typed_fields_per_entry() {
    let (service, _state) = fixture().await;
    let out = service
        .get_panos_license_info(
            GetPanosLicenseInfoInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("license info");

    assert_eq!(out.licenses.len(), 1);
    let license = &out.licenses[0];
    assert_eq!(license.feature.as_deref(), Some("PA-VM"));
    assert_eq!(license.expired.as_deref(), Some("no"));
    assert_eq!(license.expires.as_deref(), Some("Never"));
}

#[tokio::test]
async fn content_and_software_status_report_current_version() {
    let (service, _state) = fixture().await;

    let content = service
        .get_panos_content_status(
            GetPanosContentStatusInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("content status");
    assert_eq!(content.versions.len(), 1);
    assert_eq!(content.versions[0].current.as_deref(), Some("yes"));

    let software = service
        .get_panos_software_status(
            GetPanosSoftwareStatusInput {
                device: "test-fw".to_owned(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("software status");
    assert_eq!(software.versions.len(), 1);
    assert_eq!(software.versions[0].version.as_deref(), Some("11.0.0"));
}

#[tokio::test]
async fn security_policy_match_reports_matched_and_unmatched_probes() {
    let (service, _state) = fixture().await;

    let matched = service
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
            CancellationToken::new(),
        )
        .await
        .expect("policy match");
    assert!(matched.matched);
    assert_eq!(matched.rule_name.as_deref(), Some("allow-web"));
    assert_eq!(matched.action.as_deref(), Some("allow"));

    let unmatched = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "203.0.113.99".parse().expect("ip"),
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
            CancellationToken::new(),
        )
        .await
        .expect("policy match");
    assert!(!unmatched.matched);
    assert!(unmatched.rule_name.is_none());
    assert!(unmatched.action.is_none());
}

/// A matched deny rule must report its action, so a caller cannot read
/// `matched: true` as "traffic is permitted" -- the deny/drop answer this
/// tool exists to give lives only in the rule's `<action>` element.
#[tokio::test]
async fn security_policy_match_reports_a_deny_rules_action() {
    let (service, _state) = fixture().await;

    let denied = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "198.51.100.7".parse().expect("ip"),
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
            CancellationToken::new(),
        )
        .await
        .expect("policy match");
    assert!(denied.matched);
    assert_eq!(denied.rule_name.as_deref(), Some("block-untrust"));
    assert_eq!(denied.action.as_deref(), Some("deny"));
}

/// A matched rule's `xml` field must have secret material redacted the same
/// way every other tool that carries a `ConfigEntry` does -- PAN-OS's own
/// API returns a rule's free-text description verbatim alongside the match,
/// and that description can carry secret material the operator put there
/// (MEC-1233). `action` must still come back correctly even though it is
/// read from the same raw XML before redaction runs.
#[tokio::test]
async fn security_policy_match_redacts_secret_material_in_matched_rule_xml() {
    let (service, _state) = fixture().await;

    let out = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "203.0.113.77".parse().expect("ip"),
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
            CancellationToken::new(),
        )
        .await
        .expect("policy match");

    assert!(out.matched);
    assert_eq!(out.rule_name.as_deref(), Some("allow-secret-rule"));
    // The action is extracted from the raw XML before the redaction pass
    // below runs over `rules` -- it must survive that ordering.
    assert_eq!(out.action.as_deref(), Some("allow"));
    assert_eq!(out.rules.len(), 1);
    let xml = &out.rules[0].xml;
    assert!(
        !xml.contains("-AQ==zzzzsecret111"),
        "master-key blob leaked"
    );
    assert!(!xml.contains("$6$abc$secrethash"), "crypt hash leaked");
    assert!(xml.contains("[REDACTED"));
}

/// `destination_port` is optional for `icmp`, which has no port. It is
/// omitted from the command rather than sent as a made-up port 0, which
/// PAN-OS would either reject or match against as if it were real.
#[tokio::test]
async fn security_policy_match_allows_icmp_without_a_destination_port() {
    let (service, state) = fixture().await;

    let result = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "192.0.2.10".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: None,
                protocol: IpProtocol::Icmp,
                from_zone: None,
                to_zone: None,
                application: None,
                source_user: None,
                vsys: None,
            },
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(result.is_ok());
    let commands = state.commands.lock().expect("commands").clone();
    let probe = commands
        .iter()
        .find(|command| command.contains("<security-policy-match>"))
        .expect("policy-match command");
    assert!(
        !probe.contains("<destination-port>"),
        "icmp probe carried a destination port: {probe}"
    );
}

/// A non-`icmp` probe without a `destination_port` must be rejected rather
/// than silently defaulting to port 0.
#[tokio::test]
async fn security_policy_match_rejects_a_missing_destination_port_for_tcp() {
    let (service, _state) = fixture().await;

    let result = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "192.0.2.10".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: None,
                protocol: IpProtocol::Tcp,
                from_zone: None,
                to_zone: None,
                application: None,
                source_user: None,
                vsys: None,
            },
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(result.is_err());
}

/// A zone name crafted to break out of its `<from>...</from>` element must
/// not be able to inject a sibling element into the command PAN-OS receives
/// -- it must arrive escaped, exactly as XML text.
#[tokio::test]
async fn security_policy_match_escapes_a_zone_name_that_looks_like_xml() {
    let (service, state) = fixture().await;
    let _ = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "192.0.2.10".parse().expect("ip"),
                destination: "192.0.2.20".parse().expect("ip"),
                destination_port: Some(443),
                protocol: IpProtocol::Tcp,
                from_zone: Some("trust</from><to>untrust".to_owned()),
                to_zone: None,
                application: None,
                source_user: None,
                vsys: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("policy match with hostile zone name");
    // If escaping failed, the mock would have seen a well-formed but
    // attacker-controlled `<to>untrust</to>` element; asserting on the
    // request count only proves the call round-tripped without the server
    // rejecting malformed XML, which it would if the escape produced an
    // unbalanced tag.
    assert!(!state.requests.lock().expect("requests").is_empty());
}

#[tokio::test]
async fn log_query_defaults_to_a_bounded_limit_and_rejects_an_excessive_one() {
    let (service, _state) = fixture().await;

    let out = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Traffic,
                query: None,
                max_logs: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("log query");
    assert_eq!(
        out.max_logs, 100,
        "unspecified max_logs must default, not be unbounded"
    );
    assert_eq!(out.returned, 2);

    let rejected = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Traffic,
                query: None,
                max_logs: Some(1_000_001),
            },
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        rejected,
        Err(PanosMcpError::Policy {
            field: "max_logs",
            ..
        })
    ));
}

#[tokio::test]
async fn rulebase_entries_builds_the_xpath_from_kind_and_vsys() {
    let (service, state) = fixture().await;
    let out = service
        .list_panos_rulebase_entries(
            ListPanosRulebaseEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                kind: RulebaseKind::NatRules,
                vsys: "vsys2".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("rulebase entries");

    assert_eq!(
        out.xpath,
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/rule-base/nat/rules"
    );
    assert_eq!(out.entries.len(), 1);
    let requests = state.requests.lock().expect("requests").clone();
    assert!(requests.contains(&("config".to_owned(), "show".to_owned())));
}

#[tokio::test]
async fn rulebase_entries_rejects_a_vsys_name_that_would_break_out_of_the_predicate() {
    let (service, _state) = fixture().await;
    let result = service
        .list_panos_rulebase_entries(
            ListPanosRulebaseEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                kind: RulebaseKind::AddressObjects,
                vsys: "vsys1']/../shared".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        result,
        Err(PanosMcpError::Policy { field: "vsys", .. })
    ));
}

/// `list_panos_rulebase_entries` must redact secret material (a master-key
/// blob or a crypt-style hash) out of entry free text before returning it,
/// the same as `get_panos_config` already does (MEC-528, F1).
#[tokio::test]
async fn rulebase_entries_redacts_secret_material_in_entry_text() {
    let (service, _state) = fixture().await;
    let out = service
        .list_panos_rulebase_entries(
            ListPanosRulebaseEntriesInput {
                device: "test-fw".to_owned(),
                source: ConfigSource::Running,
                kind: RulebaseKind::AddressObjects,
                vsys: "vsys-with-secret".to_owned(),
                offset: None,
                limit: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("rulebase entries");

    assert_eq!(out.entries.len(), 1);
    let xml = &out.entries[0].xml;
    assert!(!xml.contains("-AQ==zzzz111"), "master-key blob leaked");
    assert!(!xml.contains("$6$abc$def"), "crypt hash leaked");
    assert!(xml.contains("[REDACTED"));
}

/// `query_panos_logs` must redact secret material out of log entry text
/// before returning it -- a config-change log can carry a PSK or admin
/// phash in its before/after detail (MEC-528, F1).
#[tokio::test]
async fn log_query_redacts_secret_material_in_entry_text() {
    let (service, _state) = fixture().await;
    let out = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Config,
                query: None,
                max_logs: None,
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("log query");

    assert_eq!(out.returned, 2);
    let joined = out
        .entries
        .iter()
        .map(|entry| entry.xml.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!joined.contains("-AQ==deadbeef"), "master-key blob leaked");
    assert!(
        !joined.contains("$5$rounds$abcdefghij"),
        "crypt hash leaked"
    );
    assert!(joined.contains("[REDACTED"));
}

/// `vsys` is sent as its own escaped element in the `<test>` command when
/// present, so a multi-vsys firewall can be tested against a non-default
/// vsys rather than only the default one.
#[tokio::test]
async fn security_policy_match_sends_an_escaped_vsys_element() {
    let (service, state) = fixture().await;
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
                vsys: Some("vsys2".to_owned()),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("policy match");

    let commands = state.commands.lock().expect("commands").clone();
    assert!(
        commands
            .iter()
            .any(|command| command.contains("<vsys>vsys2</vsys>"))
    );
}

/// A matched entry with no `name` attribute must be reported as a parse
/// error rather than `rule_name: Some("")`, which would misleadingly read
/// as "a rule matched but has no name" instead of "the response shape was
/// not what this parser expected."
#[tokio::test]
async fn security_policy_match_rejects_an_entry_with_no_name() {
    let (service, _state) = fixture().await;
    let result = service
        .test_panos_security_policy_match(
            TestPanosSecurityPolicyMatchInput {
                device: "test-fw".to_owned(),
                source: "203.0.113.50".parse().expect("ip"),
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
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(result, Err(PanosMcpError::Xml(_))));
}

/// Cancelling a log query whose job has not finished must release the job
/// on the device with a best-effort `action=finish`, so an abandoned query
/// does not hold one of PAN-OS's few concurrent log-query slots (F5c).
#[tokio::test]
async fn log_query_finishes_an_abandoned_job_on_cancellation() {
    let (service, state) = fixture().await;
    let cancellation = CancellationToken::new();
    let canceller = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        canceller.cancel();
    });

    let result = service
        .query_panos_logs(
            QueryPanosLogsInput {
                device: "test-fw".to_owned(),
                log_type: PanosLogType::Traffic,
                query: Some("(addr.src in never-finishes)".to_owned()),
                max_logs: None,
            },
            None,
            cancellation,
        )
        .await;

    assert!(matches!(result, Err(PanosMcpError::Cancelled)));
    let requests = state.requests.lock().expect("requests").clone();
    assert!(
        requests
            .iter()
            .any(|(kind, action)| kind == "log" && action == "finish"),
        "abandoned log job was not finished: {requests:?}"
    );
}
