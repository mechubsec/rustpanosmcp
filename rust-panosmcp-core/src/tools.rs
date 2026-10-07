//! Transport-independent PAN-OS service and read-only tool behavior.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    inventory::{DeviceMetadata, Inventory},
    observability::AuditScope,
    xml::{
        ConfigEntry, ContentVersionEntry, DeviceFacts, DeviceGroupSummary, HaState, JobStatus,
        LicenseEntry, PushDeviceStatus, SoftwareVersionEntry, TemplateSummary,
        collect_text_for_elements, op_command_tag_path, panos_api_code_name, parse_content_entries,
        parse_device_facts, parse_ha_state, parse_job_id, parse_license_entries, parse_log_entries,
        parse_panorama_device_groups_op, parse_panorama_templates_op, parse_push_job_status,
        parse_security_policy_match, parse_software_entries, scan_config_entries,
        validate_read_only_op_command, validate_read_xpath,
    },
};
use mecmcp_policy::{
    CommandAllowlist, CommandDomain, CommandMode, Decision, DomainRules, Policy, RuleSource,
    compile_allowlist_entries, compile_rules, normalize_input,
};
use quick_xml::escape::escape;
use rust_panosmcp_auth::CallerContext;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

const DEFAULT_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_OUTPUT_LINES: usize = 10_000;
const MAX_OUTPUT_LINES: usize = 100_000;
const SYSTEM_INFO_COMMAND: &str = "<show><system><info></info></system></show>";
const HA_STATE_COMMAND: &str =
    "<show><high-availability><state></state></high-availability></show>";
const LICENSE_INFO_COMMAND: &str = "<request><license><info></info></license></request>";
const CONTENT_INFO_COMMAND: &str =
    "<request><content><upgrade><info></info></upgrade></content></request>";
const SOFTWARE_INFO_COMMAND: &str =
    "<request><system><software><info></info></software></system></request>";
const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;
const DEFAULT_LOG_LIMIT: u32 = 100;
const MAX_LOG_LIMIT: u32 = 1_000;
const LOG_JOB_DEADLINE: Duration = Duration::from_secs(120);
/// Maximum accepted PAN-OS log query filter string.
const MAX_LOG_QUERY_BYTES: usize = 4096;
/// Depth, in tag-name-stack entries, at which a list container's `<entry>`
/// children sit below `<response>`: `response`/`result`/`container`/`entry`.
///
/// `pub(crate)`: also used by `mutation::require_move_target_exists` to scan
/// a rulebase container for the live sibling names a `move` action names.
pub(crate) const LIST_CONTAINER_ENTRY_DEPTH: usize = 3;
/// Depth for an XPath that already resolves to a single entry directly under
/// `<result>`: `response`/`result`/`entry`.
const SINGLE_ENTRY_DEPTH: usize = 2;
/// Enumerates Panorama's device groups and their connected-firewall serials
/// in one read-only op command -- runtime state, not the config tree, so the
/// rulebases/address objects nested under the config equivalent structurally
/// cannot appear in the response (MEC-759).
const PANORAMA_DEVICE_GROUPS_OP_COMMAND: &str = "<show><devicegroups></devicegroups></show>";
/// Enumerates Panorama's template names (plus per-firewall commit/connection
/// detail this server discards); see `PANORAMA_DEVICE_GROUPS_OP_COMMAND`.
/// Template *variables* have no op-command equivalent -- they are read per
/// template via `PANORAMA_TEMPLATE_XPATH` below.
const PANORAMA_TEMPLATES_OP_COMMAND: &str = "<show><templates></templates></show>";
/// Panorama's own template container. Fixed, not caller-supplied: only a
/// name reported by Panorama itself (from `PANORAMA_TEMPLATES_OP_COMMAND`)
/// is ever appended as a `[@name='...']` predicate, and that predicate is
/// validated by `validate_read_xpath` before use (MEC-759).
const PANORAMA_TEMPLATE_XPATH: &str =
    "/config/devices/entry[@name='localhost.localdomain']/template";
/// Cap on template variables read back per template; matches the bound the
/// discarded whole-container read used to enforce implicitly.
const MAX_TEMPLATE_VARIABLES: usize = 4096;

/// PAN-OS policy action: only Deny is used (fail-open blocklist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Deny,
}

/// Shared service behind read tools and the guarded candidate lifecycle.
#[derive(Debug, Clone)]
pub struct PanosService {
    inventory: Inventory,
    clients: Arc<BTreeMap<String, Arc<PanosClient>>>,
    pub(crate) mutations: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// SSDF evidence recorder, when the pipeline is configured.
    ///
    /// Held alongside the coordinator because PAN-OS commits through its own
    /// worker rather than `ChangesetCoordinator::commit_operation`, and that
    /// call is the only coordinator path emitting apply intent and the receipt.
    /// Proposal and approval come from the coordinator; execution comes from
    /// here. **Both must share one recorder** -- a different one splits a single
    /// change across two chains, and both halves verify as valid chains.
    pub(crate) evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    /// Config-domain (xpath) deny rules for `get_panos_config`, plus the
    /// commands-domain deny rules for `execute_panos_op` when
    /// `command_policy_mode` is [`CommandMode::Blocklist`]. Both domains
    /// dispatch per-device internally via `mecmcp_policy`'s own
    /// defaults-plus-device-specific merge, so one shared object is
    /// sufficient here. `None` when no device configures any deny rule --
    /// the config domain is fail-open regardless of `command_policy_mode`.
    policy: Option<Arc<Policy<Action>>>,
    /// Resolved authorization model for `execute_panos_op`. Only meaningful
    /// together with `command_allowlists`: `check_command` never gets called
    /// against `policy` under `Allowlist` mode, because
    /// `mecmcp_policy::CommandAllowlist` has no per-device dispatch and
    /// `command_allowlists` provides the equivalent instead.
    command_policy_mode: CommandMode,
    /// Per-device `execute_panos_op` allowlist policy, one entry per
    /// inventory device, each built from the global `policy.allow` /
    /// `policy.allowed_pipes` defaults merged with that device's own
    /// `blocklist.allow` / `blocklist.allowed_pipes` additions. Populated
    /// only when `command_policy_mode` is [`CommandMode::Allowlist`].
    command_allowlists: BTreeMap<String, Arc<Policy<Action>>>,
    pub(crate) allow_plane_owned_writes: bool,
    /// Gate for `commit_candidate` calls with no change_set_id -- committed
    /// with no second-principal approval at all. Refused by default; set via
    /// --allow-direct-commit.
    pub(crate) direct_commit: mecmcp_audit::DirectCommitPolicy,
}

impl PanosService {
    /// Build and validate all pooled device clients before serving requests.
    pub fn new(inventory: Inventory) -> Result<Self> {
        Self::new_with_state(inventory, None, false)
    }

    /// Build clients and optionally restore private mutation/approval state.
    ///
    /// `lab_mode` waives two-person control for single-operator environments;
    /// see the `--lab-mode` flag (mecmcp#94).
    pub fn new_with_state(
        inventory: Inventory,
        state_path: Option<&Path>,
        lab_mode: bool,
    ) -> Result<Self> {
        Self::new_with_options(inventory, state_path, lab_mode, None, false, false, None)
    }

    /// As [`new_with_state`](Self::new_with_state), with an approval TTL override.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        inventory: Inventory,
        state_path: Option<&Path>,
        lab_mode: bool,
        approval_timeout_secs: Option<u64>,
        allow_plane_owned_writes: bool,
        allow_direct_commit: bool,
        evidence: Option<std::sync::Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    ) -> Result<Self> {
        let limits = mecmcp_changeset::OperationLimits {
            max_operations: crate::mutation::MAX_OPERATIONS,
            max_change_sets: crate::mutation::MAX_CHANGE_SETS,
            max_actions_per_set: crate::mutation::MAX_CHANGE_SET_ACTIONS,
            max_change_set_bytes: crate::mutation::MAX_CHANGE_SET_BYTES as u64,
            max_state_bytes: crate::mutation::MAX_STATE_BYTES,
            // mecmcp 0.3.8 added these. Taking the shared defaults rather than
            // inventing PAN-OS constants: this server creates no multi-target
            // change set and stores no preview, so neither limit is reachable
            // from here. Give them product values if that changes.
            ..mecmcp_changeset::OperationLimits::default()
        };
        let approval_ttl = std::time::Duration::from_secs(
            approval_timeout_secs.unwrap_or(crate::mutation::APPROVAL_TTL_SECS),
        );

        // `mecmcp_changeset::ChangesetCoordinator` claims its own exclusive,
        // whole-lifetime ownership lock on the state file before reading it
        // (MEC-540), serializing two processes racing on startup the same
        // way a lock taken here would -- so this no longer takes one of its
        // own. It used to (#205), back when the coordinator had no such
        // guarantee; doing it twice at this path stopped being redundant and
        // started being a self-deadlock once mecmcp 0.25.0 added a *second*,
        // blocking lock of its own on every read-modify-write cycle against
        // the exact same sibling `<state file>.lock`: a lock taken here and
        // held for the service's whole life would never be released for that
        // per-write lock to ever acquire (MEC-1158).
        //
        // PAN-OS keeps the candidate server-side and identifies it by operation
        // id, so a staged operation survives a restart intact — unlike Junos,
        // whose staged handle is a live NETCONF session. Declaring that here lets
        // the coordinator apply it while loading, so memory and the state file are
        // written by one owner. The previous approach rewrote the file after
        // construction and left the two divergent (#72).
        let mut coordinator = mecmcp_changeset::ChangesetCoordinator::load_with_recovery(
            state_path,
            limits,
            approval_ttl,
            lab_mode,
            mecmcp_changeset::StagedRecovery::Retain,
        )
        .map_err(crate::mutation::coord_error)?;
        // `reload` rebuilds from `previous.mutations`, so the recorder attached
        // here survives a SIGHUP without any further plumbing.
        if let Some(recorder) = evidence.clone() {
            coordinator = coordinator.with_evidence(recorder);
        }
        let coordinator = Arc::new(coordinator);

        Self::build(
            inventory,
            coordinator,
            evidence,
            allow_plane_owned_writes,
            allow_direct_commit,
        )
    }

    /// Rebuild clients while retaining in-flight mutation state across atomic reload.
    pub fn reload(inventory: Inventory, previous: &Self) -> Result<Self> {
        Self::build(
            inventory,
            previous.mutations.clone(),
            // The same recorder the previous service used: reload must not
            // start a second chain for one writer.
            previous.evidence.clone(),
            previous.allow_plane_owned_writes,
            previous.direct_commit.is_allowed(),
        )
    }

    fn build(
        inventory: Inventory,
        mutations: Arc<mecmcp_changeset::ChangesetCoordinator>,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        allow_plane_owned_writes: bool,
        allow_direct_commit: bool,
    ) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for device in inventory.entries() {
            let client = Arc::new(PanosClient::new(device)?);
            clients.insert(client.device_name().to_owned(), client);
        }

        let command_policy_mode = CommandMode::from(inventory.policy_mode());
        let policy = Self::build_deny_policy(&inventory, command_policy_mode)?;
        let command_allowlists = Self::build_command_allowlists(&inventory, command_policy_mode)?;

        Ok(Self {
            inventory,
            clients: Arc::new(clients),
            mutations,
            evidence,
            policy: policy.map(Arc::new),
            command_policy_mode,
            command_allowlists,
            allow_plane_owned_writes,
            direct_commit: mecmcp_audit::DirectCommitPolicy::new(allow_direct_commit),
        })
    }

    /// `/readyz` probe: `Err` once any device's most recent PAN-OS request
    /// came back unauthorized or session-timed-out (see
    /// [`crate::client::PanosClient::is_auth_healthy`]).
    ///
    /// A device that has made no request yet reports healthy -- readiness
    /// reflects proven auth failure, not silence.
    pub fn auth_health_check(&self) -> std::result::Result<(), &'static str> {
        if self.clients.values().all(|client| client.is_auth_healthy()) {
            Ok(())
        } else {
            Err("PAN-OS authentication failed for one or more devices")
        }
    }

    /// Build the shared deny-pattern policy: the config (xpath) domain
    /// always, plus the commands domain when `mode` is
    /// [`CommandMode::Blocklist`]. `None` when neither domain has a rule --
    /// both are fail-open, so an absent policy is equivalent to an empty one.
    fn build_deny_policy(
        inventory: &Inventory,
        mode: CommandMode,
    ) -> Result<Option<Policy<Action>>> {
        let mut commands_domain = DomainRules::default();
        let mut config_domain = DomainRules::default();

        let mut has_any_rules = false;

        for device in inventory.entries() {
            if let Some(blocklist) = &device.blocklist {
                if mode == CommandMode::Blocklist && !blocklist.commands.is_empty() {
                    has_any_rules = true;
                    let rules: Vec<(Action, String)> = blocklist
                        .commands
                        .iter()
                        .map(|pattern| (Action::Deny, pattern.clone()))
                        .collect();
                    let compiled = compile_rules(
                        &rules,
                        &device.metadata.name,
                        RuleSource::Device,
                        |scope, pattern, error| {
                            PanosMcpError::Inventory(format!(
                                "device '{scope}' blocklist command pattern '{pattern}' is invalid: {error}"
                            ))
                        },
                    )?;
                    commands_domain
                        .device_specific
                        .insert(device.metadata.name.clone(), compiled);
                }

                if !blocklist.xpath.is_empty() {
                    has_any_rules = true;
                    // Canonicalise the operator's pattern to the same quote
                    // style `get_panos_config` canonicalises the candidate
                    // xpath to before matching, so a rule written with `'`
                    // still catches a request spelled with `"` (MEC-528
                    // class 3), then escape the glob metacharacters an XPath
                    // predicate is made of but does not mean as wildcards
                    // (see `escape_xpath_glob_metacharacters`).
                    let mut rules: Vec<(Action, String)> =
                        Vec::with_capacity(blocklist.xpath.len());
                    for pattern in &blocklist.xpath {
                        // MEC-528 F2: `escape_xpath_glob_metacharacters` also
                        // escapes a literal `\` (globset's own escape
                        // character) so it cannot combine with an adjacent
                        // `[`/`]`/`?` it did not intend to escape. That is
                        // correct for a pattern with no `\` in it, but it
                        // silently mangles a pattern an operator hand-escaped
                        // themselves (`\[` meant as a literal bracket):
                        // double-escaping turns it into something that
                        // matches a different, narrower or wider, set of
                        // xpaths than either the operator or this function
                        // intended -- a blocklist rule that fails open with
                        // no error at load time. Reject it instead: `\` has
                        // no meaning in an XPath predicate, so a rule cannot
                        // legitimately need one.
                        if pattern.contains('\\') {
                            return Err(PanosMcpError::Inventory(format!(
                                "device '{}' blocklist xpath pattern '{pattern}' must not contain '\\'",
                                device.metadata.name
                            )));
                        }
                        let canonical = rust_panosmcp_auth::canonicalize_xpath_quotes(pattern);
                        rules.push((Action::Deny, escape_xpath_glob_metacharacters(&canonical)));
                    }
                    let compiled = compile_rules(
                        &rules,
                        &device.metadata.name,
                        RuleSource::Device,
                        |scope, pattern, error| {
                            PanosMcpError::Inventory(format!(
                                "device '{scope}' blocklist xpath pattern '{pattern}' is invalid: {error}"
                            ))
                        },
                    )?;
                    config_domain
                        .device_specific
                        .insert(device.metadata.name.clone(), compiled);
                }
            }
        }

        if has_any_rules {
            // `mode` only matters to the commands domain (config is always
            // fail-open blocklist regardless of CommandMode); passing it
            // through keeps this object internally consistent even though
            // `execute_panos_op` never calls `check_command` on it in
            // Allowlist mode (see `command_allowlists`).
            Ok(Some(Policy::new(
                mode,
                CommandDomain {
                    blocklist: commands_domain,
                    allowlist: CommandAllowlist::default(),
                },
                config_domain,
                CommandDomain::default(), // PAN-OS has no PFE commands
            )))
        } else {
            Ok(None)
        }
    }

    /// Build one [`Policy`] per inventory device for `execute_panos_op`'s
    /// fail-closed allowlist, merging the global `policy.allow` /
    /// `policy.allowed_pipes` defaults with that device's own
    /// `blocklist.allow` / `blocklist.allowed_pipes` additions -- the same
    /// defaults-plus-device-specific shape the deny-rule domains use.
    ///
    /// `mecmcp_policy::CommandAllowlist` has no per-device dispatch within a
    /// single `Policy` (unlike the deny-rule `DomainRules`), so a shared
    /// object can't hold per-device allow entries; building one compiled
    /// `Policy` per device is the workaround. Returns an empty map when
    /// `mode` is [`CommandMode::Blocklist`] -- `execute_panos_op` never
    /// consults it in that mode.
    fn build_command_allowlists(
        inventory: &Inventory,
        mode: CommandMode,
    ) -> Result<BTreeMap<String, Arc<Policy<Action>>>> {
        let mut policies = BTreeMap::new();
        if mode != CommandMode::Allowlist {
            return Ok(policies);
        }

        for device in inventory.entries() {
            let mut allow = inventory.policy_allow_defaults().to_vec();
            let mut allowed_pipes = inventory.policy_allowed_pipes_defaults().to_vec();
            if let Some(blocklist) = &device.blocklist {
                allow.extend(blocklist.allow.iter().cloned());
                allowed_pipes.extend(blocklist.allowed_pipes.iter().cloned());
            }

            let scope = &device.metadata.name;
            let entries = compile_allowlist_entries(&allow, scope, |scope, entry, kind| {
                PanosMcpError::Inventory(format!(
                    "device '{scope}' policy.allow entry '{entry}' is invalid: {kind:?}"
                ))
            })?;
            let allowed_pipe_entries =
                compile_allowlist_entries(&allowed_pipes, scope, |scope, entry, kind| {
                    PanosMcpError::Inventory(format!(
                        "device '{scope}' policy.allowed_pipes entry '{entry}' is invalid: {kind:?}"
                    ))
                })?;

            let policy = Policy::new(
                CommandMode::Allowlist,
                CommandDomain {
                    blocklist: DomainRules::default(),
                    allowlist: CommandAllowlist {
                        entries,
                        allowed_pipes: allowed_pipe_entries,
                    },
                },
                DomainRules::default(),
                CommandDomain::default(),
            );
            policies.insert(device.metadata.name.clone(), Arc::new(policy));
        }

        Ok(policies)
    }

    /// Return only non-secret inventory metadata in stable name order.
    #[must_use]
    pub fn list_devices(&self, ctx: Option<&CallerContext>) -> ListDevicesOutput {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(ctx, "list_devices", "list", vec![]),
            None => AuditScope::stdio("list_devices", "list", vec![]),
        };
        let result = ListDevicesOutput {
            devices: self.inventory.metadata(),
        };
        audit.meta("device_count", result.devices.len() as u64);
        audit.succeed();
        result
    }

    /// Gather selected facts via the documented `show system info` command.
    pub async fn gather_device_facts(
        &self,
        input: GatherDeviceFactsInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GatherDeviceFactsOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "gather_device_facts",
                "gather-facts",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "gather_device_facts",
                "gather-facts",
                vec![input.device.clone()],
            ),
        };
        let client = self.client(&input.device)?;
        let response = match client.operational(SYSTEM_INFO_COMMAND, cancellation).await {
            Ok(r) => r,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let facts = match parse_device_facts(&response) {
            Ok(f) => f,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let advisories: Vec<String> = facts
            .software_version
            .as_deref()
            .and_then(crate::version_advisory::cve_2026_0310_warning)
            .into_iter()
            .collect();
        if let Some(warning) = advisories.first() {
            audit.meta("version_advisory", warning.clone());
        }
        audit.succeed();
        Ok(GatherDeviceFactsOutput {
            device: input.device,
            facts,
            advisories,
        })
    }

    /// Execute an explicitly read-only `<show>` operational command.
    pub async fn execute_panos_op(
        &self,
        input: ExecutePanosOpInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<XmlToolOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "execute_panos_op",
                "show-op",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("execute_panos_op", "show-op", vec![input.device.clone()]),
        };
        let result = async {
            validate_read_only_op_command(&input.command)?;
            self.check_command_policy(&input.device, &input.command)?;

            let limits = OutputLimits::resolve(input.max_bytes, input.max_lines)?;
            let client = self.client(&input.device)?;
            let response = client.operational(&input.command, cancellation).await?;
            let redacted_xml = crate::redact::redact_device_xml(&response.xml);
            Ok(XmlToolOutput {
                device: input.device,
                status: response.status,
                code: response.code,
                output: bounded_text(&redacted_xml, limits),
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read running or candidate configuration under `/config`.
    pub async fn get_panos_config(
        &self,
        input: GetPanosConfigInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ConfigToolOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_config",
                "get-config",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("get_panos_config", "get-config", vec![input.device.clone()]),
        };
        let result = async {
            let xpath = input.xpath.unwrap_or_else(|| "/config".to_owned());
            validate_read_xpath(&xpath)?;
            self.check_xpath_policy(&input.device, &xpath)?;

            let limits = OutputLimits::resolve(input.max_bytes, input.max_lines)?;
            let client = self.client(&input.device)?;
            let response = client
                .configuration(
                    input.source == ConfigSource::Candidate,
                    &xpath,
                    cancellation,
                )
                .await?;
            let redacted_xml = crate::redact::redact_device_xml(&response.xml);
            Ok(ConfigToolOutput {
                device: input.device,
                source: input.source,
                xpath,
                status: response.status,
                code: response.code,
                output: bounded_text(&redacted_xml, limits),
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read entries from a list container without materializing the whole
    /// thing: a response over the byte cap is truncated and marked rather
    /// than refused, and only the requested `[offset, offset + limit)` window
    /// is decoded into owned strings.
    pub async fn list_panos_entries(
        &self,
        input: ListPanosEntriesInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ListPanosEntriesOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "list_panos_entries",
                "list-entries",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "list_panos_entries",
                "list-entries",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            validate_read_xpath(&input.xpath)?;
            self.check_xpath_policy(&input.device, &input.xpath)?;

            let offset = input.offset.unwrap_or(0);
            let limit = input.limit.unwrap_or(DEFAULT_LIST_LIMIT);
            if limit == 0 || limit > MAX_LIST_LIMIT {
                return Err(PanosMcpError::Policy {
                    field: "limit",
                    reason: format!("value must be between 1 and {MAX_LIST_LIMIT}"),
                });
            }

            let client = self.client(&input.device)?;
            let (bytes, response_truncated) = client
                .configuration_entries(
                    input.source == ConfigSource::Candidate,
                    &input.xpath,
                    cancellation,
                )
                .await?;
            let mut scan = scan_config_entries(&bytes, offset, limit, LIST_CONTAINER_ENTRY_DEPTH)?;
            ensure_scan_success(&input.device, &bytes, &scan)?;

            // Each entry's `digest` is computed by `scan_config_entries` from
            // the untouched device bytes above -- drift detection must stay
            // keyed to what PAN-OS actually sent. Only the human/model-facing
            // `xml` copy is redacted, after that digest already exists.
            for entry in &mut scan.entries {
                entry.xml = crate::redact::redact_device_xml(&entry.xml);
            }

            let returned = scan.entries.len();
            Ok(ListPanosEntriesOutput {
                device: input.device,
                source: input.source,
                xpath: input.xpath,
                entries: scan.entries,
                offset,
                limit,
                returned,
                total_entries: scan.total_seen,
                truncated: response_truncated
                    || scan.truncated
                    || offset + returned < scan.total_seen,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// List Panorama device groups and their member firewall serials.
    ///
    /// Reads Panorama's own runtime state via `<show><devicegroups/></show>`
    /// rather than a config `get` on the whole `device-group` container: the
    /// op response already nests each group's connected serials, and
    /// rulebases/address objects/etc. structurally cannot appear in an
    /// operational response the way they would in that container's full
    /// config subtree (MEC-759).
    pub async fn list_panorama_device_groups(
        &self,
        input: ListPanoramaDeviceGroupsInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ListPanoramaDeviceGroupsOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "list_panorama_device_groups",
                "list-device-groups",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "list_panorama_device_groups",
                "list-device-groups",
                vec![input.device.clone()],
            ),
        };
        let client = match self.client(&input.device) {
            Ok(client) => client,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let response = match client
            .operational(PANORAMA_DEVICE_GROUPS_OP_COMMAND, cancellation)
            .await
        {
            Ok(response) => response,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let device_groups = match parse_panorama_device_groups_op(&response) {
            Ok(device_groups) => device_groups,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        audit.succeed();
        Ok(ListPanoramaDeviceGroupsOutput {
            device: input.device,
            device_groups,
        })
    }

    /// List Panorama templates and their declared variable names.
    ///
    /// Two-phase read (MEC-759): names come from the read-only op command
    /// `<show><templates/></show>`, which reports per-firewall commit and
    /// connection history rather than a template's declared variables --
    /// those are config-only, so each name is then re-queried with a
    /// single-entry config `get` scoped to exactly that template's
    /// `/variable` child. Because the xpath ends at `variable`, PAN-OS never
    /// emits that template's rulebase/interface/zone/etc. config alongside
    /// it -- the same narrowing `get_panos_entry_digest` relies on for a
    /// single rule or object.
    pub async fn list_panorama_templates(
        &self,
        input: ListPanoramaTemplatesInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ListPanoramaTemplatesOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "list_panorama_templates",
                "list-templates",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "list_panorama_templates",
                "list-templates",
                vec![input.device.clone()],
            ),
        };
        let client = match self.client(&input.device) {
            Ok(client) => client,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let response = match client
            .operational(PANORAMA_TEMPLATES_OP_COMMAND, cancellation.clone())
            .await
        {
            Ok(response) => response,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };
        let names = match parse_panorama_templates_op(&response) {
            Ok(names) => names,
            Err(e) => {
                audit.fail(&e);
                return Err(e);
            }
        };

        let mut templates = Vec::with_capacity(names.len());
        // Skipped rather than failing the whole call: a name Panorama itself
        // reported that cannot be safely turned into an xpath predicate
        // (MEC-759's injection guard -- see `read_panorama_template_variables`).
        let mut skipped_names: u64 = 0;
        for name in names {
            match self
                .read_panorama_template_variables(&input.device, &name, cancellation.clone())
                .await
            {
                Ok(Some(variables)) => templates.push(TemplateSummary { name, variables }),
                Ok(None) => skipped_names += 1,
                Err(e) => {
                    audit.fail(&e);
                    return Err(e);
                }
            }
        }
        if skipped_names > 0 {
            audit.meta("skipped_template_names", skipped_names);
        }
        audit.succeed();
        Ok(ListPanoramaTemplatesOutput {
            device: input.device,
            templates,
        })
    }

    /// Read one template's declared variable *names* via a single-entry
    /// config `get` scoped to its `/variable` child.
    ///
    /// `Ok(None)` means `template_name` -- reported by Panorama itself, not
    /// caller-supplied -- failed the same xpath-predicate validation every
    /// other read-only xpath in this server is held to; the caller skips
    /// that one template rather than failing the whole list (MEC-759's
    /// injection guard: a name containing `'`/`"` would unbalance the
    /// predicate `validate_read_xpath` builds around it). PAN-OS reporting
    /// "object not present"/"object not found" for a template with no
    /// declared variables is a normal shape, not a failure, and reported as
    /// an empty list.
    async fn read_panorama_template_variables(
        &self,
        device: &str,
        template_name: &str,
        cancellation: CancellationToken,
    ) -> Result<Option<Vec<String>>> {
        let xpath = format!("{PANORAMA_TEMPLATE_XPATH}/entry[@name='{template_name}']/variable");
        if validate_read_xpath(&xpath).is_err() {
            return Ok(None);
        }
        self.check_xpath_policy(device, &xpath)?;

        let client = self.client(device)?;
        let response = match client.configuration(false, &xpath, cancellation).await {
            Ok(response) => response,
            Err(PanosMcpError::Api { code: 7 | 13, .. }) => return Ok(Some(Vec::new())),
            Err(e) => return Err(e),
        };
        let scan = scan_config_entries(
            response.xml.as_bytes(),
            0,
            MAX_TEMPLATE_VARIABLES,
            LIST_CONTAINER_ENTRY_DEPTH,
        )?;
        Ok(Some(
            scan.entries.into_iter().map(|entry| entry.name).collect(),
        ))
    }

    /// Read a Panorama push (`CommitAll`) job's overall and per-device status.
    pub async fn get_panorama_push_status(
        &self,
        input: GetPanoramaPushStatusInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<PanoramaPushStatusOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panorama_push_status",
                "get-push-status",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panorama_push_status",
                "get-push-status",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let client = self.client(&input.device)?;
            let response = client.job_response(&input.job_id, cancellation).await?;
            let status = parse_push_job_status(&response)?;
            Ok(PanoramaPushStatusOutput {
                device: input.device,
                job_id: input.job_id,
                job: status.job,
                devices: status.devices,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Digest one entry by its exact XPath, without reading anything else.
    ///
    /// Meant for drift checks on a single rule or object: unlike
    /// `get_candidate_fingerprint`, which hashes every operator-authorized
    /// write root to detect any change, this issues one request scoped to
    /// the caller's entry and says only whether *that* entry's XML changed.
    pub async fn get_panos_entry_digest(
        &self,
        input: GetPanosEntryDigestInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GetPanosEntryDigestOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_entry_digest",
                "entry-digest",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_entry_digest",
                "entry-digest",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            validate_read_xpath(&input.xpath)?;
            if !input.xpath.ends_with(']') {
                return Err(PanosMcpError::Policy {
                    field: "xpath",
                    reason: "must select exactly one entry via a [@name='...'] predicate"
                        .to_owned(),
                });
            }
            self.check_xpath_policy(&input.device, &input.xpath)?;

            let client = self.client(&input.device)?;
            let response = client
                .configuration(
                    input.source == ConfigSource::Candidate,
                    &input.xpath,
                    cancellation,
                )
                .await?;
            let scan = scan_config_entries(response.xml.as_bytes(), 0, 1, SINGLE_ENTRY_DEPTH)?;
            match scan.entries.into_iter().next() {
                Some(entry) => Ok(GetPanosEntryDigestOutput {
                    device: input.device,
                    source: input.source,
                    xpath: input.xpath,
                    found: true,
                    name: Some(entry.name),
                    digest: Some(entry.digest),
                }),
                None => Ok(GetPanosEntryDigestOutput {
                    device: input.device,
                    source: input.source,
                    xpath: input.xpath,
                    found: false,
                    name: None,
                    digest: None,
                }),
            }
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read HA state via the documented `show high-availability state` command.
    ///
    /// All fields are `None` on a standalone device: PAN-OS omits `<group>`
    /// entirely rather than reporting a "not HA" state, so absence here is a
    /// valid answer, not a partial failure.
    pub async fn get_panos_ha_state(
        &self,
        input: GetPanosHaStateInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GetPanosHaStateOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_ha_state",
                "ha-state",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("get_panos_ha_state", "ha-state", vec![input.device.clone()]),
        };
        let result = async {
            let client = self.client(&input.device)?;
            let response = client.operational(HA_STATE_COMMAND, cancellation).await?;
            let state = parse_ha_state(&response)?;
            Ok(GetPanosHaStateOutput {
                device: input.device,
                state,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read license status via the documented `request license info` command.
    pub async fn get_panos_license_info(
        &self,
        input: GetPanosLicenseInfoInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GetPanosLicenseInfoOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_license_info",
                "license-info",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_license_info",
                "license-info",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let client = self.client(&input.device)?;
            let response = client.fixed_op(LICENSE_INFO_COMMAND, cancellation).await?;
            let licenses = parse_license_entries(&response)?;
            Ok(GetPanosLicenseInfoOutput {
                device: input.device,
                licenses,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read content version status via `request content upgrade info`.
    pub async fn get_panos_content_status(
        &self,
        input: GetPanosContentStatusInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GetPanosContentStatusOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_content_status",
                "content-status",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_content_status",
                "content-status",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let client = self.client(&input.device)?;
            let response = client.fixed_op(CONTENT_INFO_COMMAND, cancellation).await?;
            let versions = parse_content_entries(&response)?;
            Ok(GetPanosContentStatusOutput {
                device: input.device,
                versions,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Read software version status via `request system software info`.
    pub async fn get_panos_software_status(
        &self,
        input: GetPanosSoftwareStatusInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<GetPanosSoftwareStatusOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_software_status",
                "software-status",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_software_status",
                "software-status",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let client = self.client(&input.device)?;
            let response = client.fixed_op(SOFTWARE_INFO_COMMAND, cancellation).await?;
            let versions = parse_software_entries(&response)?;
            Ok(GetPanosSoftwareStatusOutput {
                device: input.device,
                versions,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Test which security rule, if any, a packet description would match.
    ///
    /// Builds the `<test><security-policy-match>` command server-side from
    /// typed, individually escaped fields -- never from a caller-supplied
    /// command string -- so this can bypass `operational`'s `<show>`-only
    /// gate the same way `check_pending_changes` does for its own fixed
    /// `<check>` command, without accepting arbitrary `<test>` bodies.
    pub async fn test_panos_security_policy_match(
        &self,
        input: TestPanosSecurityPolicyMatchInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<TestPanosSecurityPolicyMatchOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "test_panos_security_policy_match",
                "policy-match",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "test_panos_security_policy_match",
                "policy-match",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let command = build_security_policy_match_command(&input)?;

            // Same mode-dispatched command policy already applied to
            // `execute_panos_op`, so a device- or global-scoped blocklist
            // rule (blocklist mode) or a missing `allow` entry (allowlist
            // mode, the default) both refuse this the same way (Percy F1,
            // MEC-935).
            self.check_command_policy(&input.device, &command)?;

            let client = self.client(&input.device)?;
            let response = client
                .post_fields(
                    vec![("type", "op".to_owned()), ("cmd", command)],
                    cancellation,
                )
                .await?;
            let mut rules = parse_security_policy_match(&response)?;
            let first_entry = rules.first();
            // Some PAN-OS releases return a text-form entry (`rule; index:
            // N`) with no `name` attribute; report that as a parse error
            // rather than a misleading `rule_name: Some("")`.
            if let Some(entry) = first_entry
                && entry.name.is_empty()
            {
                return Err(PanosMcpError::Xml(
                    "security-policy-match matched entry has no rule name".to_owned(),
                ));
            }
            let rule_name = first_entry.map(|entry| entry.name.clone());
            let action = first_entry
                .map(|entry| crate::xml::extract_element_text(&entry.xml, "action"))
                .transpose()?
                .flatten();
            // `action` is pulled from each entry's raw XML above, before the
            // loop below redacts it -- `rules` here carries the matched
            // rule's exact source XML, redacted the same way every other
            // tool that returns a `ConfigEntry` is (MEC-1233).
            for entry in &mut rules {
                entry.xml = crate::redact::redact_device_xml(&entry.xml);
            }
            Ok(TestPanosSecurityPolicyMatchOutput {
                device: input.device,
                matched: !rules.is_empty(),
                rule_name,
                action,
                rules,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Fetch a bounded window of PAN-OS logs for one log type.
    ///
    /// `max_logs` always applies -- defaulting to `DEFAULT_LOG_LIMIT` and
    /// capped at `MAX_LOG_LIMIT` -- so a caller can never pull an unbounded
    /// log set; this mirrors `OutputLimits::resolve`'s default-plus-hard-cap
    /// shape for free-form output.
    pub async fn query_panos_logs(
        &self,
        input: QueryPanosLogsInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<QueryPanosLogsOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "query_panos_logs",
                "log-query",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("query_panos_logs", "log-query", vec![input.device.clone()]),
        };
        let result = async {
            let max_logs = input.max_logs.unwrap_or(DEFAULT_LOG_LIMIT);
            if max_logs == 0 || max_logs > MAX_LOG_LIMIT {
                return Err(PanosMcpError::Policy {
                    field: "max_logs",
                    reason: format!("value must be between 1 and {MAX_LOG_LIMIT}"),
                });
            }
            if let Some(query) = &input.query
                && (query.is_empty() || query.len() > MAX_LOG_QUERY_BYTES)
            {
                return Err(PanosMcpError::Policy {
                    field: "query",
                    reason: format!("value must be 1-{MAX_LOG_QUERY_BYTES} bytes"),
                });
            }

            let client = self.client(&input.device)?;
            let mut fields = vec![
                ("type", "log".to_owned()),
                ("log-type", input.log_type.panos_value().to_owned()),
                ("nlogs", max_logs.to_string()),
            ];
            if let Some(query) = &input.query {
                fields.push(("query", query.clone()));
            }
            let submitted = client.post_fields(fields, cancellation.clone()).await?;
            let job_id = parse_job_id(&submitted)?;
            let finished = client
                .poll_log_job(&job_id, LOG_JOB_DEADLINE, cancellation)
                .await?;
            let mut entries = parse_log_entries(&finished)?;
            // PAN-OS config-change log entries can carry a PSK, bind
            // password, or SNMPv3 key in the before/after change detail;
            // this is the explicit token-allowlisted tool, but redact
            // regardless of caller.
            for entry in &mut entries {
                entry.xml = crate::redact::redact_device_xml(&entry.xml);
            }
            let returned = entries.len();
            Ok(QueryPanosLogsOutput {
                device: input.device,
                log_type: input.log_type,
                max_logs,
                entries,
                returned,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// List a rulebase or object container's entries by typed kind and vsys,
    /// rather than requiring the caller to know the exact XPath.
    ///
    /// Shares its scan/pagination/truncation behavior with
    /// [`list_panos_entries`](Self::list_panos_entries) -- this only differs
    /// in how the XPath is produced.
    pub async fn list_panos_rulebase_entries(
        &self,
        input: ListPanosRulebaseEntriesInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ListPanosRulebaseEntriesOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "list_panos_rulebase_entries",
                "list-rulebase-entries",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "list_panos_rulebase_entries",
                "list-rulebase-entries",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            validate_vsys_name(&input.vsys)?;
            let xpath = format!(
                "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{}']/{}",
                input.vsys,
                input.kind.xpath_suffix()
            );
            validate_read_xpath(&xpath)?;
            self.check_xpath_policy(&input.device, &xpath)?;

            let offset = input.offset.unwrap_or(0);
            let limit = input.limit.unwrap_or(DEFAULT_LIST_LIMIT);
            if limit == 0 || limit > MAX_LIST_LIMIT {
                return Err(PanosMcpError::Policy {
                    field: "limit",
                    reason: format!("value must be between 1 and {MAX_LIST_LIMIT}"),
                });
            }

            let client = self.client(&input.device)?;
            let (bytes, response_truncated) = client
                .configuration_entries(
                    input.source == ConfigSource::Candidate,
                    &xpath,
                    cancellation,
                )
                .await?;
            let scan = scan_config_entries(&bytes, offset, limit, LIST_CONTAINER_ENTRY_DEPTH)?;
            ensure_scan_success(&input.device, &bytes, &scan)?;

            let mut entries = scan.entries;
            for entry in &mut entries {
                entry.xml = crate::redact::redact_device_xml(&entry.xml);
            }
            let returned = entries.len();
            Ok(ListPanosRulebaseEntriesOutput {
                device: input.device,
                source: input.source,
                kind: input.kind,
                vsys: input.vsys,
                xpath,
                entries,
                offset,
                limit,
                returned,
                total_entries: scan.total_seen,
                truncated: response_truncated
                    || scan.truncated
                    || offset + returned < scan.total_seen,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Mode-dispatched command-policy gate shared by every tool that sends
    /// an op command built from a caller-controlled or caller-selected
    /// shape (`execute_panos_op`'s `<show>` command,
    /// `test_panos_security_policy_match`'s server-built `<test>` command).
    ///
    /// Fail-closed allowlist (default) and fail-open blocklist (legacy,
    /// opt-in) resolve to a `Decision` differently -- the allowlist checks a
    /// tag-path derived from the command XML against a per-device merged
    /// `CommandAllowlist` (no per-device dispatch inside mecmcp_policy for
    /// that domain), the blocklist checks the normalized raw command
    /// against the shared deny-rule policy -- but from here on both are
    /// handled by one exhaustive match so neither path can silently allow a
    /// variant the other introduced (Percy F1, MEC-352, MEC-935).
    fn check_command_policy(&self, device: &str, command_xml: &str) -> Result<()> {
        let decision = match self.command_policy_mode {
            CommandMode::Blocklist => self.policy.as_ref().map(|policy| {
                let normalized = normalize_input(command_xml);
                policy.check_command(device, &normalized, Action::Deny)
            }),
            CommandMode::Allowlist => {
                let policy = self
                    .command_allowlists
                    .get(device)
                    .ok_or_else(|| PanosMcpError::UnknownDevice(device.to_owned()))?;
                let tag_path = op_command_tag_path(command_xml)?;
                Some(policy.check_command(device, &tag_path, Action::Deny))
            }
        };
        if let Some(decision) = decision {
            match decision {
                Decision::Allow => {}
                Decision::Deny { rule, source, .. } => {
                    return Err(PanosMcpError::Policy {
                        field: "command",
                        reason: format!(
                            "blocked by {} blocklist rule '{}'",
                            source.as_str(),
                            rule.pattern
                        ),
                    });
                }
                Decision::DenyAllowlist {
                    reason, normalized, ..
                } => {
                    return Err(PanosMcpError::Policy {
                        field: "command",
                        reason: format!(
                            "refused by allowlist ({}); normalized input: {normalized}",
                            reason.as_str()
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Deny an xpath matched by a device or global config blocklist rule.
    ///
    /// Fail-open when no policy is configured, matching this server's
    /// existing command-blocklist semantics.
    fn check_xpath_policy(&self, device: &str, xpath: &str) -> Result<()> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        use mecmcp_policy::{evaluate, normalize_input};
        // Canonicalise quote style before matching, as `validate_write_xpath`
        // does: `'` and `"` are the same XPath predicate to PAN-OS, so a
        // blocklist rule written with one quote style must still catch a read
        // spelled with the other (MEC-528 class 3). Applies to every read path
        // that goes through this helper, including the paginated ones.
        let canonical = rust_panosmcp_auth::canonicalize_xpath_quotes(xpath);
        let normalized = normalize_input(&canonical);
        let rules = policy.config_rules_for(device);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == Action::Deny => Err(PanosMcpError::Policy {
                field: "xpath",
                reason: format!(
                    "blocked by {} blocklist rule '{}'",
                    rule.source.as_str(),
                    rule.pattern
                ),
            }),
            _ => Ok(()),
        }
    }

    pub(crate) fn client(&self, name: &str) -> Result<Arc<PanosClient>> {
        self.clients
            .get(name)
            .cloned()
            .ok_or_else(|| PanosMcpError::UnknownDevice(name.to_owned()))
    }
}

/// Result of `list_devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListDevicesOutput {
    /// Configured devices without API keys or trust material.
    pub devices: Vec<DeviceMetadata>,
}

/// Input for `gather_device_facts`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatherDeviceFactsInput {
    /// Exact inventory device name.
    pub device: String,
}

/// Result of `gather_device_facts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GatherDeviceFactsOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Selected facts from `show system info`.
    pub facts: DeviceFacts,
    /// Known-CVE version-floor warnings for the reported `sw-version`.
    ///
    /// Never gates the call -- this is advisory text for the human operator,
    /// not a decision. Empty when the version is unknown, unparseable, or at
    /// or above every fix level this server currently tracks.
    pub advisories: Vec<String>,
}

/// Input for `execute_panos_op`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutePanosOpInput {
    /// Exact inventory device name.
    pub device: String,
    /// A single XML operational command rooted at `<show>`.
    pub command: String,
    /// Optional returned-content cap; defaults to 524288 and cannot exceed 5242880.
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// Optional returned-line cap; defaults to 10000 and cannot exceed 100000.
    #[serde(default)]
    pub max_lines: Option<usize>,
}

/// PAN-OS configuration data source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// Active/running configuration via XML API action `show`.
    #[default]
    Running,
    /// Candidate configuration via XML API action `get`.
    Candidate,
}

/// Input for `get_panos_config`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosConfigInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// Optional XPath rooted at `/config`; defaults to `/config`.
    #[serde(default)]
    pub xpath: Option<String>,
    /// Optional returned-content cap; defaults to 524288 and cannot exceed 5242880.
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// Optional returned-line cap; defaults to 10000 and cannot exceed 100000.
    #[serde(default)]
    pub max_lines: Option<usize>,
}

/// Input for `list_panos_entries`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListPanosEntriesInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// XPath of the list container, e.g. a rulebase or address-object list.
    pub xpath: String,
    /// Zero-based index of the first entry to return; defaults to 0.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Maximum entries to return; defaults to 100 and cannot exceed 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Result of `list_panos_entries`.
///
/// `entries` holds only the `[offset, offset + limit)` window; `total_entries`
/// counts every complete entry observed in the (possibly `truncated`)
/// response, so a caller can page through a rulebase far larger than any
/// single response is allowed to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListPanosEntriesOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Validated XPath sent to PAN-OS.
    pub xpath: String,
    /// Entries in `[offset, offset + limit)`, each with its own XML and digest.
    pub entries: Vec<ConfigEntry>,
    /// Zero-based index of the first entry requested.
    pub offset: usize,
    /// Maximum entries requested.
    pub limit: usize,
    /// `entries.len()`.
    pub returned: usize,
    /// Complete entries observed in the response, truncated or not.
    pub total_entries: usize,
    /// True when more entries exist beyond this page, or the device response
    /// itself was cut off before every entry could be observed -- "N of M
    /// shown" rather than an outright failure.
    pub truncated: bool,
}

/// Input for `get_panos_entry_digest`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosEntryDigestInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// XPath resolving to exactly one entry, e.g.
    /// `.../rule-base/security/rules/entry[@name='allow-dns']`.
    pub xpath: String,
}

/// Result of `get_panos_entry_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GetPanosEntryDigestOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Validated XPath sent to PAN-OS.
    pub xpath: String,
    /// Whether PAN-OS had an entry at this XPath.
    pub found: bool,
    /// The entry's `name` attribute, when found.
    pub name: Option<String>,
    /// `sha256:<hex>` over the entry's exact source XML, when found. Changes
    /// if and only if this one entry changed -- no other part of the
    /// configuration is read to produce it.
    pub digest: Option<String>,
}

/// Input for `get_panos_ha_state`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosHaStateInput {
    /// Exact inventory device name.
    pub device: String,
}

/// Result of `get_panos_ha_state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GetPanosHaStateOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Parsed high-availability state.
    pub state: HaState,
}

/// Input for `get_panos_license_info`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosLicenseInfoInput {
    /// Exact inventory device name.
    pub device: String,
}

/// Result of `get_panos_license_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GetPanosLicenseInfoOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Every license entry PAN-OS reported.
    pub licenses: Vec<LicenseEntry>,
}

/// Input for `get_panos_content_status`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosContentStatusInput {
    /// Exact inventory device name.
    pub device: String,
}

/// Result of `get_panos_content_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GetPanosContentStatusOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Every content version entry PAN-OS reported.
    pub versions: Vec<ContentVersionEntry>,
}

/// Input for `get_panos_software_status`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanosSoftwareStatusInput {
    /// Exact inventory device name.
    pub device: String,
}

/// Result of `get_panos_software_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GetPanosSoftwareStatusOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Every software version entry PAN-OS reported.
    pub versions: Vec<SoftwareVersionEntry>,
}

/// IP protocol accepted by `test_panos_security_policy_match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    /// TCP (protocol number 6).
    Tcp,
    /// UDP (protocol number 17).
    Udp,
    /// ICMP (protocol number 1).
    Icmp,
}

impl IpProtocol {
    fn panos_number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
        }
    }
}

/// Maximum accepted length for a single zone, application, or user field in
/// a `test_panos_security_policy_match` request.
const MAX_POLICY_MATCH_FIELD_BYTES: usize = 255;

/// Input for `test_panos_security_policy_match`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TestPanosSecurityPolicyMatchInput {
    /// Exact inventory device name.
    pub device: String,
    /// Simulated packet source address.
    pub source: IpAddr,
    /// Simulated packet destination address.
    pub destination: IpAddr,
    /// Simulated packet destination port. Required unless `protocol` is
    /// `icmp`, which has no port; if omitted for `icmp` the command carries
    /// no `<destination-port>` element at all.
    #[serde(default)]
    pub destination_port: Option<u16>,
    /// Simulated packet IP protocol.
    pub protocol: IpProtocol,
    /// Optional source zone.
    #[serde(default)]
    pub from_zone: Option<String>,
    /// Optional destination zone.
    #[serde(default)]
    pub to_zone: Option<String>,
    /// Optional application name.
    #[serde(default)]
    pub application: Option<String>,
    /// Optional `user@domain` source user.
    #[serde(default)]
    pub source_user: Option<String>,
    /// Optional vsys name; defaults to PAN-OS's own default vsys when
    /// omitted. Validated with the same token shape as
    /// `list_panos_rulebase_entries`'s `vsys` field.
    #[serde(default)]
    pub vsys: Option<String>,
}

/// Result of `test_panos_security_policy_match`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct TestPanosSecurityPolicyMatchOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Whether any security rule matched the simulated packet.
    pub matched: bool,
    /// The first matched rule's name, when any rule matched.
    pub rule_name: Option<String>,
    /// The first matched rule's `<action>` (e.g. `allow`, `deny`, `drop`),
    /// when any rule matched. A model summarizing `matched: true` without
    /// this could read a matched deny rule as "traffic is permitted".
    pub action: Option<String>,
    /// Every matched rule, in the order PAN-OS returned them.
    pub rules: Vec<ConfigEntry>,
}

/// Build the `<test><security-policy-match>` command from typed, validated
/// fields, escaping every caller-supplied string individually.
///
/// This never interpolates a caller-supplied command string -- every value
/// here is either a validated typed field (`IpAddr`, `u16`, [`IpProtocol`])
/// or an explicitly length-capped, XML-escaped string -- matching the
/// pattern `mutation.rs` uses to build fixed-shape commands from operator
/// input.
fn build_security_policy_match_command(
    input: &TestPanosSecurityPolicyMatchInput,
) -> Result<String> {
    for (field, value) in [
        ("from_zone", &input.from_zone),
        ("to_zone", &input.to_zone),
        ("application", &input.application),
        ("source_user", &input.source_user),
    ] {
        if let Some(value) = value
            && (value.is_empty() || value.len() > MAX_POLICY_MATCH_FIELD_BYTES)
        {
            return Err(PanosMcpError::Policy {
                field,
                reason: format!("value must be 1-{MAX_POLICY_MATCH_FIELD_BYTES} bytes"),
            });
        }
    }
    if let Some(vsys) = &input.vsys {
        validate_vsys_name(vsys)?;
    }
    let destination_port = match (input.protocol, input.destination_port) {
        (IpProtocol::Icmp, port) => port,
        (_, Some(port)) => Some(port),
        (_, None) => {
            return Err(PanosMcpError::Policy {
                field: "destination_port",
                reason: "required unless protocol is icmp".to_owned(),
            });
        }
    };

    let mut command = String::from("<test><security-policy-match>");
    command.push_str(&format!(
        "<source>{}</source>",
        escape(input.source.to_string())
    ));
    command.push_str(&format!(
        "<destination>{}</destination>",
        escape(input.destination.to_string())
    ));
    if let Some(port) = destination_port {
        command.push_str(&format!("<destination-port>{port}</destination-port>"));
    }
    command.push_str(&format!(
        "<protocol>{}</protocol>",
        input.protocol.panos_number()
    ));
    if let Some(vsys) = &input.vsys {
        command.push_str(&format!("<vsys>{}</vsys>", escape(vsys)));
    }
    if let Some(zone) = &input.from_zone {
        command.push_str(&format!("<from>{}</from>", escape(zone)));
    }
    if let Some(zone) = &input.to_zone {
        command.push_str(&format!("<to>{}</to>", escape(zone)));
    }
    if let Some(application) = &input.application {
        command.push_str(&format!(
            "<application>{}</application>",
            escape(application)
        ));
    }
    if let Some(user) = &input.source_user {
        command.push_str(&format!("<source-user>{}</source-user>", escape(user)));
    }
    command.push_str("</security-policy-match></test>");
    Ok(command)
}

/// PAN-OS log type accepted by `query_panos_logs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PanosLogType {
    /// Traffic log.
    Traffic,
    /// Threat log.
    Threat,
    /// System log.
    System,
    /// Configuration log.
    Config,
}

impl PanosLogType {
    fn panos_value(self) -> &'static str {
        match self {
            Self::Traffic => "traffic",
            Self::Threat => "threat",
            Self::System => "system",
            Self::Config => "config",
        }
    }
}

/// Input for `query_panos_logs`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryPanosLogsInput {
    /// Exact inventory device name.
    pub device: String,
    /// PAN-OS log type to query.
    pub log_type: PanosLogType,
    /// Optional PAN-OS log filter expression.
    #[serde(default)]
    pub query: Option<String>,
    /// Maximum log entries to return; defaults to 100 and cannot exceed 1000.
    #[serde(default)]
    pub max_logs: Option<u32>,
}

/// Result of `query_panos_logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct QueryPanosLogsOutput {
    /// Exact inventory device name.
    pub device: String,
    /// PAN-OS log type queried.
    pub log_type: PanosLogType,
    /// The resolved, enforced cap applied to this query.
    pub max_logs: u32,
    /// Matched log entries, up to `max_logs`.
    pub entries: Vec<ConfigEntry>,
    /// `entries.len()`.
    pub returned: usize,
}

/// Typed rulebase or object container `list_panos_rulebase_entries` can page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RulebaseKind {
    /// `rule-base/security/rules`.
    SecurityRules,
    /// `rule-base/nat/rules`.
    NatRules,
    /// `address`.
    AddressObjects,
    /// `service`.
    ServiceObjects,
}

impl RulebaseKind {
    fn xpath_suffix(self) -> &'static str {
        match self {
            Self::SecurityRules => "rule-base/security/rules",
            Self::NatRules => "rule-base/nat/rules",
            Self::AddressObjects => "address",
            Self::ServiceObjects => "service",
        }
    }
}

fn default_vsys() -> String {
    "vsys1".to_owned()
}

/// Validate a caller-supplied vsys name before it is interpolated into an
/// XPath predicate.
///
/// Restricted to a safe token shape (no quotes, brackets, or slashes) so the
/// built XPath cannot address anything the `vsys`/`kind` combination did not
/// intend, regardless of what `validate_read_xpath`'s broader XPath grammar
/// would otherwise accept.
fn validate_vsys_name(vsys: &str) -> Result<()> {
    if vsys.is_empty()
        || vsys.len() > 63
        || !vsys
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PanosMcpError::Policy {
            field: "vsys",
            reason: "value must be 1-63 ASCII alphanumeric, '-', '_', or '.' characters".to_owned(),
        });
    }
    Ok(())
}

/// Input for `list_panos_rulebase_entries`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListPanosRulebaseEntriesInput {
    /// Exact inventory device name.
    pub device: String,
    /// Running or candidate configuration; defaults to running.
    #[serde(default)]
    pub source: ConfigSource,
    /// Rulebase or object container to list.
    pub kind: RulebaseKind,
    /// Vsys name; defaults to `vsys1`.
    #[serde(default = "default_vsys")]
    pub vsys: String,
    /// Zero-based index of the first entry to return; defaults to 0.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Maximum entries to return; defaults to 100 and cannot exceed 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Result of `list_panos_rulebase_entries`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListPanosRulebaseEntriesOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Rulebase or object container listed.
    pub kind: RulebaseKind,
    /// Vsys name used to build the XPath.
    pub vsys: String,
    /// The XPath resolved from `kind` and `vsys`.
    pub xpath: String,
    /// Entries in `[offset, offset + limit)`, each with its own XML and digest.
    pub entries: Vec<ConfigEntry>,
    /// Zero-based index of the first entry requested.
    pub offset: usize,
    /// Maximum entries requested.
    pub limit: usize,
    /// `entries.len()`.
    pub returned: usize,
    /// Complete entries observed in the response, truncated or not.
    pub total_entries: usize,
    /// True when more entries exist beyond this page, or the device response
    /// itself was cut off before every entry could be observed.
    pub truncated: bool,
}

/// Bounded XML result shared by operational reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct XmlToolOutput {
    /// Exact inventory device name.
    pub device: String,
    /// PAN-OS envelope status.
    pub status: String,
    /// PAN-OS numeric response code, when supplied.
    pub code: Option<i32>,
    /// Bounded XML and truncation metadata.
    pub output: BoundedText,
}

/// Bounded configuration result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ConfigToolOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configuration data source.
    pub source: ConfigSource,
    /// Validated XPath sent to PAN-OS.
    pub xpath: String,
    /// PAN-OS envelope status.
    pub status: String,
    /// PAN-OS numeric response code, when supplied.
    pub code: Option<i32>,
    /// Bounded XML and truncation metadata.
    pub output: BoundedText,
}

/// Input for `list_panorama_device_groups`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListPanoramaDeviceGroupsInput {
    /// Exact inventory device name for the Panorama management API.
    pub device: String,
}

/// Result of `list_panorama_device_groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListPanoramaDeviceGroupsOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configured device groups and their member firewall serials.
    pub device_groups: Vec<DeviceGroupSummary>,
}

/// Input for `list_panorama_templates`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListPanoramaTemplatesInput {
    /// Exact inventory device name for the Panorama management API.
    pub device: String,
}

/// Result of `list_panorama_templates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ListPanoramaTemplatesOutput {
    /// Exact inventory device name.
    pub device: String,
    /// Configured templates and their declared variable names.
    pub templates: Vec<TemplateSummary>,
}

/// Input for `get_panorama_push_status`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPanoramaPushStatusInput {
    /// Exact inventory device name for the Panorama management API.
    pub device: String,
    /// PAN-OS job identifier returned by a Panorama commit-all/push operation.
    pub job_id: String,
}

/// Result of `get_panorama_push_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct PanoramaPushStatusOutput {
    /// Exact inventory device name.
    pub device: String,
    /// The PAN-OS job identifier this status was read for.
    pub job_id: String,
    /// Overall push job state.
    pub job: JobStatus,
    /// Per-target-firewall push results, in document order.
    pub devices: Vec<PushDeviceStatus>,
}

/// Caller-visible bounded text plus exact truncation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct BoundedText {
    /// UTF-8 content, never exceeding the requested byte or line cap.
    pub content: String,
    /// Bytes in the complete device response.
    pub original_bytes: usize,
    /// Lines in the complete device response.
    pub original_lines: usize,
    /// Bytes returned in `content`.
    pub returned_bytes: usize,
    /// Lines returned in `content`.
    pub returned_lines: usize,
    /// Whether either output limit removed content.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
struct OutputLimits {
    max_bytes: usize,
    max_lines: usize,
}

impl OutputLimits {
    fn resolve(max_bytes: Option<usize>, max_lines: Option<usize>) -> Result<Self> {
        let max_bytes = max_bytes.unwrap_or(DEFAULT_OUTPUT_BYTES);
        let max_lines = max_lines.unwrap_or(DEFAULT_OUTPUT_LINES);
        if !(1..=MAX_OUTPUT_BYTES).contains(&max_bytes) {
            return Err(PanosMcpError::Policy {
                field: "max_bytes",
                reason: format!("value must be between 1 and {MAX_OUTPUT_BYTES}"),
            });
        }
        if !(1..=MAX_OUTPUT_LINES).contains(&max_lines) {
            return Err(PanosMcpError::Policy {
                field: "max_lines",
                reason: format!("value must be between 1 and {MAX_OUTPUT_LINES}"),
            });
        }
        Ok(Self {
            max_bytes,
            max_lines,
        })
    }
}

/// Escape glob metacharacters that occur naturally in an XPath predicate but
/// are not the wildcard an operator means when writing a blocklist rule.
///
/// `compile_rules` compiles xpath blocklist patterns as globs (the `globset`
/// crate). Globs treat a bare `[...]` as a character class, so a pattern like
/// `.../entry[@name='secret']*` is not matched literally: `[@name='secret']`
/// is parsed as "one character from the set `@name='secret`", which either
/// fails to compile (e.g. the value contains characters globset reads as an
/// invalid range, silently refusing to enforce the rule at startup) or
/// compiles into a character class the operator never intended, matching a
/// different set of xpaths than the literal predicate they wrote (MEC-528
/// class 3). `*` is left untouched since it is the one wildcard operators
/// are expected to use; `?` is also escaped since XPath has no single-char
/// wildcard of its own but globset would still treat it as one.
fn escape_xpath_glob_metacharacters(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for ch in pattern.chars() {
        if matches!(ch, '[' | ']' | '?' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Turn a failed PAN-OS envelope observed mid-scan into a typed API error.
///
/// The entry scan never buffers a full [`PanosResponse`], so it cannot reuse
/// `PanosResponse::ensure_success` -- this extracts the same `<msg>`/`<line>`
/// text from the raw bytes instead.
fn ensure_scan_success(device: &str, raw: &[u8], scan: &crate::xml::EntryScanResult) -> Result<()> {
    let is_success =
        scan.status.eq_ignore_ascii_case("success") && !matches!(scan.code, Some(1..=18 | 21..));
    if is_success {
        return Ok(());
    }
    let code = scan.code.unwrap_or(-1);
    let message = collect_text_for_elements(raw, &[b"msg", b"line"], 1024)
        .ok()
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "PAN-OS returned an error without a message".to_owned());
    Err(PanosMcpError::api(
        device,
        code,
        panos_api_code_name(code),
        message,
    ))
}

fn bounded_text(input: &str, limits: OutputLimits) -> BoundedText {
    let original_bytes = input.len();
    let original_lines = input.lines().count();
    let mut boundary = input.len().min(limits.max_bytes);
    while !input.is_char_boundary(boundary) {
        boundary -= 1;
    }
    if original_lines > limits.max_lines
        && let Some((index, _)) = input.match_indices('\n').nth(limits.max_lines - 1)
    {
        boundary = boundary.min(index);
    }
    let content = input[..boundary].to_owned();
    BoundedText {
        original_bytes,
        original_lines,
        returned_bytes: content.len(),
        returned_lines: content.lines().count(),
        truncated: boundary < input.len(),
        content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_utf8_safe_and_reports_truncation() {
        let output = bounded_text(
            "one\ntwø\nthree",
            OutputLimits {
                max_bytes: 8,
                max_lines: 2,
            },
        );
        assert_eq!(output.content, "one\ntwø");
        assert_eq!(output.original_lines, 3);
        assert!(output.truncated);
    }

    #[test]
    fn output_limits_refuse_zero_and_excessive_values() {
        assert!(OutputLimits::resolve(Some(0), None).is_err());
        assert!(OutputLimits::resolve(None, Some(MAX_OUTPUT_LINES + 1)).is_err());
    }

    /// MEC-528 class 3: an xpath predicate compiled as a raw glob either
    /// fails outright (an invalid character range, as here) or silently
    /// matches something other than the literal predicate the operator
    /// wrote. Escaping the brackets must make the pattern match the literal
    /// text of the predicate and nothing else.
    #[test]
    fn escaping_makes_a_bracketed_predicate_a_literal_match() {
        let pattern = "*/address/entry[@name='secret-object']*";
        // Unescaped, this glob fails to compile: globset reads `t' > 'o` in
        // `[@name='secret-object']` as an invalid descending character range.
        assert!(
            compile_rules(
                &[(Action::Deny, pattern.to_owned())],
                "test",
                RuleSource::Device,
                |_scope, _pattern, error| error,
            )
            .is_err()
        );

        let escaped = escape_xpath_glob_metacharacters(pattern);
        let compiled = compile_rules(
            &[(Action::Deny, escaped)],
            "test",
            RuleSource::Device,
            |_scope, _pattern, error| error,
        )
        .expect("escaped pattern compiles");
        let rules: Vec<_> = compiled.iter().collect();
        assert!(mecmcp_policy::evaluate(
            &rules,
            "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address/entry[@name='secret-object']"
        )
        .is_some());
        assert!(mecmcp_policy::evaluate(
            &rules,
            "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address/entry[@name='other-object']"
        )
        .is_none());
    }

    #[test]
    fn escaping_leaves_the_wildcard_asterisk_alone() {
        assert_eq!(
            escape_xpath_glob_metacharacters("*/hostname*"),
            "*/hostname*"
        );
    }
}
