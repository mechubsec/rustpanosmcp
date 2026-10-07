//! MCP adapters and atomically reloadable runtime state for rust-panosmcp.

pub mod cli;
pub mod cli_validate_extra;
pub mod http_transport;
pub mod token_cmd;

use arc_swap::ArcSwap;
use rmcp::{
    ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, Extensions, Implementation, ServerCapabilities, ServerConfig,
    },
    tool, tool_handler, tool_router,
};
use rust_panosmcp_auth::{CallerContext, TokenStore, TokenStoreFile};
use rust_panosmcp_core::{
    Result as CoreResult,
    inventory::Inventory,
    mutation::{
        ApplyChangeSetInput, ApproveChangeSetInput, CandidateFingerprintInput,
        ChangeSetStatusInput, CreateChangeSetInput, OperationInput, OperationStatusInput,
        StageConfigInput,
    },
    tools::{
        ExecutePanosOpInput, GatherDeviceFactsInput, GetPanoramaPushStatusInput,
        GetPanosConfigInput, GetPanosContentStatusInput, GetPanosEntryDigestInput,
        GetPanosHaStateInput, GetPanosLicenseInfoInput, GetPanosSoftwareStatusInput,
        ListPanoramaDeviceGroupsInput, ListPanoramaTemplatesInput, ListPanosEntriesInput,
        ListPanosRulebaseEntriesInput, PanosService, QueryPanosLogsInput,
        TestPanosSecurityPolicyMatchInput,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

/// Complete immutable runtime replaced in one atomic operation on reload.
#[derive(Debug)]
pub struct RuntimeSnapshot {
    /// Validated device service and reusable HTTPS pools.
    pub service: Arc<PanosService>,
    /// Validated bearer store for remote HTTP; absent for stdio/no-auth mode.
    pub tokens: Option<Arc<TokenStore>>,
}

/// Shared runtime plus its reload sources.
#[derive(Debug, Clone)]
pub struct RuntimeState {
    current: Arc<ArcSwap<RuntimeSnapshot>>,
    inventory_path: Arc<PathBuf>,
    token_path: Option<Arc<PathBuf>>,
}

impl RuntimeState {
    /// Load and fully validate inventory, clients, and optional tokens.
    pub fn load(
        inventory_path: impl AsRef<Path>,
        token_path: Option<&Path>,
    ) -> Result<Self, RuntimeLoadError> {
        Self::load_with_state(
            inventory_path,
            token_path,
            None,
            false,
            None,
            false,
            false,
            None,
        )
    }

    /// Load runtime with an optional persistent private mutation-state file.
    #[allow(clippy::too_many_arguments)]
    pub fn load_with_state(
        inventory_path: impl AsRef<Path>,
        token_path: Option<&Path>,
        state_path: Option<&Path>,
        lab_mode: bool,
        approval_timeout_secs: Option<u64>,
        allow_plane_owned_writes: bool,
        allow_direct_commit: bool,
        evidence: Option<std::sync::Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    ) -> Result<Self, RuntimeLoadError> {
        let inventory_path = inventory_path.as_ref().to_path_buf();
        let token_path = token_path.map(Path::to_path_buf);
        let snapshot = load_snapshot(
            &inventory_path,
            token_path.as_deref(),
            None,
            SnapshotOptions {
                state_path: state_path.map(Path::to_path_buf),
                lab_mode,
                approval_timeout_secs,
                allow_plane_owned_writes,
                allow_direct_commit,
                evidence,
            },
        )?;
        Ok(Self {
            current: Arc::new(ArcSwap::from_pointee(snapshot)),
            inventory_path: Arc::new(inventory_path),
            token_path: token_path.map(Arc::new),
        })
    }

    /// Construct an embedding/test runtime from already validated parts.
    #[must_use]
    pub fn from_parts(service: PanosService, tokens: Option<TokenStore>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(RuntimeSnapshot {
                service: Arc::new(service),
                tokens: tokens.map(Arc::new),
            })),
            inventory_path: Arc::new(PathBuf::new()),
            token_path: None,
        }
    }

    /// Current consistent service/token snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    /// Build a complete replacement and publish it only after all validation.
    pub fn reload(&self) -> Result<(), RuntimeLoadError> {
        if self.inventory_path.as_os_str().is_empty() {
            return Err(RuntimeLoadError::Configuration(
                "embedded runtime has no reload source".to_owned(),
            ));
        }
        let current = self.snapshot();
        let replacement = load_snapshot(
            &self.inventory_path,
            self.token_path.as_ref().map(|path| path.as_path()),
            Some(&current.service),
            // Every field is unused on this path: reload rebuilds from the
            // previous service's coordinator, so lab mode, the break-glass
            // posture and the evidence recorder all carry over from startup. A
            // SIGHUP must not be able to change whether two-person control
            // applies.
            SnapshotOptions::default(),
        )?;
        self.current.store(Arc::new(replacement));
        Ok(())
    }

    /// Configured inventory path.
    #[must_use]
    pub fn inventory_path(&self) -> &Path {
        &self.inventory_path
    }

    /// Configured token path, when remote auth is enabled.
    #[must_use]
    pub fn token_path(&self) -> Option<&Path> {
        self.token_path.as_deref().map(PathBuf::as_path)
    }
}

/// What a fresh snapshot needs beyond its paths.
///
/// Grouped rather than passed positionally: `lab_mode` and
/// `allow_plane_owned_writes` are adjacent bools, and swapping them silently
/// turns off two-person control while turning on writes to plane-owned devices
/// -- the two things most worth not getting wrong by transposition.
#[derive(Default)]
struct SnapshotOptions {
    state_path: Option<PathBuf>,
    lab_mode: bool,
    approval_timeout_secs: Option<u64>,
    allow_plane_owned_writes: bool,
    allow_direct_commit: bool,
    evidence: Option<std::sync::Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
}

fn load_snapshot(
    inventory_path: &Path,
    token_path: Option<&Path>,
    previous_service: Option<&PanosService>,
    options: SnapshotOptions,
) -> Result<RuntimeSnapshot, RuntimeLoadError> {
    let SnapshotOptions {
        state_path,
        lab_mode,
        approval_timeout_secs,
        allow_plane_owned_writes,
        allow_direct_commit,
        evidence,
    } = options;
    let state_path = state_path.as_deref();
    let inventory = Inventory::load(inventory_path)?;
    let service = Arc::new(match previous_service {
        Some(previous) => PanosService::reload(inventory, previous)?,
        None => PanosService::new_with_options(
            inventory,
            state_path,
            lab_mode,
            approval_timeout_secs,
            allow_plane_owned_writes,
            allow_direct_commit,
            evidence,
        )?,
    });
    let tokens = token_path
        .map(|path| TokenStoreFile::load(path).map(|file| file.store()))
        .transpose()?;
    Ok(RuntimeSnapshot { service, tokens })
}

/// Startup/reload validation error.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeLoadError {
    /// Inventory or PAN-OS client validation failed.
    #[error(transparent)]
    Core(#[from] rust_panosmcp_core::PanosMcpError),
    /// Bearer-token file validation failed.
    #[error(transparent)]
    Tokens(#[from] rust_panosmcp_auth::TokenStoreFileError),
    /// Runtime configuration has no safe interpretation.
    #[error("runtime configuration error: {0}")]
    Configuration(String),
}

/// MCP server whose sessions share one atomically reloadable runtime.
#[derive(Debug, Clone)]
pub struct PanosMcpServer {
    runtime: RuntimeState,
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

impl PanosMcpServer {
    /// Wrap one validated PAN-OS service for local stdio/embedding.
    #[must_use]
    pub fn new(service: PanosService) -> Self {
        Self::from_runtime(RuntimeState::from_parts(service, None))
    }

    /// Wrap shared atomically reloadable runtime for HTTP sessions.
    #[must_use]
    pub fn from_runtime(runtime: RuntimeState) -> Self {
        Self {
            runtime,
            tool_router: Self::tool_router(),
        }
    }

    fn to_call_result<T: Serialize>(
        result: CoreResult<T>,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        Ok(match result {
            Ok(value) => match serde_json::to_string_pretty(&value) {
                Ok(json) => CallToolResult::success(vec![ContentBlock::text(json)]),
                Err(error) => CallToolResult::error(vec![ContentBlock::text(format!(
                    "failed to serialize tool result: {error}"
                ))]),
            },
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error.to_string())]),
        })
    }

    /// Detect whether this request came over HTTP (vs local stdio).
    ///
    /// HTTP requests carry `http::request::Parts` in rmcp's Extensions.
    /// stdio requests do not. This distinction is precise and stable.
    fn is_http(extensions: &Extensions) -> bool {
        extensions.get::<http::request::Parts>().is_some()
    }

    fn caller(extensions: &Extensions) -> Option<CallerContext> {
        // The bearer boundary inserts the CallerCtx the authenticator built,
        // which is typed over `MutationGrant` so the grant survives the hop.
        // rmcp's Extensions carries Parts, so we must extract two levels deep:
        // extensions → Parts → Parts.extensions → CallerCtx. Reading only the
        // outer map returns None, which would fail open.
        extensions
            .get::<http::request::Parts>()
            .and_then(|parts| {
                parts
                    .extensions
                    .get::<mecmcp_auth::CallerCtx<rust_panosmcp_auth::MutationGrant>>()
            })
            .map(|ctx| rust_panosmcp_auth::CallerContext {
                token_name: ctx.token_name.clone(),
                devices: ctx.devices.clone(),
                tools: ctx.tools.clone(),
                grant: ctx.grant.clone(),
                provider: ctx.provider.clone(),
                provider_tier: ctx.provider_tier,
                on_behalf_of: ctx.on_behalf_of.clone(),
                actor_type: ctx.actor_type,
                client_name: ctx.client_name,
                model_id: ctx.model_id,
                session_id: ctx.session_id.clone(),
                request_id: ctx.request_id,
            })
    }

    fn authorize(
        extensions: &Extensions,
        tool: &'static str,
        device: Option<&str>,
    ) -> Option<CallToolResult> {
        let caller = Self::caller(extensions);

        // Fail closed: HTTP requests without a caller are denied.
        // stdio (no Parts) with no caller is allowed — stdio is unauthenticated by design.
        if caller.is_none() && Self::is_http(extensions) {
            return Some(CallToolResult::error(vec![ContentBlock::text(
                "authenticated HTTP transport requires a valid bearer token",
            )]));
        }

        let Some(caller) = caller else {
            // stdio with no caller → allow (unauthenticated by design)
            return None;
        };

        if !caller
            .tools
            .allows_tool(tool, rust_panosmcp_auth::MUTATION_TOOLS)
        {
            return Some(CallToolResult::error(vec![ContentBlock::text(format!(
                "token '{}' is not authorized for tool '{tool}'",
                caller.token_name
            ))]));
        }
        if let Some(device) = device
            && !caller.devices.allows(device)
        {
            return Some(CallToolResult::error(vec![ContentBlock::text(format!(
                "token '{}' is not authorized for the requested device",
                caller.token_name
            ))]));
        }
        None
    }

    // `CallToolResult` is rmcp's type and its size is set by the MCP protocol
    // shape, not by anything here. A transitive upgrade that came with the
    // mecmcp 0.3.0 bump pushed it past clippy's 128-byte threshold. Boxing the
    // Err would ripple through sixteen call sites that return it straight back
    // to the tool handler, to no benefit on an error path.
    #[allow(clippy::result_large_err)]
    fn mutation_principal(extensions: &Extensions) -> Result<String, CallToolResult> {
        if let Some(caller) = Self::caller(extensions) {
            return Ok(caller.token_name.clone());
        }
        // Fail closed: HTTP without caller is denied.
        if Self::is_http(extensions) {
            return Err(CallToolResult::error(vec![ContentBlock::text(
                "candidate mutation requires authenticated HTTP or local stdio",
            )]));
        }
        Ok("local-stdio".to_owned())
    }

    #[allow(clippy::result_large_err)]
    fn mutation_identity(
        extensions: &Extensions,
    ) -> Result<(String, Option<rust_panosmcp_auth::MutationGrant>), CallToolResult> {
        let principal = Self::mutation_principal(extensions)?;
        let caller = Self::caller(extensions);
        if caller.as_ref().is_some_and(|caller| caller.grant.is_none()) {
            return Err(CallToolResult::error(vec![ContentBlock::text(
                "candidate mutations over HTTP require a token-specific mutation grant",
            )]));
        }
        Ok((principal, caller.and_then(|caller| caller.grant.clone())))
    }
}

/// Empty input object for `list_devices`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[tool_router]
impl PanosMcpServer {
    /// Persist a fingerprint-bound multi-action plan without changing PAN-OS.
    #[tool(
        name = "create_panos_change_set",
        description = "Plan and persist 1-64 ordered PAN-OS candidate actions under inventory and token XPath/action scopes"
    )]
    async fn create_panos_change_set(
        &self,
        Parameters(input): Parameters<CreateChangeSetInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "create_panos_change_set", Some(&input.device))
        {
            return Ok(denial);
        }
        let (principal, grant) = match Self::mutation_identity(&extensions) {
            Ok(identity) => identity,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .create_change_set(
                    input,
                    caller.as_ref(),
                    &principal,
                    grant.as_ref(),
                    cancellation,
                )
                .await,
        )
    }

    /// Independently approve the exact digest of another principal's plan.
    #[tool(
        name = "approve_panos_change_set",
        description = "Approve an unexpired exact change-set digest; self-approval is refused"
    )]
    async fn approve_panos_change_set(
        &self,
        Parameters(input): Parameters<ApproveChangeSetInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "approve_panos_change_set", Some(&input.device))
        {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .approve_change_set(input, caller.as_ref(), &principal)
                .await,
        )
    }

    /// Inspect the exact persistent plan, approval, expiry, and apply state.
    #[tool(
        name = "get_panos_change_set",
        description = "Return the exact actions, digest, approval, expiry, and operation state for review or recovery"
    )]
    async fn get_panos_change_set(
        &self,
        Parameters(input): Parameters<ChangeSetStatusInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panos_change_set", Some(&input.device))
        {
            return Ok(denial);
        }
        if let Err(denial) = Self::mutation_principal(&extensions) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(service.change_set_status(input, caller.as_ref()).await)
    }

    /// Apply one independently approved plan as a normal staged operation.
    #[tool(
        name = "apply_panos_change_set",
        description = "Apply an independently approved exact change set under one endpoint/config lock, reverting partial failure"
    )]
    async fn apply_panos_change_set(
        &self,
        Parameters(input): Parameters<ApplyChangeSetInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "apply_panos_change_set", Some(&input.device))
        {
            return Ok(denial);
        }
        let (principal, grant) = match Self::mutation_identity(&extensions) {
            Ok(identity) => identity,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .apply_change_set(
                    input,
                    caller.as_ref(),
                    &principal,
                    grant.as_ref(),
                    cancellation,
                )
                .await,
        )
    }

    /// Fingerprint all operator-authorized candidate subtrees before mutation.
    #[tool(
        name = "get_candidate_fingerprint",
        description = "Return a SHA-256 fingerprint over all operator-authorized candidate subtrees"
    )]
    async fn get_candidate_fingerprint(
        &self,
        Parameters(input): Parameters<CandidateFingerprintInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            &extensions,
            "get_candidate_fingerprint",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .candidate_fingerprint(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Stage one guarded set/delete candidate action.
    #[tool(
        name = "stage_panos_config",
        description = "Stage one policy-bounded PAN-OS candidate set/delete using an expected fingerprint"
    )]
    async fn stage_panos_config(
        &self,
        Parameters(input): Parameters<StageConfigInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "stage_panos_config", Some(&input.device))
        {
            return Ok(denial);
        }
        // MEC-528 F4: `stage_panos_config` is the v0.1 write tool and used to
        // check only the device-wide mutation policy for an HTTP caller with
        // no grant, passing `None` straight to `stage_config` -- unlike the
        // v0.2 change-set tools (`create_panos_change_set`,
        // `apply_panos_change_set`), which already refuse that caller via
        // `mutation_identity`. Sharing the same identity check means both
        // write paths fail closed on the same condition.
        let (principal, grant) = match Self::mutation_identity(&extensions) {
            Ok(identity) => identity,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .stage_config(
                    input,
                    &principal,
                    grant.as_ref(),
                    caller.as_ref(),
                    cancellation,
                )
                .await,
        )
    }

    /// Read a bounded PAN-OS running/candidate change summary.
    #[tool(
        name = "diff_panos_candidate",
        description = "Return a bounded PAN-OS change summary for the exact staged candidate fingerprint. Output is redacted: secret-shaped values such as phash, private keys, pre-shared keys, and shared-secret fields are redacted; structure and non-secret change text remain"
    )]
    async fn diff_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "diff_panos_candidate", Some(&input.device))
        {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .diff_candidate(input, &principal, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Run full PAN-OS validation for the staged fingerprint.
    #[tool(
        name = "validate_panos_candidate",
        description = "Validate a staged candidate and make only the same fingerprint eligible for commit"
    )]
    async fn validate_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "validate_panos_candidate", Some(&input.device))
        {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .validate_candidate(input, &principal, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Start the second, admin-scoped commit step and reconcile its job.
    #[tool(
        name = "commit_panos_candidate",
        description = "Commit only a successfully validated operation using an exact candidate fingerprint"
    )]
    async fn commit_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "commit_panos_candidate", Some(&input.device))
        {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .commit_candidate(input, &principal, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Revert candidate changes belonging to the configured dedicated PAN-OS admin.
    #[tool(
        name = "discard_panos_candidate",
        description = "Discard a staged operation through an admin-scoped partial candidate revert"
    )]
    async fn discard_panos_candidate(
        &self,
        Parameters(input): Parameters<OperationInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "discard_panos_candidate", Some(&input.device))
        {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .discard_candidate(input, &principal, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Poll detached or completed lifecycle state.
    #[tool(
        name = "get_panos_operation",
        description = "Return safe status for an owned PAN-OS candidate lifecycle operation"
    )]
    async fn get_panos_operation(
        &self,
        Parameters(input): Parameters<OperationStatusInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panos_operation", Some(&input.device))
        {
            return Ok(denial);
        }
        let principal = match Self::mutation_principal(&extensions) {
            Ok(principal) => principal,
            Err(denial) => return Ok(denial),
        };
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .operation_status(input, &principal, caller.as_ref())
                .await,
        )
    }

    /// List devices visible to the authenticated caller.
    #[tool(
        name = "list_devices",
        description = "List authorized PAN-OS devices and safe metadata; never returns API keys"
    )]
    async fn list_devices(
        &self,
        Parameters(_input): Parameters<EmptyInput>,
        extensions: Extensions,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(&extensions, "list_devices", None) {
            return Ok(denial);
        }
        let caller = Self::caller(&extensions);
        let mut output = self
            .runtime
            .snapshot()
            .service
            .list_devices(caller.as_ref());
        // Fail closed: HTTP without caller was already denied by authorize.
        // Only stdio (no Parts, no caller) reaches here and should see all devices.
        if let Some(caller) = caller {
            output
                .devices
                .retain(|device| caller.devices.allows(&device.name));
        }
        Self::to_call_result(Ok(output))
    }

    /// Gather selected device facts using `show system info`.
    #[tool(
        name = "gather_device_facts",
        description = "Gather hostname, model, serial, version, management IP, and uptime from an authorized PAN-OS device"
    )]
    async fn gather_device_facts(
        &self,
        Parameters(input): Parameters<GatherDeviceFactsInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "gather_device_facts", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .gather_device_facts(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Execute only a single `<show>` operational command.
    #[tool(
        name = "execute_panos_op",
        description = "Execute a read-only PAN-OS XML command rooted at <show> on an authorized device, with output caps. Output is redacted: secret-shaped values such as phash, private keys, pre-shared keys, and shared-secret fields (RADIUS/LDAP server secrets, SNMP community strings, etc.) are redacted; structure and non-secret output remain"
    )]
    async fn execute_panos_op(
        &self,
        Parameters(input): Parameters<ExecutePanosOpInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(&extensions, "execute_panos_op", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .execute_panos_op(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Read running or candidate configuration under `/config`.
    #[tool(
        name = "get_panos_config",
        description = "Read running or candidate PAN-OS configuration at a validated /config XPath on an authorized device. Output is redacted: secret-shaped values such as phash, private keys, pre-shared keys, and shared-secret fields (RADIUS/LDAP server secrets, SNMP community strings, etc.) are redacted; structure and non-secret configuration remain"
    )]
    async fn get_panos_config(
        &self,
        Parameters(input): Parameters<GetPanosConfigInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(&extensions, "get_panos_config", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panos_config(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Page through a rule or object list container's entries.
    #[tool(
        name = "list_panos_entries",
        description = "List <entry> children of a PAN-OS rulebase or object list XPath as structured JSON, paginated and truncation-marked rather than erroring on a large rulebase. Each entry's XML is redacted: secret-shaped values such as phash, private keys, pre-shared keys, and shared-secret fields are redacted; structure and non-secret configuration remain. The per-entry digest is computed before redaction, so drift detection is unaffected"
    )]
    async fn list_panos_entries(
        &self,
        Parameters(input): Parameters<ListPanosEntriesInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "list_panos_entries", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .list_panos_entries(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// List Panorama device groups and their member firewall serials.
    #[tool(
        name = "list_panorama_device_groups",
        description = "List Panorama device groups and the serial numbers of their member firewalls"
    )]
    async fn list_panorama_device_groups(
        &self,
        Parameters(input): Parameters<ListPanoramaDeviceGroupsInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            &extensions,
            "list_panorama_device_groups",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .list_panorama_device_groups(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// List Panorama templates and their declared variable names.
    #[tool(
        name = "list_panorama_templates",
        description = "List Panorama templates and the names of their declared variables"
    )]
    async fn list_panorama_templates(
        &self,
        Parameters(input): Parameters<ListPanoramaTemplatesInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "list_panorama_templates", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .list_panorama_templates(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Read a Panorama push job's overall and per-device status.
    #[tool(
        name = "get_panorama_push_status",
        description = "Read a Panorama commit-all/push job's overall and per-target-firewall status by job id"
    )]
    async fn get_panorama_push_status(
        &self,
        Parameters(input): Parameters<GetPanoramaPushStatusInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panorama_push_status", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panorama_push_status(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// List a rulebase or object container's entries by typed kind and vsys.
    #[tool(
        name = "list_panos_rulebase_entries",
        description = "List security rules, NAT rules, address objects, or service objects for a vsys as structured JSON, paginated and truncation-marked"
    )]
    async fn list_panos_rulebase_entries(
        &self,
        Parameters(input): Parameters<ListPanosRulebaseEntriesInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            &extensions,
            "list_panos_rulebase_entries",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .list_panos_rulebase_entries(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Read high-availability state.
    #[tool(
        name = "get_panos_ha_state",
        description = "Read PAN-OS high-availability state (enabled, mode, local and peer state) on an authorized device"
    )]
    async fn get_panos_ha_state(
        &self,
        Parameters(input): Parameters<GetPanosHaStateInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panos_ha_state", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panos_ha_state(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Read license status.
    #[tool(
        name = "get_panos_license_info",
        description = "Read PAN-OS license status (feature, serial, issued, expires, expired) on an authorized device"
    )]
    async fn get_panos_license_info(
        &self,
        Parameters(input): Parameters<GetPanosLicenseInfoInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panos_license_info", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panos_license_info(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Read content version status.
    #[tool(
        name = "get_panos_content_status",
        description = "Read PAN-OS content version status (version, released, downloaded, current) on an authorized device"
    )]
    async fn get_panos_content_status(
        &self,
        Parameters(input): Parameters<GetPanosContentStatusInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panos_content_status", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panos_content_status(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Read software version status.
    #[tool(
        name = "get_panos_software_status",
        description = "Read PAN-OS software version status (version, released, downloaded, current, latest) on an authorized device"
    )]
    async fn get_panos_software_status(
        &self,
        Parameters(input): Parameters<GetPanosSoftwareStatusInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            &extensions,
            "get_panos_software_status",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panos_software_status(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Test which security rule a simulated packet would match.
    #[tool(
        name = "test_panos_security_policy_match",
        description = "Test which PAN-OS security rule, if any, a simulated packet (source, destination, port, protocol, zones, application, user) would match on an authorized device"
    )]
    async fn test_panos_security_policy_match(
        &self,
        Parameters(input): Parameters<TestPanosSecurityPolicyMatchInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(
            &extensions,
            "test_panos_security_policy_match",
            Some(&input.device),
        ) {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .test_panos_security_policy_match(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Fetch a bounded window of PAN-OS logs.
    #[tool(
        name = "query_panos_logs",
        description = "Fetch a bounded window of PAN-OS logs (traffic, threat, system, or config) on an authorized device; always capped, never unbounded"
    )]
    async fn query_panos_logs(
        &self,
        Parameters(input): Parameters<QueryPanosLogsInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) = Self::authorize(&extensions, "query_panos_logs", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .query_panos_logs(input, caller.as_ref(), cancellation)
                .await,
        )
    }

    /// Digest one entry for single-rule drift detection.
    #[tool(
        name = "get_panos_entry_digest",
        description = "Fetch and hash exactly one PAN-OS config entry by XPath, without reading the rest of the configuration -- for detecting drift on a single rule or object"
    )]
    async fn get_panos_entry_digest(
        &self,
        Parameters(input): Parameters<GetPanosEntryDigestInput>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> std::result::Result<CallToolResult, rmcp::ErrorData> {
        if let Some(denial) =
            Self::authorize(&extensions, "get_panos_entry_digest", Some(&input.device))
        {
            return Ok(denial);
        }
        let service = self.runtime.snapshot().service.clone();
        let caller = Self::caller(&extensions);
        Self::to_call_result(
            service
                .get_panos_entry_digest(input, caller.as_ref(), cancellation)
                .await,
        )
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for PanosMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rust-panosmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "PAN-OS MCP server. Remote callers are restricted by exact bearer-token tool and device scopes.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_principal_refuses_unauthenticated_http_but_allows_stdio() {
        // Local stdio: no Parts, no caller → defaults to "local-stdio"
        let local = Extensions::default();
        assert_eq!(
            PanosMcpServer::mutation_principal(&local).expect("local stdio"),
            "local-stdio"
        );

        // HTTP with Parts but no CallerCtx → denied (fail closed)
        let (parts, _) = http::Request::new(()).into_parts();
        let mut remote = Extensions::default();
        remote.insert(parts);
        assert!(
            PanosMcpServer::mutation_principal(&remote).is_err(),
            "HTTP without caller must be denied"
        );
    }

    #[test]
    fn authorize_denies_http_without_caller_but_allows_stdio() {
        // stdio: no Parts → no caller is legitimate → allow
        let stdio = Extensions::default();
        assert!(
            PanosMcpServer::authorize(&stdio, "list_devices", None).is_none(),
            "stdio without caller must be allowed"
        );

        // HTTP: Parts present, no CallerCtx → deny
        let (parts, _) = http::Request::new(()).into_parts();
        let mut http = Extensions::default();
        http.insert(parts);
        let denial = PanosMcpServer::authorize(&http, "list_devices", None);
        assert!(
            denial.is_some(),
            "HTTP without caller must be denied (fail closed)"
        );
        // Verify it's the right error message
        if let Some(result) = denial {
            let text = result
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| &t.text);
            assert!(
                text.is_some_and(|msg| msg.contains("authenticated HTTP transport")),
                "error must mention HTTP authentication requirement"
            );
        }
    }
}
