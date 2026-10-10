//! Fingerprint-bound, per-device serialized PAN-OS candidate lifecycle.

use crate::{
    PanosMcpError, Result,
    client::PanosClient,
    observability::AuditScope,
    tools::{LIST_CONTAINER_ENTRY_DEPTH, PanosService},
    xml::{parse_job_id, scan_config_entries, validate_config_element, validate_write_xpath},
};
use mecmcp_audit::Attribution;
use quick_xml::escape::escape;
use rust_panosmcp_auth::CallerContext;
use rust_panosmcp_auth::{Grant, MutationAction, MutationGrant};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

// Import shared types - no longer aliased since local types are deleted
pub use mecmcp_changeset::OperationLimits as PublicOperationLimits;
use mecmcp_changeset::{
    ChangeSetRecord, ChangeSetState, ChangesetCoordinator, CoordinatorError, LifecycleState,
    OperationRecord,
};
pub use mecmcp_changeset::{RecoveryDisposition, resolve_persisted_operation};

pub(crate) const MAX_OPERATIONS: usize = 1024;
pub(crate) const MAX_CHANGE_SETS: usize = 1024;
pub(crate) const MAX_CHANGE_SET_ACTIONS: usize = 64;
pub(crate) const MAX_CHANGE_SET_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const APPROVAL_TTL_SECS: u64 = 15 * 60;
const MAX_DIFF_BYTES: usize = 256 * 1024;
const VALIDATE_DEADLINE: Duration = Duration::from_secs(300);
const COMMIT_DEADLINE: Duration = Duration::from_secs(600);
/// Maximum sibling entries scanned to confirm a `move` target and destination
/// exist before anything is sent to PAN-OS. Bounded independently of
/// `MAX_LIST_LIMIT` (which paginates a caller-facing read): this is an
/// internal existence check over one full container response, and a
/// container holding more entries than this cannot be validated -- the move
/// is refused rather than silently checked against a partial view.
const MAX_MOVE_SIBLING_ENTRIES: usize = 20_000;

/// Maps `CoordinatorError` from the shared coordinator to this crate's error type.
///
/// Preserves the coordinator's error categories: cancellation errors map to
/// `Cancelled`, persistence failures map to `Configuration`, and policy/state
/// violations map to `Policy`.
pub(crate) fn coord_error(error: CoordinatorError) -> PanosMcpError {
    // Cancellation is signaled by field "device" + message "operation cancelled"
    if error.field() == "device" && error.message() == "operation cancelled" {
        return PanosMcpError::Cancelled;
    }

    // Persistence failures are signaled by field "state"
    if error.field() == "state" {
        return PanosMcpError::Configuration(format!(
            "changeset state persistence failed: {}",
            error.message()
        ));
    }

    // All other coordinator errors are policy/lifecycle refusals
    PanosMcpError::Policy {
        field: error.field(),
        reason: error.message().to_owned(),
    }
}

/// Let `?` carry a coordinator error straight through.
///
/// Most coordinator refusals are policy refusals (digest mismatch, not approved,
/// wrong state), but cancellation and persistence failures have their own categories.
/// The `From` impl delegates to `coord_error` to preserve the distinction.
impl From<CoordinatorError> for PanosMcpError {
    fn from(error: CoordinatorError) -> Self {
        coord_error(error)
    }
}

/// Extracts the primary `StageAction` from a JSON value serialized by this crate.
///
/// The shared coordinator stores `action` as `serde_json::Value`. This function
/// deserializes it back to the local `StageAction` enum.
fn extract_stage_action(value: &serde_json::Value) -> Result<StageAction> {
    serde_json::from_value(value.clone()).map_err(|error| {
        PanosMcpError::Configuration(format!("could not deserialize action: {error}"))
    })
}

/// Serializes a `StageAction` to JSON for storage in the shared coordinator.
fn serialize_stage_action(action: StageAction) -> Result<serde_json::Value> {
    serde_json::to_value(action).map_err(|error| {
        PanosMcpError::Configuration(format!("could not serialize action: {error}"))
    })
}

/// Extracts the primary XPath target from an operation record.
///
/// The `xpath` field is optional in the shared schema (Junos omits it), but PAN-OS
/// operations always carry it. Returns `None` only if the field is missing.
fn extract_xpath(record: &OperationRecord) -> Option<String> {
    record.xpath.clone()
}

/// Whether `change_set` carries a genuine two-person approval or a lab-mode
/// waiver — either satisfies "independent approval before apply".
///
/// Lab mode's auto-approval (see `create_panos_change_set`) records
/// `approval.waived` rather than inventing an `approver`, so a check that
/// only looks at `approver` treats every lab-mode change set as unapproved
/// and locks out apply under `--lab-mode` (MEC-2687). A waiver counts only
/// while this deployment is currently in lab mode, so a change set waived
/// before a mode switch to two-person mode does not apply without a real
/// approver.
fn change_set_is_independently_approved(change_set: &ChangeSetRecord, lab_mode: bool) -> bool {
    match &change_set.approval {
        Some(approval) => approval.approver.is_some() || (lab_mode && approval.waived.is_some()),
        None => change_set.approver.is_some(),
    }
}

/// Converts a `ChangeSetRecord` to the local `ChangeSetOutput` type.
///
/// This is the output projection visible to callers. The record is vendor-neutral
/// and stores actions as JSON; this extracts and deserializes them to the local
/// `ChangeSetAction` type.
fn changeset_record_to_output(record: &ChangeSetRecord) -> Result<ChangeSetOutput> {
    let actions: Vec<ChangeSetAction> = record
        .actions
        .iter()
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                PanosMcpError::Configuration(format!(
                    "could not deserialize change-set action: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ChangeSetOutput {
        change_set_id: record.id.clone(),
        device: record.device.clone(),
        owner: record.owner.clone(),
        digest: record.digest.clone(),
        expected_candidate_fingerprint: record.expected_candidate_fingerprint.clone(),
        actions,
        state: record.state.as_str().to_owned(),
        approval_waiver: record
            .approval
            .as_ref()
            .and_then(|approval| approval.waived.as_ref())
            .map(|waiver| waiver.reason.clone()),
        approver: record
            .approval
            .as_ref()
            .and_then(|a| a.approver.clone())
            .or_else(|| record.approver.clone()),
        expires_at_unix: record.expires_at_unix,
        operation_id: record.operation_id.clone(),
    })
}

/// Candidate configuration action supported by the guarded stage tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageAction {
    /// Merge the supplied XML element at the XPath.
    Set,
    /// Delete the exact XPath after policy and confirmation checks.
    Delete,
    /// Reorder the exact rulebase entry at the XPath relative to a sibling,
    /// or to the top/bottom of its container.
    Move,
}

impl StageAction {
    pub(crate) const fn api_name(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Delete => "delete",
            Self::Move => "move",
        }
    }
}

impl From<StageAction> for MutationAction {
    fn from(value: StageAction) -> Self {
        match value {
            StageAction::Set => Self::Set,
            StageAction::Delete => Self::Delete,
            StageAction::Move => Self::Move,
        }
    }
}

/// Position of a `move` action relative to a sibling entry, or the
/// container's own top/bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MovePosition {
    /// Immediately before `move_destination`.
    Before,
    /// Immediately after `move_destination`.
    After,
    /// First entry in the container; `move_destination` must be absent.
    Top,
    /// Last entry in the container; `move_destination` must be absent.
    Bottom,
}

impl MovePosition {
    pub(crate) const fn api_name(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Top => "top",
            Self::Bottom => "bottom",
        }
    }

    /// Whether this position names a sibling in `move_destination`.
    const fn requires_destination(self) -> bool {
        matches!(self, Self::Before | Self::After)
    }
}

/// One action in an exact, digest-bound change set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetAction {
    /// Set, delete, or move.
    pub action: StageAction,
    /// Exact XPath within both inventory and token policy. For move, the
    /// exact XPath of the entry being reordered.
    pub xpath: String,
    /// One XML element; required for set and forbidden for delete or move.
    #[serde(default)]
    pub element: Option<String>,
    /// For delete, must equal `DELETE <xpath>` exactly. Forbidden for set and move.
    #[serde(default)]
    pub destructive_confirmation: Option<String>,
    /// Required for move, forbidden otherwise.
    #[serde(default)]
    pub move_position: Option<MovePosition>,
    /// Sibling entry name; required when `move_position` is before/after,
    /// forbidden otherwise, and forbidden for set and delete.
    #[serde(default)]
    pub move_destination: Option<String>,
}

/// Input for planning a multi-action change set without mutating PAN-OS.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateChangeSetInput {
    /// Exact inventory device.
    pub device: String,
    /// Candidate fingerprint to which this plan is bound.
    pub expected_candidate_fingerprint: String,
    /// Ordered actions; all are covered by one digest and approval.
    pub actions: Vec<ChangeSetAction>,
}

/// Input for approving the exact digest of another principal's plan.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveChangeSetInput {
    /// Exact inventory device.
    pub device: String,
    /// Planned change-set identifier.
    pub change_set_id: String,
    /// Exact digest returned by create/get.
    pub expected_digest: String,
}

/// Input for applying a previously approved plan.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyChangeSetInput {
    /// Exact inventory device.
    pub device: String,
    /// Approved change-set identifier.
    pub change_set_id: String,
    /// Exact approved digest.
    pub expected_digest: String,
    /// Candidate fingerprint originally bound into the plan.
    pub expected_candidate_fingerprint: String,
}

/// Input for reading safe change-set state and its exact reviewed actions.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetStatusInput {
    /// Exact inventory device.
    pub device: String,
    /// Change-set identifier.
    pub change_set_id: String,
}

/// Persistent planned/approved/applied change-set metadata.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ChangeSetOutput {
    /// Random change-set identifier.
    pub change_set_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Principal that owns and may apply the plan.
    pub owner: String,
    /// SHA-256 binding owner, device, pre-fingerprint, and ordered actions.
    pub digest: String,
    /// Candidate fingerprint to which the plan is bound.
    pub expected_candidate_fingerprint: String,
    /// Exact ordered actions covered by the digest.
    pub actions: Vec<ChangeSetAction>,
    /// Planned, approved, applied, expired, or failed.
    pub state: String,
    /// Independent approver, when approved.
    pub approver: Option<String>,
    /// Why approval was waived, when it was.
    ///
    /// `None` on an ordinary change set. `Some("lab-mode")` when a
    /// single-operator server approved it without a second principal.
    /// `approver: None` alone cannot carry this — it means both "not yet
    /// approved" and "approved without review" (mecmcp#94).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_waiver: Option<String>,
    /// Approval deadline.
    pub expires_at_unix: u64,
    /// Lifecycle operation created by apply, when available.
    pub operation_id: Option<String>,
}

/// Input for candidate fingerprint retrieval.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateFingerprintInput {
    /// Exact inventory device.
    pub device: String,
}

/// Stable candidate fingerprint.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CandidateFingerprintOutput {
    /// Exact inventory device.
    pub device: String,
    /// SHA-256 over every operator-authorized candidate subtree.
    pub candidate_fingerprint: String,
}

/// Input for a guarded candidate change.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageConfigInput {
    /// Exact inventory device.
    pub device: String,
    /// Candidate fingerprint observed immediately before staging.
    pub expected_candidate_fingerprint: String,
    /// Set, delete, or move.
    pub action: StageAction,
    /// Exact XPath within an operator-configured root. For move, the exact
    /// XPath of the entry being reordered.
    pub xpath: String,
    /// One XML element; required for set and forbidden for delete or move.
    #[serde(default)]
    pub element: Option<String>,
    /// For delete, must equal `DELETE <xpath>` exactly. Forbidden for set and move.
    #[serde(default)]
    pub destructive_confirmation: Option<String>,
    /// Required for move, forbidden otherwise.
    #[serde(default)]
    pub move_position: Option<MovePosition>,
    /// Sibling entry name; required when `move_position` is before/after,
    /// forbidden otherwise, and forbidden for set and delete.
    #[serde(default)]
    pub move_destination: Option<String>,
}

/// Result of staging one candidate change.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StageConfigOutput {
    /// Random operation identifier required by later lifecycle calls.
    pub operation_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Candidate fingerprint before mutation.
    pub before_fingerprint: String,
    /// Candidate fingerprint after mutation.
    pub candidate_fingerprint: String,
    /// Whether a PAN-OS configuration lock is being held for this operation.
    pub config_lock_held: bool,
}

/// Input identifying a previously staged operation.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationInput {
    /// Exact inventory device.
    pub device: String,
    /// Operation identifier returned by stage.
    pub operation_id: String,
    /// Candidate fingerprint expected at this lifecycle step.
    pub expected_candidate_fingerprint: String,
}

/// Candidate change summary tied to one operation.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CandidateDiffOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Staged action.
    pub action: StageAction,
    /// Target XPath.
    pub xpath: String,
    /// Candidate fingerprint at diff time.
    pub candidate_fingerprint: String,
    /// PAN-OS change-summary XML, bounded independently of the device response cap.
    pub change_summary: String,
    /// Whether the change summary was truncated.
    pub truncated: bool,
}

/// Validation result.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ValidationOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// PAN-OS validation job identifier.
    pub job_id: String,
    /// Terminal result.
    pub succeeded: bool,
    /// Bounded terminal details.
    pub details: Option<String>,
    /// Fingerprint that is now eligible for commit.
    pub candidate_fingerprint: String,
}

/// Commit caller disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitDisposition {
    /// Commit job reached a terminal state before the caller cancelled.
    Reconciled,
    /// Caller cancelled while the detached worker continued reconciliation.
    Detached,
}

/// Commit result or detached acknowledgement.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CommitOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Caller disposition.
    pub disposition: CommitDisposition,
    /// Job identifier when already available.
    pub job_id: Option<String>,
    /// Terminal success when reconciled; absent while detached.
    pub succeeded: Option<bool>,
    /// Bounded terminal details.
    pub details: Option<String>,
}

/// Discard result.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiscardOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Candidate fingerprint after admin-scoped partial revert.
    pub candidate_fingerprint: String,
}

/// Safe operation state for polling and recovery.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct OperationStatusOutput {
    /// Operation identifier.
    pub operation_id: String,
    /// Exact inventory device.
    pub device: String,
    /// Lifecycle state.
    pub state: String,
    /// PAN-OS job identifier when known.
    pub job_id: Option<String>,
    /// Current candidate fingerprint when known.
    pub candidate_fingerprint: String,
    /// Bounded terminal details.
    pub details: Option<String>,
}

/// Input for polling a lifecycle operation without authorizing a new action.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusInput {
    /// Exact inventory device.
    pub device: String,
    /// Operation identifier returned by stage.
    pub operation_id: String,
}

impl PanosService {
    /// Fingerprint every operator-authorized candidate subtree.
    pub async fn candidate_fingerprint(
        &self,
        input: CandidateFingerprintInput,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<CandidateFingerprintOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_candidate_fingerprint",
                "get-fingerprint",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_candidate_fingerprint",
                "get-fingerprint",
                vec![input.device.clone()],
            ),
        };
        let result = async {
            let client = self.client(&input.device)?;
            require_policy(&client)?;
            let candidate = candidate_fingerprint(&client, cancellation).await?;
            Ok(CandidateFingerprintOutput {
                device: input.device,
                candidate_fingerprint: candidate,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Plan and persist an exact multi-action change set without mutating PAN-OS.
    pub async fn create_change_set(
        &self,
        input: CreateChangeSetInput,
        ctx: Option<&CallerContext>,
        owner: &str,
        grant: Option<&MutationGrant>,
        cancellation: CancellationToken,
    ) -> Result<ChangeSetOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "create_panos_change_set",
                "plan",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "create_panos_change_set",
                "plan",
                vec![input.device.clone()],
            ),
        };

        let result = async {
            validate_fingerprint(&input.expected_candidate_fingerprint)?;
            let client = self.client(&input.device)?;
            let policy = require_policy(&client)?;
            validate_change_set_actions(&input.actions, policy, grant)?;
            require_move_targets_exist(&client, &input.actions, cancellation.clone()).await?;
            let current = candidate_fingerprint(&client, cancellation.clone()).await?;
            require_fingerprint(&input.expected_candidate_fingerprint, &current)?;
            require_clean_candidate(&client, cancellation).await?;
            let now = now_unix()?;
            let id = new_operation_id()?;

            // Serialize actions to JSON for the shared coordinator
            let actions_json: Vec<serde_json::Value> = input
                .actions
                .iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, serde_json::Error>>()
                .map_err(|error| {
                    PanosMcpError::Configuration(format!("could not serialize actions: {error}"))
                })?;

            let digest = mecmcp_changeset::change_set_digest(
                owner,
                &input.device,
                &input.expected_candidate_fingerprint,
                &actions_json,
            )
            .map_err(|error| {
                PanosMcpError::Configuration(format!("could not compute digest: {error}"))
            })?;

            // Keep policy_signature empty to maintain version 1 file format.
            // Version 2 triggers if policy_signature is non-empty, and the previous
            // binary cannot read version 2 files, preventing rollback. Policy drift
            // is checked on operations, not change-sets, so this is safe.
            let record = ChangeSetRecord {
                id: id.clone(),
                owner: owner.to_owned(),
                device: input.device.clone(),
                expected_candidate_fingerprint: input.expected_candidate_fingerprint,
                actions: actions_json,
                digest: digest.clone(),
                state: ChangeSetState::Planned,
                // This server does not yet implement MEC-994's step-up
                // verified-approver assertion (no `bind_approver` preflight
                // wired in), so there is no owner OIDC subject to record.
                // `None` preserves the pre-MEC-994 legacy approval path.
                owner_subject: None,
                approver: None,
                approval: None,
                // From the coordinator, not the constant: an operator who sets
                // --approval-timeout-secs would otherwise get their value applied
                // to the coordinator's own expiry checks while change sets kept
                // the compiled-in default, and the two would disagree.
                expires_at_unix: now.saturating_add(self.mutations.approval_ttl().as_secs()),
                operation_id: None,
                policy_signature: String::new(),
                // Same rule as policy_signature above: both of these gate the
                // file to version 2, which the previous binary cannot read.
                // PAN-OS applies to one device per change set, so the
                // single-target shape is the correct one here, not a
                // compatibility compromise — `record.targets()` still answers
                // with [device].
                targets: Vec::new(),
                preview: None,
                // Never an apply that lost its handle: this is a record being
                // created, and PAN-OS applies synchronously anyway. See the
                // note below on why there is no handle to record.
                apply_without_handle: false,
                // mecmcp 0.20.0 records a vendor task handle so an apply that
                // dies mid-flight leaves something to re-probe. A change set
                // never has one to record: its apply only issues synchronous
                // config requests, and it reaches `Applied` before the commit
                // is even started. The asynchronous PAN-OS commit job *is*
                // captured, but it belongs to the linked operation — see
                // `record.job_id` on the `OperationRecord` — so a crashed commit
                // is re-probed from there, by `operation_id`, not from here.
                //
                // `None` is also what keeps rollback working, for the same
                // reason as `policy_signature` and `targets` above: the field is
                // `skip_serializing_if = "Option::is_none"`, so an absent handle
                // never appears in the file and a previous binary, which rejects
                // unknown fields, can still read it.
                task_id: None,
            };
            self.mutations
                .insert_change_set(record.clone())
                .await
                .map_err(coord_error)?;

            audit.meta("change_set_id", id.clone());
            audit.meta("digest", digest.clone());
            audit.meta("action_count", record.actions.len() as u64);

            // Single-operator servers waive approval here rather than exposing a
            // tool to do it. Starting the service with `--lab-mode` is already the
            // deliberate decision to run without a second reviewer, so a
            // per-change-set waive call would be ceremony protecting nobody — and
            // the digest confirmation it would carry is already enforced by
            // `apply`, which is what touches the device (mecmcp#94).
            //
            // No approver is invented: the record keeps `approver: null` and gains
            // `approval_waiver`, so a waived change stays distinguishable from one
            // a second person reviewed.
            if self.mutations.lab_mode() {
                let waived = self
                    .mutations
                    .waive_approval(id, record.device.clone(), record.owner.clone(), digest)
                    .await
                    .map_err(coord_error)?;
                audit.meta("approval_waiver", "lab-mode");
                let mut output = changeset_record_to_output(&record)?;
                output.state = format!("{:?}", waived.state).to_lowercase();
                output.approver = None;
                output.approval_waiver = Some("lab-mode".to_owned());
                return Ok(output);
            }

            changeset_record_to_output(&record)
        }
        .await;

        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Approve the exact digest of another principal's unexpired plan.
    pub async fn approve_change_set(
        &self,
        input: ApproveChangeSetInput,
        ctx: Option<&CallerContext>,
        approver: &str,
    ) -> Result<ChangeSetOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "approve_panos_change_set",
                "approve",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "approve_panos_change_set",
                "approve",
                vec![input.device.clone()],
            ),
        };

        // Add change_set_id and digest to audit metadata BEFORE any checks
        // so they're emitted even on denial/failure
        audit.meta("change_set_id", input.change_set_id.clone());
        audit.meta("digest", input.expected_digest.clone());

        // rust_panosmcp_auth::ActorType (the caller-context type, re-exported
        // from mecmcp_auth) is a distinct enum from mecmcp_audit::ActorType
        // (what the coordinator gate checks against) -- converted explicitly
        // rather than assumed identical.
        let actor_type = match ctx.map(|c| c.actor_type) {
            Some(rust_panosmcp_auth::ActorType::Human) => mecmcp_audit::ActorType::Human,
            Some(rust_panosmcp_auth::ActorType::Agent) => mecmcp_audit::ActorType::Agent,
            Some(rust_panosmcp_auth::ActorType::Unknown) | None => mecmcp_audit::ActorType::Unknown,
        };

        // This server does not yet implement MEC-994's step-up
        // verified-approver assertion (no `bind_approver` preflight wired
        // in), so every approver is asserted by its bearer token alone --
        // the pre-MEC-994 identity, carried through unchanged.
        let approver_identity = mecmcp_changeset::ApproverIdentity::TokenAsserted {
            principal: approver.to_owned(),
            actor_type,
        };

        let result = async {
            // Use shared coordinator's approve_change_set which handles all validation
            let output = self
                .mutations
                .approve_change_set(
                    input.change_set_id.clone(),
                    input.device.clone(),
                    &approver_identity,
                    input.expected_digest,
                )
                .await
                .map_err(coord_error)?;

            // Add owner to metadata after successful approval
            audit.meta("owner", output.owner.clone());
            audit.meta("action_count", output.action_count as u64);

            // Fetch the full record to get the actions for our output
            let full_record = self
                .mutations
                .change_set(&output.change_set_id, &output.device)
                .await
                .map_err(coord_error)?;

            changeset_record_to_output(&full_record)
        }
        .await;

        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Return an exact persistent plan for independent review or recovery.
    pub async fn change_set_status(
        &self,
        input: ChangeSetStatusInput,
        ctx: Option<&CallerContext>,
    ) -> Result<ChangeSetOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_change_set",
                "get-change-set",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_change_set",
                "get-change-set",
                vec![input.device.clone()],
            ),
        };
        audit.meta("change_set_id", input.change_set_id.clone());
        let result = async {
            let mut record = self
                .mutations
                .change_set(&input.change_set_id, &input.device)
                .await
                .map_err(coord_error)?;
            if matches!(
                record.state,
                ChangeSetState::Planned | ChangeSetState::Approved
            ) && now_unix()? >= record.expires_at_unix
            {
                record.state = ChangeSetState::Expired;
                self.mutations
                    .update_change_set(record.clone())
                    .await
                    .map_err(coord_error)?;
            }
            changeset_record_to_output(&record)
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Apply an independently approved change set as one guarded lifecycle operation.
    pub async fn apply_change_set(
        &self,
        input: ApplyChangeSetInput,
        ctx: Option<&CallerContext>,
        owner: &str,
        grant: Option<&MutationGrant>,
        cancellation: CancellationToken,
    ) -> Result<StageConfigOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "apply_panos_change_set",
                "apply",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "apply_panos_change_set",
                "apply",
                vec![input.device.clone()],
            ),
        };

        audit.meta("change_set_id", input.change_set_id.clone());
        audit.meta("digest", input.expected_digest.clone());

        validate_digest(&input.expected_digest, "expected_digest")?;
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let mut change_set = self
            .mutations
            .change_set(&input.change_set_id, &input.device)
            .await?;
        if change_set.owner != owner {
            return Err(policy(
                "change_set_id",
                "only the principal that created the change set may apply it",
            ));
        }
        if change_set.state != ChangeSetState::Approved
            || !change_set_is_independently_approved(&change_set, self.mutations.lab_mode())
        {
            return Err(policy(
                "change_set_id",
                "change set requires independent approval before apply",
            ));
        }
        if now_unix()? >= change_set.expires_at_unix {
            change_set.state = ChangeSetState::Expired;
            self.mutations.update_change_set(change_set).await?;
            return Err(policy("change_set_id", "approved change set expired"));
        }
        if change_set.digest != input.expected_digest
            || change_set.expected_candidate_fingerprint != input.expected_candidate_fingerprint
        {
            return Err(policy(
                "expected_digest",
                "apply input does not match the exact approved plan",
            ));
        }
        let client = self.client(&input.device)?;
        let inventory_policy = require_policy(&client)?.clone();
        // Records hold vendor-opaque JSON now; policy validation still works on
        // the typed actions, so bring them back before checking.
        let typed_actions: Vec<ChangeSetAction> = change_set
            .actions
            .iter()
            .map(|value| serde_json::from_value(value.clone()))
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()
            .map_err(|error| {
                PanosMcpError::Configuration(format!(
                    "stored change-set action is unreadable: {error}"
                ))
            })?;
        validate_change_set_actions(&typed_actions, &inventory_policy, grant)?;
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await?;
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        change_set = self
            .mutations
            .change_set(&input.change_set_id, &input.device)
            .await?;
        if change_set.owner != owner
            || change_set.state != ChangeSetState::Approved
            || !change_set_is_independently_approved(&change_set, self.mutations.lab_mode())
            || change_set.digest != input.expected_digest
            || change_set.expected_candidate_fingerprint != input.expected_candidate_fingerprint
            || now_unix()? >= change_set.expires_at_unix
        {
            return Err(policy(
                "change_set_id",
                "change set is no longer the exact unexpired approved plan",
            ));
        }

        let operation_id = new_operation_id()?;
        let first_value = change_set
            .actions
            .first()
            .expect("validated change set is non-empty");
        let first: ChangeSetAction =
            serde_json::from_value(first_value.clone()).map_err(|error| {
                PanosMcpError::Configuration(format!("could not deserialize first action: {error}"))
            })?;

        let action_json = serialize_stage_action(first.action)?;
        let policy_sig = local_mutation_policy_signature(&inventory_policy);

        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            endpoint: client.mutation_lock_key(),
            action: action_json,
            xpath: Some(first.xpath.clone()),
            actions: change_set.actions.clone(),
            change_set_id: Some(change_set.id.clone()),
            current: input.expected_candidate_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: policy_sig,
            attribution: None,
            rollback_deadline_unix: None,
            config_authority: Some(client.config_authority().as_str().to_owned()),
        };
        self.mutations
            .insert(record.clone())
            .await
            .map_err(coord_error)?;
        let mut config_lock_held = false;
        if inventory_policy.require_config_lock {
            if let Err(error) = acquire_config_lock(&client, &operation_id).await {
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
            config_lock_held = true;
            record.config_lock_held = true;
            if let Err(error) = self
                .mutations
                .update(record.clone())
                .await
                .map_err(coord_error)
            {
                release_config_lock_best_effort(&client).await;
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        }
        let before = match candidate_fingerprint(&client, CancellationToken::new()).await {
            Ok(value) => value,
            Err(error) => {
                if config_lock_held {
                    release_config_lock_best_effort(&client).await;
                }
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        };
        if let Err(error) = require_fingerprint(&input.expected_candidate_fingerprint, &before) {
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }
        if let Err(error) = require_clean_candidate(&client, CancellationToken::new()).await {
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }
        // mecmcp 0.22.0 makes `claim_change_set_for_apply` the only legal
        // `Approved -> Applying` transition, and it does the read and the write
        // under one lock so two applies cannot both read `Approved` and both
        // push configuration. A plain `update_change_set` on this edge is
        // refused outright.
        //
        // `None`: a PAN-OS apply is synchronous and hands back no pollable
        // handle, so a crash mid-apply leaves an outcome only the device knows.
        // That is what `apply_without_handle` records, and it is the honest
        // state rather than an outcome nobody observed.
        let mut change_set = match self
            .mutations
            .claim_change_set_for_apply(
                &change_set.id,
                &change_set.device,
                mecmcp_changeset::ApplyHandle::None,
            )
            .await
            .map_err(coord_error)
        {
            Ok(claimed) => claimed,
            Err(error) => {
                if config_lock_held {
                    release_config_lock_best_effort(&client).await;
                }
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
        };
        change_set.operation_id = Some(operation_id.clone());
        if let Err(error) = self
            .mutations
            .update_change_set(change_set.clone())
            .await
            .map_err(coord_error)
        {
            // Nothing has been pushed to PAN-OS yet -- the actions are applied
            // below -- so this failure leaves a claimed record that never ran,
            // with no `operation_id` on it and its `OperationRecord` about to be
            // removed. `ApplyHandle::None` keeps `Applying` across a restart, so
            // without settling it here the owner could not retry, cancel or
            // reconcile it through any normal API. `Failed` is the true outcome.
            let mut abandoned = change_set.clone();
            abandoned.state = ChangeSetState::Failed;
            abandoned.operation_id = None;
            if let Err(settle_error) = self.mutations.update_change_set(abandoned).await {
                tracing::error!(
                    target: "audit",
                    %settle_error,
                    change_set = %change_set.id,
                    "claimed change set left applying after its operation id could not be \
                     persisted; nothing was sent to the device, but it needs an operator"
                );
            }
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            self.mutations.remove(&operation_id).await;
            return Err(error);
        }

        let mut applied = 0_usize;
        let apply_result: Result<()> = async {
            for action_value in &change_set.actions {
                let action: ChangeSetAction = serde_json::from_value(action_value.clone())
                    .map_err(|error| {
                        PanosMcpError::Configuration(format!(
                            "could not deserialize action: {error}"
                        ))
                    })?;
                let mut fields = vec![
                    ("type", "config".to_owned()),
                    ("action", action.action.api_name().to_owned()),
                    ("xpath", action.xpath.clone()),
                ];
                if let Some(element) = &action.element {
                    fields.push(("element", element.clone()));
                }
                if let Some(position) = action.move_position {
                    fields.push(("where", position.api_name().to_owned()));
                }
                if let Some(destination) = &action.move_destination {
                    fields.push(("dst", destination.clone()));
                }
                client.post_fields(fields, CancellationToken::new()).await?;
                applied += 1;
            }
            Ok(())
        }
        .await;

        if let Err(error) = apply_result {
            let original = error.to_string();
            let reverted = if applied > 0 {
                revert_admin_candidate(&client, &inventory_policy.admin).await
            } else {
                Ok(())
            };
            record.state = if reverted.is_ok() {
                LifecycleState::Discarded
            } else {
                LifecycleState::Indeterminate
            };
            record.details = Some(match &reverted {
                Ok(()) => {
                    format!("apply failed after {applied} actions and was reverted: {original}")
                }
                Err(revert) => format!(
                    "apply failed after {applied} actions: {original}; automatic revert failed: {revert}"
                ),
            });
            if let Ok(current) = candidate_fingerprint(&client, CancellationToken::new()).await {
                record.current = current;
            }
            self.mutations
                .update(record.clone())
                .await
                .map_err(coord_error)?;
            change_set.state = ChangeSetState::Failed;
            change_set.operation_id = Some(operation_id.clone());
            self.mutations
                .update_change_set(change_set)
                .await
                .map_err(coord_error)?;
            if config_lock_held {
                release_config_lock_best_effort(&client).await;
            }
            audit.meta("operation_id", operation_id.clone());
            audit.fail(&error);
            return match reverted {
                Ok(()) => Err(error),
                Err(revert) => Err(PanosMcpError::Configuration(format!(
                    "change-set apply and automatic revert failed: {original}; {revert}"
                ))),
            };
        }

        let after = match candidate_fingerprint(&client, CancellationToken::new()).await {
            Ok(value) => value,
            Err(error) => {
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!(
                    "all actions were accepted but the resulting fingerprint could not be read: {error}"
                ));
                self.mutations.update(record).await.map_err(coord_error)?;
                change_set.state = ChangeSetState::Failed;
                change_set.operation_id = Some(operation_id.clone());
                self.mutations
                    .update_change_set(change_set)
                    .await
                    .map_err(coord_error)?;
                audit.meta("operation_id", operation_id);
                audit.fail(&error);
                return Err(error);
            }
        };
        record.current = after.clone();
        record.state = LifecycleState::Staged;
        self.mutations.update(record).await?;
        change_set.state = ChangeSetState::Applied;
        change_set.operation_id = Some(operation_id.clone());
        self.mutations.update_change_set(change_set.clone()).await?;

        audit.meta("operation_id", operation_id.clone());
        audit.meta("approver", change_set.approver.unwrap_or_default());
        audit.meta("action_count", change_set.actions.len() as u64);
        audit.succeed();

        Ok(StageConfigOutput {
            operation_id,
            device: input.device,
            before_fingerprint: before,
            candidate_fingerprint: after,
            config_lock_held,
        })
    }

    /// Stage one fingerprint-guarded candidate mutation.
    ///
    /// `grant`, when the caller's token carries one, narrows the device-wide
    /// `allowed_xpath_roots`/action policy to that token's own scope -- the
    /// same enforcement `create_panos_change_set`/`apply_panos_change_set`
    /// apply. Without this, a token holding a mutation grant narrower than
    /// the device policy (e.g. one vsys) could still write anywhere in the
    /// device's full policy through this v0.1 tool (MEC-528 class 2).
    pub async fn stage_config(
        &self,
        input: StageConfigInput,
        owner: &str,
        grant: Option<&MutationGrant>,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<StageConfigOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "stage_panos_config",
                "stage",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("stage_panos_config", "stage", vec![input.device.clone()]),
        };
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?.clone();
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        validate_write_xpath(&input.xpath, &policy.allowed_xpath_roots)?;
        validate_stage_payload(&input, policy.allow_delete)?;
        if let Some(grant) = grant {
            if !grant.allows_action(input.action.into()) {
                let error = self::policy("action", "action is outside this token's mutation grant");
                audit.fail(&error);
                return Err(error);
            }
            if !grant.allows_xpath(&input.xpath) {
                let error = self::policy("xpath", "XPath is outside this token's mutation grant");
                audit.fail(&error);
                return Err(error);
            }
        }
        if input.action == StageAction::Move {
            let (container, moved_name) = match extract_move_target(&input.xpath) {
                Ok(target) => target,
                Err(error) => {
                    audit.fail(&error);
                    return Err(error);
                }
            };
            if let Err(error) = require_move_target_exists(
                &client,
                &container,
                &moved_name,
                input.move_destination.as_deref(),
                cancellation.clone(),
            )
            .await
            {
                audit.fail(&error);
                return Err(error);
            }
        }
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await
            .map_err(coord_error)?;
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        let operation_id = new_operation_id()?;

        let action_json = serialize_stage_action(input.action)?;
        let policy_sig = local_mutation_policy_signature(&policy);

        let action_value = serde_json::to_value(&ChangeSetAction {
            action: input.action,
            xpath: input.xpath.clone(),
            element: input.element.clone(),
            destructive_confirmation: input.destructive_confirmation.clone(),
            move_position: input.move_position,
            move_destination: input.move_destination.clone(),
        })
        .map_err(|error| {
            PanosMcpError::Configuration(format!("could not serialize action: {error}"))
        })?;

        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: input.device.clone(),
            endpoint: client.mutation_lock_key(),
            action: action_json,
            xpath: Some(input.xpath.clone()),
            actions: vec![action_value],
            change_set_id: None,
            current: input.expected_candidate_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: policy_sig,
            attribution: None,
            rollback_deadline_unix: None,
            config_authority: Some(client.config_authority().as_str().to_owned()),
        };
        self.mutations
            .insert(record.clone())
            .await
            .map_err(coord_error)?;
        let mut config_lock_held = false;
        if policy.require_config_lock {
            if let Err(error) = acquire_config_lock(&client, &operation_id).await {
                self.mutations.remove(&operation_id).await;
                return Err(error);
            }
            config_lock_held = true;
            record.config_lock_held = true;
        }
        let result = async {
            let before = candidate_fingerprint(&client, CancellationToken::new()).await?;
            require_fingerprint(&input.expected_candidate_fingerprint, &before)?;
            require_clean_candidate(&client, CancellationToken::new()).await?;
            let mut fields = vec![
                ("type", "config".to_owned()),
                ("action", input.action.api_name().to_owned()),
                ("xpath", input.xpath.clone()),
            ];
            if let Some(element) = &input.element {
                fields.push(("element", element.clone()));
            }
            if let Some(position) = input.move_position {
                fields.push(("where", position.api_name().to_owned()));
            }
            if let Some(destination) = &input.move_destination {
                fields.push(("dst", destination.clone()));
            }
            client.post_fields(fields, CancellationToken::new()).await?;
            let after = candidate_fingerprint(&client, CancellationToken::new()).await?;
            record.current = after.clone();
            record.state = LifecycleState::Staged;
            self.mutations
                .update(record.clone())
                .await
                .map_err(coord_error)?;
            Ok(StageConfigOutput {
                operation_id: operation_id.clone(),
                device: input.device.clone(),
                before_fingerprint: before,
                candidate_fingerprint: after,
                config_lock_held,
            })
        }
        .await;
        if result.is_err() && config_lock_held {
            release_config_lock_best_effort(&client).await;
        }
        if result.is_err() {
            self.mutations.remove(&operation_id).await;
        }
        audit.meta("operation_id", operation_id.clone());
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Return a bounded PAN-OS candidate change summary.
    pub async fn diff_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<CandidateDiffOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "diff_panos_candidate",
                "diff",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio("diff_panos_candidate", "diff", vec![input.device.clone()]),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
            validate_fingerprint(&input.expected_candidate_fingerprint)?;
            let record = self
                .mutations
                .record(&input.operation_id, owner, &input.device)
                .await
                .map_err(coord_error)?;
            let client = self.client(&input.device)?;
            let policy = require_policy(&client)?;
            let policy_sig = local_mutation_policy_signature(policy);
            mecmcp_changeset::require_operation_policy(&record, &policy_sig)
                .map_err(|e| crate::mutation::policy(e.field(), e.message()))?;
            let current = candidate_fingerprint(&client, cancellation.clone()).await?;
            mecmcp_changeset::require_operation_fingerprint(
                &record,
                &input.expected_candidate_fingerprint,
                &current,
            )
            .map_err(|e| crate::mutation::policy(e.field(), e.message()))?;
            let response = client
                .post_fields(
                    vec![
                        ("type", "op".to_owned()),
                        (
                            "cmd",
                            "<show><config><list><change-summary/></list></config></show>"
                                .to_owned(),
                        ),
                    ],
                    cancellation,
                )
                .await?;
            let redacted_xml = crate::redact::redact_device_xml(&response.xml);
            let (change_summary, truncated) = truncate_utf8(redacted_xml, MAX_DIFF_BYTES);
            let action = extract_stage_action(&record.action)?;
            let xpath = extract_xpath(&record).ok_or_else(|| {
                PanosMcpError::Configuration("operation record missing xpath".to_owned())
            })?;
            Ok(CandidateDiffOutput {
                operation_id: record.id,
                device: record.device,
                action,
                xpath,
                candidate_fingerprint: current,
                change_summary,
                truncated,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Validate the exact staged candidate and transition it to commit-eligible.
    pub async fn validate_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<ValidationOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "validate_panos_candidate",
                "validate",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "validate_panos_candidate",
                "validate",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
            validate_fingerprint(&input.expected_candidate_fingerprint)?;
            let mut record = self
                .mutations
                .record(&input.operation_id, owner, &input.device)
                .await?;
            if record.state != LifecycleState::Staged {
                return Err(policy("operation_id", "operation is not in staged state"));
            }
            let client = self.client(&input.device)?;
            require_operation_policy(&record, &client)?;
            let _guard = self
                .mutations
                .device_guard(&client.mutation_lock_key(), &cancellation)
                .await?;
            let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
            require_operation_fingerprint(&input, &record, &current)?;
            let response = client
                .post_fields(
                    vec![
                        ("type", "op".to_owned()),
                        ("cmd", "<validate><full></full></validate>".to_owned()),
                    ],
                    CancellationToken::new(),
                )
                .await?;
            let job_id = parse_job_id(&response)?;
            record.job_id = Some(job_id.clone());
            record.state = LifecycleState::Validating;
            self.mutations.update(record.clone()).await?;
            let status = match client
                .poll_job(&job_id, VALIDATE_DEADLINE, CancellationToken::new())
                .await
            {
                Ok(status) => status,
                Err(error) => {
                    record.state = LifecycleState::Failed;
                    record.details = Some(error.to_string());
                    self.mutations.update(record.clone()).await?;
                    return Err(error);
                }
            };
            record.details = status.details.clone();
            record.state = if status.succeeded() {
                LifecycleState::Validated
            } else {
                LifecycleState::Failed
            };
            self.mutations.update(record.clone()).await?;
            Ok(ValidationOutput {
                operation_id: record.id,
                job_id,
                succeeded: status.succeeded(),
                details: status.details,
                candidate_fingerprint: current,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Start an admin-scoped partial commit and reconcile it in a detached worker.
    pub async fn commit_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<CommitOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "commit_panos_candidate",
                "commit",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "commit_panos_candidate",
                "commit",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        // Set when the direct-commit gate refuses: DirectCommitPolicy::check
        // has already marked the scope Denied(direct_commit_disabled), and the
        // generic `audit.fail(e)` below must not overwrite that (Percy F2).
        let mut direct_commit_refused = false;
        let result = async {
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let mut record = self
            .mutations
            .record(&input.operation_id, owner, &input.device)
            .await?;
        if record.state != LifecycleState::Validated {
            return Err(policy(
                "operation_id",
                "operation must validate successfully before commit",
            ));
        }

        // An operation with no change_set_id came from stage_config directly,
        // not from create_change_set / approve_change_set / apply_change_set --
        // there is no second-principal approval to point to. Refused unless
        // the operator has accepted that risk with --allow-direct-commit.
        // Applies identically over stdio and HTTP: the policy is a
        // process-level setting and never reads `ctx`.
        if record.change_set_id.is_none()
            && let Err(e) = self.direct_commit.check(&mut audit)
        {
            direct_commit_refused = true;
            return Err(policy("operation_id", &e.to_string()));
        }
        let client = self.client(&input.device)?;

        // Refuse commits on plane-managed firewalls where changes would be overwritten
        let authority = client.config_authority();
        if !authority.is_local() {
            if self.allow_plane_owned_writes {
                tracing::warn!(
                    device = %input.device,
                    config_authority = authority.as_str(),
                    "proceeding with commit on {} device; changes may be overwritten at next push. \
                     This is allowed only because --allow-plane-owned-writes is set.",
                    authority.as_str()
                );
            } else {
                return Err(policy(
                    "device",
                    &format!(
                        "commits to {} devices are refused; local changes would be overwritten at next push",
                        authority.as_str()
                    ),
                ));
            }
        }
        let policy = require_policy(&client)?.clone();
        require_operation_policy(&record, &client)?;
        let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
        require_operation_fingerprint(&input, &record, &current)?;
        record.state = LifecycleState::Committing;
        self.mutations.update(record.clone()).await?;

        // Carry attribution onto the firewall's own commit log.
        //
        // The description used to name nobody, so PAN-OS's commit history could
        // not say who made a change or who approved it. Built here rather than
        // in the worker because only this scope still holds the caller context.
        let mut attribution = match ctx {
            Some(ctx) => Attribution::from_caller(ctx),
            None => Attribution::stdio(),
        };

        // Two-person evidence, when this operation came from a change set.
        // `approval.approver` is the field documented as present only for a
        // genuine two-person approval and absent when waived — exactly the
        // distinction a commit log has to keep. A lookup failure is not fatal:
        // the change set is a label on the commit, and losing the label is not
        // worth refusing a commit whose candidate is already staged and
        // validated.
        if let Some(change_set_id) = record.change_set_id.clone() {
            let approver = self
                .mutations
                .change_set(&change_set_id, &input.device)
                .await
                .ok()
                .and_then(|change_set| {
                    change_set
                        .approval
                        .as_ref()
                        .and_then(|approval| approval.approver.clone())
                });
            attribution.with_change_set(&change_set_id, approver.as_deref());
        }

        let coordinator = self.mutations.clone();
        let evidence = self.evidence.clone();
        let owner = owner.to_owned();
        let operation_id = record.id.clone();
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let result =
                commit_worker(
                coordinator,
                client,
                policy.admin,
                record,
                &owner,
                attribution,
                evidence,
            )
            .await;
            let _ = sender.send(result);
        });
        tokio::select! {
            result = receiver => result.map_err(|_| PanosMcpError::Configuration("commit worker stopped without reconciliation".to_owned()))?,
            () = cancellation.cancelled() => Ok(CommitOutput {
                operation_id,
                disposition: CommitDisposition::Detached,
                job_id: None,
                succeeded: None,
                details: Some("commit continues in a detached reconciliation worker; poll operation status".to_owned()),
            }),
        }
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            // Keep the Denied(direct_commit_disabled) outcome already recorded.
            Err(_) if direct_commit_refused => {}
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Revert only candidate changes attributed by PAN-OS to the configured admin.
    pub async fn discard_candidate(
        &self,
        input: OperationInput,
        owner: &str,
        ctx: Option<&CallerContext>,
        cancellation: CancellationToken,
    ) -> Result<DiscardOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "discard_panos_candidate",
                "discard",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "discard_panos_candidate",
                "discard",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
        validate_fingerprint(&input.expected_candidate_fingerprint)?;
        let mut record = self
            .mutations
            .record(&input.operation_id, owner, &input.device)
            .await?;
        if matches!(
            record.state,
            LifecycleState::Validating
                | LifecycleState::Committing
                | LifecycleState::Committed
                | LifecycleState::Discarded
                | LifecycleState::Indeterminate
        ) {
            return Err(policy(
                "operation_id",
                "operation cannot be discarded in its current state",
            ));
        }
        let client = self.client(&input.device)?;
        let policy = require_policy(&client)?.clone();
        require_operation_policy(&record, &client)?;
        let _guard = self
            .mutations
            .device_guard(&client.mutation_lock_key(), &cancellation)
            .await?;
        let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
        require_operation_fingerprint(&input, &record, &current)?;
        let command = format!(
            "<revert><config><partial><admin><member>{}</member></admin></partial></config></revert>",
            escape(&policy.admin)
        );
        client
            .post_fields(
                vec![("type", "op".to_owned()), ("cmd", command)],
                CancellationToken::new(),
            )
            .await?;
        let after = candidate_fingerprint(&client, CancellationToken::new()).await?;
        record.current = after.clone();
        if record.config_lock_held {
            if let Err(error) = release_config_lock(&client).await {
                let details = format!(
                    "discard succeeded but PAN-OS configuration lock release failed: {error}; manual job/candidate/lock reconciliation required"
                );
                record.state = LifecycleState::Indeterminate;
                record.details = Some(details.clone());
                self.mutations.update(record.clone()).await?;
                return Err(PanosMcpError::Configuration(details));
            }
            record.config_lock_held = false;
        }
        record.state = LifecycleState::Discarded;
        record.details = None;
        self.mutations.update(record.clone()).await?;
        Ok(DiscardOutput {
            operation_id: record.id,
            candidate_fingerprint: after,
        })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }

    /// Poll safe in-memory state for a detached or completed operation.
    pub async fn operation_status(
        &self,
        input: OperationStatusInput,
        owner: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<OperationStatusOutput> {
        let mut audit = match ctx {
            Some(ctx) => AuditScope::from_caller(
                ctx,
                "get_panos_operation",
                "get-operation",
                vec![input.device.clone()],
            ),
            None => AuditScope::stdio(
                "get_panos_operation",
                "get-operation",
                vec![input.device.clone()],
            ),
        };
        audit.meta("operation_id", input.operation_id.clone());
        let result = async {
            let record = self
                .mutations
                .record(&input.operation_id, owner, &input.device)
                .await?;
            Ok(OperationStatusOutput {
                operation_id: record.id,
                device: record.device,
                state: record.state.as_str().to_owned(),
                job_id: record.job_id,
                candidate_fingerprint: record.current,
                details: record.details,
            })
        }
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail(e),
        }
        result
    }
}

/// How much of a change-set id reaches the device's commit description.
///
/// Enough to correlate a commit with the server's change-set store — 16 hex
/// characters is 64 bits, against a store holding tens of records — without
/// spending a third of a bounded description field on an identifier.
const CHANGE_SET_ID_DESCRIPTION_PREFIX: usize = 16;

/// How much of a principal's name reaches the device's commit description.
///
/// PAN-OS accepts 512 characters of commit description. This one carries up to
/// three token names — the principal, the on-behalf-of, and the approver — each
/// of which may be 128 characters (`mecmcp_auth::MAX_TOKEN_NAME`), so together
/// they can exceed the field on their own. Truncating is strictly better than
/// the alternative: an over-long description fails the commit after the
/// candidate is already staged.
const MAX_NAME_IN_DESCRIPTION: usize = 64;

/// Bound one name for inclusion in a commit description, marking any truncation.
fn bounded_name(name: &str) -> String {
    if name.len() > MAX_NAME_IN_DESCRIPTION {
        let kept: String = name.chars().take(MAX_NAME_IN_DESCRIPTION).collect();
        format!("{kept}...")
    } else {
        name.to_owned()
    }
}

/// Build the PAN-OS commit description for an operation.
///
/// Before this, the description was `rust-panosmcp <operation-id>` and nothing
/// else: the firewall's own commit history could not say who made a change, let
/// alone who approved it. The evidence existed only in this server's audit log
/// and change-set store, on a host the firewall's operator may not have — and
/// the commit log is the durable half, since an audit log can be re-derived
/// while a commit description cannot be corrected retroactively.
///
/// The operation id stays first so anything already matching on the existing
/// shape keeps working; the attribution is appended.
///
/// `approved-by` and `change-set` are omitted rather than emitted empty.
/// `commit_panos_candidate` can be called on a candidate that never went
/// through a change set, and `approved-by=` with nothing after it reads, to
/// anyone scanning a commit log, like an approval that happened.
fn commit_description(record: &OperationRecord, attribution: &Attribution) -> String {
    let principal = bounded_name(&attribution.principal.to_string());
    let on_behalf_of = attribution
        .on_behalf_of
        .as_deref()
        .map(bounded_name)
        .unwrap_or_else(|| "self".to_owned());

    let approval_info = attribution
        .approver
        .as_deref()
        .map(|approver| format!(" approved-by={}", bounded_name(approver)))
        .unwrap_or_default();

    let change_set_info = attribution
        .change_set_id
        .as_deref()
        .map(|id| {
            let prefix: String = id.chars().take(CHANGE_SET_ID_DESCRIPTION_PREFIX).collect();
            format!(" change-set={prefix}")
        })
        .unwrap_or_default();

    format!(
        "rust-panosmcp {} by {} on-behalf-of={} request.id={}{}{}",
        record.id, principal, on_behalf_of, attribution.request_id, approval_info, change_set_info
    )
}

/// Build the PAN-OS `<commit>` command carrying the operation's description.
///
/// Split from [`commit_worker`] so the description actually reaching the device
/// is testable. The worker needs a live PAN-OS session, so without this seam the
/// only covered thing would be `commit_description` in isolation — and a
/// description that is built correctly but never placed in the command is
/// exactly the defect this change exists to fix.
///
/// Both interpolations are XML-escaped. The description embeds token names,
/// which are operator-supplied, and an unescaped `<` would otherwise let a name
/// close the element and inject into the command.
fn commit_command(record: &OperationRecord, attribution: &Attribution, admin: &str) -> String {
    format!(
        "<commit><description>{}</description><partial><admin><member>{}</member></admin></partial></commit>",
        escape(commit_description(record, attribution)),
        escape(admin)
    )
}

async fn commit_worker(
    coordinator: Arc<ChangesetCoordinator>,
    client: Arc<PanosClient>,
    admin: String,
    mut record: OperationRecord,
    _owner: &str,
    attribution: Attribution,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
) -> Result<CommitOutput> {
    let guard = coordinator
        .device_guard(&client.mutation_lock_key(), &CancellationToken::new())
        .await?;
    let command = commit_command(&record, &attribution, &admin);

    // PAN-OS commits here rather than through `ChangesetCoordinator::commit_operation`,
    // which is the only coordinator path that emits execution evidence -- so
    // without this the trail showed a proposal and an approval and nothing about
    // the commit that followed. Written before the device is touched, and
    // refused if it cannot be persisted: a firewall committed with no record
    // that anyone tried is the state this chain exists to rule out.
    // The approved change set, not the operation. `apply_panos_change_set`
    // mints a fresh operation id, while the approval and its digest are keyed
    // by `change_set_id` -- writing execution records under the operation id
    // leaves an auditor unable to join the commit to the digest that was
    // approved. Standalone operations have no change set, so the operation id
    // is the fallback there.
    let evidence_change_set = record
        .change_set_id
        .clone()
        .unwrap_or_else(|| record.id.clone());

    if let Some(recorder) = &evidence
        && let Err(error) = recorder.apply_intent(
            &attribution.request_id.to_string(),
            &evidence_change_set,
            &record.device,
            &attribution.principal.to_string(),
        )
    {
        // `commit_candidate` persisted `Committing` before spawning this
        // worker. Returning without undoing that strands the operation: retry
        // requires `Validated`, discard refuses `Committing`, and the candidate
        // and configuration lock stay held. Put it back where a retry can find
        // it -- which is also what the error message claims.
        record.state = LifecycleState::Validated;
        record.details = Some(format!("apply-intent evidence not persisted: {error}"));
        // Whether the restore itself worked decides what the caller is told.
        // Swallowing its failure would repeat the mistake one level down:
        // claiming the operation is retryable while it sits in `Committing`,
        // holding the candidate and the configuration lock.
        return Err(PanosMcpError::Configuration(
            match coordinator.update(record.clone()).await {
                Ok(()) => format!(
                    "commit refused: the apply-intent evidence record could not be \
                     persisted ({error}); the operation is still staged and can be \
                     retried"
                ),
                Err(restore_error) => {
                    // Name only what is actually held. Telling an operator a
                    // configuration lock needs releasing when the deployment
                    // runs lock-free sends them after something that does not
                    // exist -- the same inaccurate-state reporting this whole
                    // path exists to stop.
                    let held = if record.config_lock_held {
                        "its candidate and configuration lock held"
                    } else {
                        "its candidate held"
                    };
                    format!(
                        "commit refused: the apply-intent evidence record could not be \
                         persisted ({error}), and the operation could not be returned to \
                         a retryable state ({restore_error}); it is stranded in \
                         `committing` with {held}, and needs manual reconciliation"
                    )
                }
            },
        ));
    }
    let mut result: Result<CommitOutput> = async {
        let response = client
            .post_fields(
                vec![
                    ("type", "commit".to_owned()),
                    ("action", "partial".to_owned()),
                    ("cmd", command),
                ],
                CancellationToken::new(),
            )
            .await?;
        let job_id = parse_job_id(&response)?;
        record.job_id = Some(job_id.clone());
        coordinator.update(record.clone()).await?;
        let status = client
            .poll_job(&job_id, COMMIT_DEADLINE, CancellationToken::new())
            .await?;
        let current = candidate_fingerprint(&client, CancellationToken::new()).await?;
        record.current = current;
        record.details = status.details.clone();
        record.state = if status.succeeded() {
            LifecycleState::Committing
        } else {
            LifecycleState::Failed
        };
        coordinator.update(record.clone()).await?;
        Ok(CommitOutput {
            operation_id: record.id.clone(),
            disposition: CommitDisposition::Reconciled,
            job_id: Some(job_id),
            succeeded: Some(status.succeeded()),
            details: status.details,
        })
    }
    .await;
    drop(guard);
    let commit_succeeded = result
        .as_ref()
        .is_ok_and(|output| output.succeeded == Some(true));
    if commit_succeeded && record.config_lock_held {
        match release_config_lock(&client).await {
            Ok(()) => {
                record.config_lock_held = false;
                record.state = LifecycleState::Committed;
            }
            Err(error) => {
                let details = format!(
                    "commit succeeded but PAN-OS configuration lock release failed: {error}; manual job/candidate/lock reconciliation required"
                );
                record.state = LifecycleState::Indeterminate;
                record.details = Some(details.clone());
                result = Err(PanosMcpError::Configuration(details));
            }
        }
    } else if commit_succeeded {
        record.state = LifecycleState::Committed;
    } else if let Err(error) = &result {
        record.state = LifecycleState::Indeterminate;
        record.details = Some(error.to_string());
    }
    // PAN-OS answered. Emitted before the state write, because that write can
    // fail and the receipt describes what the device did, which local
    // persistence cannot retract.
    //
    // Keyed on the **job outcome**, not the lifecycle state. A commit that
    // PAN-OS reported as successful and whose *lock release* then failed is
    // marked `Indeterminate` above -- correctly, for reconciliation -- but the
    // device action is known, and suppressing the receipt there would leave the
    // chain at apply intent for something PAN-OS proved. Only an unknown job
    // outcome gets no receipt.
    if let Some(recorder) = &evidence {
        let job_outcome_known = commit_succeeded || result.is_ok();
        if !job_outcome_known {
            tracing::error!(
                operation_id = %record.id,
                "the PAN-OS commit outcome is unknown; no result receipt is emitted"
            );
        } else if let Err(error) = recorder.result_receipt(
            &attribution.request_id.to_string(),
            &evidence_change_set,
            &record.device,
            &attribution.principal.to_string(),
            commit_succeeded,
            // Only a failure's details are an error. A successful commit's
            // details are warnings or a job note, and filing those as errors
            // hands every warning-bearing success back to anyone filtering the
            // trail for failures.
            if commit_succeeded {
                ""
            } else {
                record.details.as_deref().unwrap_or("")
            },
        ) {
            tracing::error!(
                %error,
                operation_id = %record.id,
                "PAN-OS answered but the result receipt could not be persisted"
            );
        }
    }

    coordinator.update(record.clone()).await?;
    result
}

fn require_policy(client: &PanosClient) -> Result<&crate::inventory::MutationPolicy> {
    client.mutation_policy().ok_or_else(|| {
        policy(
            "device",
            "candidate mutation is disabled by inventory policy",
        )
    })
}

fn require_operation_policy(record: &OperationRecord, client: &PanosClient) -> Result<()> {
    let current_policy = require_policy(client)?;
    if record.policy_signature == local_mutation_policy_signature(current_policy) {
        Ok(())
    } else {
        Err(policy(
            "operation_id",
            "inventory mutation policy changed after this operation staged; discard or recover manually",
        ))
    }
}

fn local_mutation_policy_signature(policy: &crate::inventory::MutationPolicy) -> String {
    // Use the original PAN-OS encoding (raw bytes + length prefixes) to maintain
    // compatibility with existing persisted operations. Operations created before
    // the migration used this encoding, and changing it would cause false policy
    // drift detection on restart.
    let mut digest = Sha256::new();
    digest.update(policy.admin.as_bytes());
    digest.update([u8::from(policy.allow_delete)]);
    digest.update([u8::from(policy.require_config_lock)]);
    for root in &policy.allowed_xpath_roots {
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root.as_bytes());
    }
    format!("sha256:{}", bytes_hex(&digest.finalize()))
}

fn validate_change_set_actions(
    actions: &[ChangeSetAction],
    inventory_policy: &crate::inventory::MutationPolicy,
    grant: Option<&MutationGrant>,
) -> Result<()> {
    if actions.is_empty() || actions.len() > MAX_CHANGE_SET_ACTIONS {
        return Err(policy(
            "actions",
            &format!("change set must contain 1-{MAX_CHANGE_SET_ACTIONS} actions"),
        ));
    }
    let encoded = serde_json::to_vec(actions).map_err(|error| {
        PanosMcpError::Configuration(format!("could not encode change set: {error}"))
    })?;
    if encoded.len() > MAX_CHANGE_SET_BYTES {
        return Err(policy(
            "actions",
            &format!("serialized change set exceeds {MAX_CHANGE_SET_BYTES} bytes"),
        ));
    }
    for action in actions {
        validate_write_xpath(&action.xpath, &inventory_policy.allowed_xpath_roots)?;
        let stage = StageConfigInput {
            device: String::new(),
            expected_candidate_fingerprint: String::new(),
            action: action.action,
            xpath: action.xpath.clone(),
            element: action.element.clone(),
            destructive_confirmation: action.destructive_confirmation.clone(),
            move_position: action.move_position,
            move_destination: action.move_destination.clone(),
        };
        validate_stage_payload(&stage, inventory_policy.allow_delete)?;
        if let Some(grant) = grant {
            if !grant.allows_action(action.action.into()) {
                return Err(policy(
                    "action",
                    "action is outside this token's mutation grant",
                ));
            }
            if !grant.allows_xpath(&action.xpath) {
                return Err(policy(
                    "xpath",
                    "XPath is outside this token's mutation grant",
                ));
            }
        }
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(policy(
            field,
            "value must use sha256:<64 lowercase hex> format",
        ));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(policy(
            field,
            "value must use sha256:<64 lowercase hex> format",
        ))
    }
}

fn validate_stage_payload(input: &StageConfigInput, allow_delete: bool) -> Result<()> {
    match input.action {
        StageAction::Set => {
            let element = input
                .element
                .as_deref()
                .ok_or_else(|| policy("element", "set requires one XML element"))?;
            validate_config_element(element)?;
            if input.destructive_confirmation.is_some() {
                return Err(policy(
                    "destructive_confirmation",
                    "set must not carry delete confirmation",
                ));
            }
            require_no_move_fields(input, "set")?;
        }
        StageAction::Delete => {
            if !allow_delete {
                return Err(policy("action", "delete is disabled by inventory policy"));
            }
            if input.element.is_some() {
                return Err(policy("element", "delete must not carry an XML element"));
            }
            let expected = format!("DELETE {}", input.xpath);
            if input.destructive_confirmation.as_deref() != Some(expected.as_str()) {
                return Err(policy(
                    "destructive_confirmation",
                    "delete requires exact 'DELETE <xpath>' confirmation",
                ));
            }
            require_no_move_fields(input, "delete")?;
        }
        StageAction::Move => {
            if input.element.is_some() {
                return Err(policy("element", "move must not carry an XML element"));
            }
            if input.destructive_confirmation.is_some() {
                return Err(policy(
                    "destructive_confirmation",
                    "move must not carry delete confirmation",
                ));
            }
            let position = input
                .move_position
                .ok_or_else(|| policy("move_position", "move requires a position"))?;
            match (position.requires_destination(), &input.move_destination) {
                (true, None) => {
                    return Err(policy(
                        "move_destination",
                        "before/after requires a sibling entry name",
                    ));
                }
                (false, Some(_)) => {
                    return Err(policy(
                        "move_destination",
                        "top/bottom must not carry a sibling entry name",
                    ));
                }
                _ => {}
            }
            let (_, moved_name) = extract_move_target(&input.xpath)?;
            if let Some(destination) = &input.move_destination {
                validate_move_destination_name(destination)?;
                if destination == &moved_name {
                    return Err(policy(
                        "move_destination",
                        "a rule cannot be moved relative to itself",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Reject `move_position`/`move_destination` on a non-move action.
///
/// Without this, a set or delete carrying stray move fields would pass
/// unnoticed -- `deny_unknown_fields` only rejects fields the schema does not
/// know about, and these two are legal fields of the same struct, just for a
/// different `action`.
fn require_no_move_fields(input: &StageConfigInput, action_name: &'static str) -> Result<()> {
    if input.move_position.is_some() || input.move_destination.is_some() {
        return Err(policy(
            "move_position",
            &format!("{action_name} must not carry move_position or move_destination"),
        ));
    }
    Ok(())
}

/// Bound a `move_destination` sibling name to the same shape PAN-OS accepts
/// for an entry's own `name` attribute, so it cannot smuggle XPath or XML
/// syntax into a plain form field the device treats as an opaque string.
fn validate_move_destination_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(policy("move_destination", "value must be 1-63 characters"));
    }
    if name.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(policy(
            "move_destination",
            "value must not contain control characters",
        ));
    }
    Ok(())
}

/// Split a write XPath into its container prefix and the exact name of the
/// trailing `entry[@name='...']` step, when the XPath has that shape.
///
/// Only ever called after [`validate_write_xpath`], which (via
/// `is_strict_xpath_shape`) has already guaranteed every step is either a
/// bare name or `name[@attr='literal']`/`name[@attr="literal"]` -- so the
/// final step here is trusted to have that shape rather than re-validated.
/// Returns `None` for a container-level XPath (for example a `set` whose
/// element carries the new entry's name, rather than the XPath itself
/// naming the entry) -- callers that only simulate entry-shaped actions
/// treat that as "nothing to simulate", not an error.
fn split_container_and_entry_name(xpath: &str) -> Option<(String, String)> {
    let slash = xpath.rfind('/')?;
    let (container, last_step) = xpath.split_at(slash);
    let last_step = &last_step[1..];
    let rest = last_step.strip_prefix("entry[@name=")?;
    let rest = rest.strip_suffix(']')?;
    let quote = rest.chars().next()?;
    if (quote != '\'' && quote != '"') || !rest.ends_with(quote) || rest.len() < 2 {
        return None;
    }
    let name = rest[quote.len_utf8()..rest.len() - quote.len_utf8()].to_owned();
    if name.is_empty() {
        return None;
    }
    Some((container.to_owned(), name))
}

/// Split a validated write XPath into its container prefix and the exact
/// name of the trailing `entry[@name='...']` step being moved.
fn extract_move_target(xpath: &str) -> Result<(String, String)> {
    split_container_and_entry_name(xpath).ok_or_else(|| {
        policy(
            "xpath",
            "move requires an xpath ending in entry[@name='...']",
        )
    })
}

/// Per-container view of entry names used to check `move` actions in a plan,
/// simulating the `set`/`delete` actions that precede them in the same plan.
struct ContainerEntries {
    names: std::collections::HashSet<String>,
    /// Whether the live fetch this view is based on was too large to scan in
    /// full -- see [`require_move_target_exists`].
    truncated: bool,
}

/// Check every `move` action in a plan against the live rulebase container it
/// targets, *as that container will look after every `set`/`delete` action
/// earlier in the same plan has run* -- not just against what is live on the
/// device right now.
///
/// Without this, `[set .../rules/entry[@name='new'], move new top]` -- adding
/// a rule and immediately placing it, the most common real workflow -- would
/// be refused at plan time because `new` does not exist yet on the device.
/// And `[delete .../rules/entry[@name='B'], move A after B]` would pass
/// planning and approval, then fail only when PAN-OS applies it, which is
/// exactly the device-side error the existence check exists to avoid.
///
/// Called once per `create_change_set`, before the plan is persisted --
/// nonexistent targets are refused at plan time, not discovered only when an
/// already-approved change set is applied.
async fn require_move_targets_exist(
    client: &PanosClient,
    actions: &[ChangeSetAction],
    cancellation: CancellationToken,
) -> Result<()> {
    let mut containers: std::collections::HashMap<String, ContainerEntries> =
        std::collections::HashMap::new();
    for action in actions {
        if action.action != StageAction::Move {
            continue;
        }
        let (container, _) = extract_move_target(&action.xpath)?;
        if containers.contains_key(&container) {
            continue;
        }
        let (bytes, response_truncated) = client
            .configuration_entries(false, &container, cancellation.clone())
            .await?;
        let scan = scan_config_entries(
            &bytes,
            0,
            MAX_MOVE_SIBLING_ENTRIES,
            LIST_CONTAINER_ENTRY_DEPTH,
        )?;
        let truncated =
            response_truncated || scan.truncated || scan.total_seen > scan.entries.len();
        let names = scan.entries.into_iter().map(|entry| entry.name).collect();
        containers.insert(container, ContainerEntries { names, truncated });
    }

    for action in actions {
        let Some((container, name)) = split_container_and_entry_name(&action.xpath) else {
            continue;
        };
        match action.action {
            StageAction::Set => {
                if let Some(state) = containers.get_mut(&container) {
                    state.names.insert(name);
                }
            }
            StageAction::Delete => {
                if let Some(state) = containers.get_mut(&container) {
                    state.names.remove(&name);
                }
            }
            StageAction::Move => {
                let state = containers
                    .get(&container)
                    .expect("every move's container was fetched above");
                if !state.names.contains(name.as_str()) {
                    return Err(policy(
                        "xpath",
                        if state.truncated {
                            "the rule to move could not be confirmed to exist: the live \
                             rulebase is too large to verify in full"
                        } else {
                            "the rule to move does not exist in the live rulebase"
                        },
                    ));
                }
                if let Some(destination) = action.move_destination.as_deref()
                    && !state.names.contains(destination)
                {
                    return Err(policy(
                        "move_destination",
                        if state.truncated {
                            "the destination sibling rule could not be confirmed to exist: \
                             the live rulebase is too large to verify in full"
                        } else {
                            "the destination sibling rule does not exist in the live rulebase"
                        },
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Confirm, against the live device, that the entry a `move` action targets
/// and its sibling destination (when named) both exist -- so a nonexistent
/// target is refused here rather than surfacing only as a PAN-OS API error
/// after the change set is already approved and applying.
///
/// Fails closed: a response too large to scan completely (`truncated`) is
/// treated the same as "not found," since a container this check cannot see
/// in full cannot be used to prove either name exists.
async fn require_move_target_exists(
    client: &PanosClient,
    container_xpath: &str,
    moved_name: &str,
    destination: Option<&str>,
    cancellation: CancellationToken,
) -> Result<()> {
    let (bytes, response_truncated) = client
        .configuration_entries(false, container_xpath, cancellation)
        .await?;
    let scan = scan_config_entries(
        &bytes,
        0,
        MAX_MOVE_SIBLING_ENTRIES,
        LIST_CONTAINER_ENTRY_DEPTH,
    )?;
    let truncated = response_truncated || scan.truncated || scan.total_seen > scan.entries.len();
    let names: std::collections::HashSet<&str> = scan
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    if !names.contains(moved_name) {
        return Err(policy(
            "xpath",
            if truncated {
                "the rule to move could not be confirmed to exist: the live rulebase is too \
                 large to verify in full"
            } else {
                "the rule to move does not exist in the live rulebase"
            },
        ));
    }
    if let Some(destination) = destination
        && !names.contains(destination)
    {
        return Err(policy(
            "move_destination",
            if truncated {
                "the destination sibling rule could not be confirmed to exist: the live \
                 rulebase is too large to verify in full"
            } else {
                "the destination sibling rule does not exist in the live rulebase"
            },
        ));
    }
    Ok(())
}

pub(crate) async fn candidate_fingerprint(
    client: &PanosClient,
    cancellation: CancellationToken,
) -> Result<String> {
    let policy = require_policy(client)?;
    let mut digest = Sha256::new();
    for root in &policy.allowed_xpath_roots {
        if cancellation.is_cancelled() {
            return Err(PanosMcpError::Cancelled);
        }
        let response = client
            .configuration(true, root, cancellation.clone())
            .await?;
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root.as_bytes());
        digest.update((response.xml.len() as u64).to_be_bytes());
        digest.update(response.xml.as_bytes());
    }
    Ok(format!("sha256:{}", bytes_hex(&digest.finalize())))
}

/// Refuse to build on a candidate that already diverges from the running
/// configuration before this operation has staged anything of its own.
///
/// `expected_candidate_fingerprint` optimistic-concurrency checks
/// ([`require_fingerprint`], [`require_operation_fingerprint`]) only catch a
/// candidate that changes *after* the caller observed it -- they treat
/// whatever was live at that moment as the trusted baseline. If the dedicated
/// admin's candidate already held pending edits from outside this tool (a
/// human in the GUI, a second concurrent operator, a stuck prior session),
/// those edits become that baseline and ride along into the eventual partial
/// commit, since PAN-OS scopes a partial commit by admin, not by xpath.
///
/// This asks PAN-OS directly via `check pending-changes` rather than
/// comparing a candidate fingerprint against a running-config fingerprint:
/// `get` (candidate) and `show` (running) return different response
/// envelopes on a real device (the candidate response carries `code`/
/// `total`/`count` attributes the running response does not), so hashing the
/// full envelope of each -- as an earlier version of this check did -- can
/// never match even on a byte-identical candidate. `check pending-changes` is
/// also deliberately global rather than scoped to `allowed_xpath_roots`: a
/// foreign edit sitting outside every root this tool manages still lands in
/// the same partial commit and must still be refused.
async fn require_clean_candidate(
    client: &PanosClient,
    cancellation: CancellationToken,
) -> Result<()> {
    if client.check_pending_changes(cancellation).await? {
        Err(policy(
            "candidate",
            "candidate configuration already has pending changes outside this operation; \
             commit or discard them before staging a new change",
        ))
    } else {
        Ok(())
    }
}

fn require_fingerprint(expected: &str, actual: &str) -> Result<()> {
    validate_fingerprint(expected)?;
    if expected == actual {
        Ok(())
    } else {
        Err(policy(
            "expected_candidate_fingerprint",
            "candidate changed since the caller observed it",
        ))
    }
}

fn validate_fingerprint(value: &str) -> Result<()> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(policy(
            "expected_candidate_fingerprint",
            "value must use the sha256:<64 lowercase hex> format",
        ));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(policy(
            "expected_candidate_fingerprint",
            "value must use the sha256:<64 lowercase hex> format",
        ))
    }
}

fn require_operation_fingerprint(
    input: &OperationInput,
    record: &OperationRecord,
    actual: &str,
) -> Result<()> {
    require_fingerprint(&input.expected_candidate_fingerprint, actual)?;
    if record.current == actual {
        Ok(())
    } else {
        Err(policy(
            "operation_id",
            "candidate changed after this operation staged",
        ))
    }
}

async fn acquire_config_lock(client: &PanosClient, operation_id: &str) -> Result<()> {
    let command = format!(
        "<request><config-lock><add><comment>rust-panosmcp {}</comment></add></config-lock></request>",
        escape(operation_id)
    );
    client
        .post_fields(
            vec![("type", "op".to_owned()), ("cmd", command)],
            CancellationToken::new(),
        )
        .await?;
    Ok(())
}

/// True when PAN-OS refused an unlock because nothing was locked.
///
/// PAN-OS reports this as a generic `code=-1` with only the message to
/// distinguish it, so the text is the only signal available. Matched
/// case-insensitively on the stable part of the phrase; the scope name it
/// appends ("for scope vsys1") varies per device.
fn is_already_unlocked(error: &PanosMcpError) -> bool {
    matches!(
        error,
        PanosMcpError::Api { message, .. }
            if message.to_ascii_lowercase().contains("not currently locked")
    )
}

pub(crate) async fn release_config_lock(client: &PanosClient) -> Result<()> {
    let outcome = client
        .post_fields(
            vec![
                ("type", "op".to_owned()),
                (
                    "cmd",
                    "<request><config-lock><remove></remove></config-lock></request>".to_owned(),
                ),
            ],
            CancellationToken::new(),
        )
        .await;

    match outcome {
        Ok(_) => Ok(()),
        // PAN-OS releases a vsys-scoped configuration lock as part of committing,
        // so the explicit release that follows a successful commit finds nothing
        // to remove. The post-condition being asserted is *no lock is held*, and
        // that holds — treating it as failure marked every successful commit
        // `Indeterminate` and, because one unreconciled operation is allowed per
        // endpoint, left the device blocked for the next change set (#75).
        //
        // This deliberately does not swallow other failures: an unreachable
        // device or a refused permission leaves the lock genuinely held, which is
        // exactly what `Indeterminate` is for.
        Err(error) if is_already_unlocked(&error) => {
            tracing::debug!(
                target: "audit",
                device = client.device_name(),
                "PAN-OS configuration lock was already released"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn release_config_lock_best_effort(client: &PanosClient) {
    if let Err(error) = release_config_lock(client).await {
        tracing::error!(target: "audit", device = client.device_name(), %error, "PAN-OS configuration lock release failed");
    }
}

pub(crate) async fn revert_admin_candidate(client: &PanosClient, admin: &str) -> Result<()> {
    let command = format!(
        "<revert><config><partial><admin><member>{}</member></admin></partial></config></revert>",
        escape(admin)
    );
    client
        .post_fields(
            vec![("type", "op".to_owned()), ("cmd", command)],
            CancellationToken::new(),
        )
        .await?;
    Ok(())
}

fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PanosMcpError::Configuration("system clock is before Unix epoch".to_owned()))
}

#[cfg(test)]
fn read_mutation_state(
    path: &std::path::Path,
) -> Result<mecmcp_changeset::persistence::ChangesetState> {
    mecmcp_changeset::persistence::read_state(path, MAX_STATE_BYTES).map_err(|error| {
        PanosMcpError::Configuration(format!("could not read mutation state: {error}"))
    })
}

#[cfg(test)]
fn write_mutation_state(
    path: &std::path::Path,
    state: &mecmcp_changeset::persistence::ChangesetState,
) -> Result<()> {
    mecmcp_changeset::persistence::write_state_for_test(path, state, MAX_STATE_BYTES).map_err(
        |error| PanosMcpError::Configuration(format!("could not write mutation state: {error}")),
    )
}

fn new_operation_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        PanosMcpError::Configuration("operating-system random source failed".to_owned())
    })?;
    Ok(digest_hex(&bytes))
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    bytes_hex(&digest)
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn truncate_utf8(mut value: String, limit: usize) -> (String, bool) {
    if value.len() <= limit {
        return (value, false);
    }
    let mut boundary = limit;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    (value, true)
}

fn policy(field: &'static str, reason: &str) -> PanosMcpError {
    PanosMcpError::Policy {
        field,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An operation record, optionally linked to a change set.
    fn operation_record(change_set_id: Option<&str>) -> OperationRecord {
        OperationRecord {
            id: "10b9c0321bc7".to_owned(),
            owner: "claude-test".to_owned(),
            device: "fw".to_owned(),
            endpoint: "https://fw.example".to_owned(),
            action: serde_json::json!({"op": "set"}),
            xpath: None,
            actions: vec![serde_json::json!({"op": "set"})],
            change_set_id: change_set_id.map(str::to_owned),
            current: format!("sha256:{}", "a".repeat(64)),
            state: LifecycleState::Committing,
            job_id: None,
            details: None,
            config_lock_held: true,
            policy_signature: String::new(),
            attribution: None,
            rollback_deadline_unix: None,
            config_authority: None,
        }
    }

    fn attribution_with(approver: Option<&str>, change_set_id: Option<&str>) -> Attribution {
        let mut attribution = Attribution {
            principal: mecmcp_audit::Principal::Token("claude-test".to_owned()),
            actor_type: mecmcp_audit::ActorType::Agent,
            agent: None,
            on_behalf_of: Some("mharman".to_owned()),
            change_ref: None,
            request_id: uuid::Uuid::nil(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
            verified_approver: None,
            approver: None,
            change_set_id: None,
        };
        if let Some(id) = change_set_id {
            attribution.with_change_set(id, approver);
        }
        attribution
    }

    /// The defect: the device's commit log named nobody at all.
    ///
    /// The production description was `rust-panosmcp <operation-id>` and
    /// carried no principal, no approver, no change set and no request id — so
    /// PAN-OS's own commit history could not say who made a change, let alone
    /// who approved it.
    #[test]
    fn commit_description_names_the_principal_and_request() {
        let description =
            commit_description(&operation_record(None), &attribution_with(None, None));

        assert!(
            description.contains("by claude-test"),
            "the acting principal must reach the device: {description}"
        );
        assert!(
            description.contains("request.id=00000000-0000-0000-0000-000000000000"),
            "the request id joins the commit to its audit event: {description}"
        );
    }

    /// The operation id stays, and stays first.
    ///
    /// Anything already reading these descriptions matches on the existing
    /// `rust-panosmcp <id>` shape; the attribution is appended, not substituted.
    #[test]
    fn commit_description_keeps_the_operation_id_prefix() {
        let description =
            commit_description(&operation_record(None), &attribution_with(None, None));

        assert!(
            description.starts_with("rust-panosmcp 10b9c0321bc7"),
            "the existing prefix must survive unchanged: {description}"
        );
    }

    /// The two-person evidence reaches the firewall (the #307 equivalent).
    #[test]
    fn commit_description_names_the_approver_and_change_set() {
        let full = "86324b20a3ecbfde732b981a8c69a664d44b176c29b5cdaf59e23e4ea96d4175";
        let description = commit_description(
            &operation_record(Some(full)),
            &attribution_with(Some("codex-approver"), Some(full)),
        );

        assert!(
            description.contains("approved-by=codex-approver"),
            "the approver must reach the device: {description}"
        );
        assert!(
            description.contains("change-set=86324b20a3ecbfde"),
            "the change set must reach the device: {description}"
        );
        assert!(
            !description.contains(full),
            "only a correlating prefix is written, not all 64 characters: {description}"
        );
    }

    /// A commit outside the change-set flow claims no approval.
    ///
    /// `commit_panos_candidate` can be called on a candidate that never went
    /// through a change set. Writing `approved-by=` with nothing after it would
    /// read, to anyone scanning a commit log, like an approval that happened.
    #[test]
    fn commit_description_omits_an_absent_approver_and_change_set() {
        let description =
            commit_description(&operation_record(None), &attribution_with(None, None));

        assert!(!description.contains("approved-by"), "{description}");
        assert!(!description.contains("change-set"), "{description}");
    }

    /// The description must stay inside what PAN-OS accepts.
    ///
    /// Every variable field is a token name, capped at 128 characters by
    /// `mecmcp_auth::MAX_TOKEN_NAME`. PAN-OS truncates or rejects an over-long
    /// commit description, and a commit that fails here fails after the
    /// candidate is already staged.
    #[test]
    fn worst_case_description_stays_within_the_panos_ceiling() {
        let long = "n".repeat(128);
        let mut attribution = attribution_with(None, None);
        attribution.principal = mecmcp_audit::Principal::Token(long.clone());
        attribution.on_behalf_of = Some(long.clone());
        attribution.with_change_set(&"f".repeat(64), Some(&long));

        let description =
            commit_description(&operation_record(Some(&"f".repeat(64))), &attribution);

        assert!(
            description.len() <= 512,
            "commit description is {} characters, over the 512 PAN-OS allows: {description}",
            description.len()
        );
    }

    /// The description must actually reach the command sent to the device.
    ///
    /// Without this, a description built correctly and then dropped on the way
    /// to the firewall would pass every other test here — which is precisely
    /// the defect being fixed.
    #[test]
    fn commit_command_carries_the_description_to_the_device() {
        let full = "86324b20a3ecbfde732b981a8c69a664d44b176c29b5cdaf59e23e4ea96d4175";
        let command = commit_command(
            &operation_record(Some(full)),
            &attribution_with(Some("codex-approver"), Some(full)),
            "panos-admin",
        );

        assert!(
            command.contains("approved-by=codex-approver"),
            "the approver must be in the command sent to PAN-OS: {command}"
        );
        assert!(
            command.contains("change-set=86324b20a3ecbfde"),
            "the change set must be in the command sent to PAN-OS: {command}"
        );
        assert!(
            command.contains("<member>panos-admin</member>"),
            "the partial-commit admin must survive: {command}"
        );
    }

    /// A token name carrying XML metacharacters cannot escape the element.
    ///
    /// Token names are operator-supplied and reach the description verbatim. An
    /// unescaped `<` would close `<description>` and inject into the commit
    /// command itself.
    #[test]
    fn commit_command_escapes_xml_metacharacters_in_a_principal() {
        let mut attribution = attribution_with(None, None);
        attribution.principal = mecmcp_audit::Principal::Token("</description><evil>x".to_owned());

        let command = commit_command(&operation_record(None), &attribution, "admin");

        assert!(
            !command.contains("<evil>"),
            "a principal must not be able to inject an element: {command}"
        );
        assert_eq!(
            command.matches("</description>").count(),
            1,
            "exactly one description element may close: {command}"
        );
    }

    #[test]
    fn destructive_confirmation_and_element_policy_are_exact() {
        let mut input = StageConfigInput {
            device: "fw".to_owned(),
            expected_candidate_fingerprint: "sha256:x".to_owned(),
            action: StageAction::Delete,
            xpath: "/config/shared/address/entry[@name='x']".to_owned(),
            element: None,
            destructive_confirmation: None,
            move_position: None,
            move_destination: None,
        };
        assert!(validate_stage_payload(&input, false).is_err());
        assert!(validate_stage_payload(&input, true).is_err());
        input.destructive_confirmation = Some(format!("DELETE {}", input.xpath));
        assert!(validate_stage_payload(&input, true).is_ok());

        input.action = StageAction::Set;
        input.destructive_confirmation = None;
        input.element = Some("<!DOCTYPE entry><entry/>".to_owned());
        assert!(validate_stage_payload(&input, true).is_err());
        input.element =
            Some("<entry name=\"x\"><ip-netmask>192.0.2.1</ip-netmask></entry>".to_owned());
        assert!(validate_stage_payload(&input, true).is_ok());
    }

    fn move_input(
        xpath: &str,
        position: Option<MovePosition>,
        destination: Option<&str>,
    ) -> StageConfigInput {
        StageConfigInput {
            device: "fw".to_owned(),
            expected_candidate_fingerprint: "sha256:x".to_owned(),
            action: StageAction::Move,
            xpath: xpath.to_owned(),
            element: None,
            destructive_confirmation: None,
            move_position: position,
            move_destination: destination.map(str::to_owned),
        }
    }

    const RULE_XPATH: &str = "/config/shared/rulebase/security/rules/entry[@name='rule1']";

    #[test]
    fn move_requires_a_position() {
        let input = move_input(RULE_XPATH, None, None);
        assert!(validate_stage_payload(&input, true).is_err());
    }

    #[test]
    fn move_before_and_after_require_a_destination() {
        for position in [MovePosition::Before, MovePosition::After] {
            let input = move_input(RULE_XPATH, Some(position), None);
            assert!(
                validate_stage_payload(&input, true).is_err(),
                "{position:?} without a destination must be refused"
            );
            let input = move_input(RULE_XPATH, Some(position), Some("rule2"));
            assert!(
                validate_stage_payload(&input, true).is_ok(),
                "{position:?} with a destination must be accepted"
            );
        }
    }

    #[test]
    fn move_top_and_bottom_forbid_a_destination() {
        for position in [MovePosition::Top, MovePosition::Bottom] {
            let input = move_input(RULE_XPATH, Some(position), Some("rule2"));
            assert!(
                validate_stage_payload(&input, true).is_err(),
                "{position:?} with a destination must be refused"
            );
            let input = move_input(RULE_XPATH, Some(position), None);
            assert!(
                validate_stage_payload(&input, true).is_ok(),
                "{position:?} without a destination must be accepted"
            );
        }
    }

    #[test]
    fn move_cannot_target_itself() {
        let input = move_input(RULE_XPATH, Some(MovePosition::After), Some("rule1"));
        assert!(validate_stage_payload(&input, true).is_err());
    }

    #[test]
    fn move_forbids_element_and_destructive_confirmation() {
        let mut input = move_input(RULE_XPATH, Some(MovePosition::Top), None);
        input.element = Some("<entry name=\"rule1\"/>".to_owned());
        assert!(validate_stage_payload(&input, true).is_err());

        let mut input = move_input(RULE_XPATH, Some(MovePosition::Top), None);
        input.destructive_confirmation = Some(format!("DELETE {RULE_XPATH}"));
        assert!(validate_stage_payload(&input, true).is_err());
    }

    #[test]
    fn set_and_delete_forbid_move_fields() {
        let mut input = move_input(RULE_XPATH, None, None);
        input.action = StageAction::Set;
        input.element = Some("<entry name=\"rule1\"/>".to_owned());
        input.move_position = Some(MovePosition::Top);
        assert!(validate_stage_payload(&input, true).is_err());

        let mut input = move_input(RULE_XPATH, None, None);
        input.action = StageAction::Delete;
        input.destructive_confirmation = Some(format!("DELETE {RULE_XPATH}"));
        input.move_destination = Some("rule2".to_owned());
        assert!(validate_stage_payload(&input, true).is_err());
    }

    #[test]
    fn extract_move_target_splits_container_and_name() {
        let (container, name) = extract_move_target(RULE_XPATH).expect("extract");
        assert_eq!(container, "/config/shared/rulebase/security/rules");
        assert_eq!(name, "rule1");

        assert!(extract_move_target("/config/shared/rulebase/security/rules").is_err());
        assert!(
            extract_move_target("/config/shared/rulebase/security/rules/entry[@name=]").is_err()
        );
    }

    #[test]
    fn offline_resolution_requires_indeterminate_state_and_exact_confirmation() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("state.json");
        let id = "a".repeat(64);
        let record = OperationRecord {
            id: id.clone(),
            owner: "writer".to_owned(),
            device: "fw".to_owned(),
            endpoint: "https://fw.example:443".to_owned(),
            // The record now holds vendor-opaque JSON: the discriminator string
            // in `action`, the full object in `actions`, the target in `xpath` —
            // matching what the deployed reader on LXC 608 expects.
            action: serde_json::Value::String("set".to_owned()),
            xpath: Some("/config/shared/address".to_owned()),
            actions: vec![
                serde_json::to_value(ChangeSetAction {
                    action: StageAction::Set,
                    xpath: "/config/shared/address".to_owned(),
                    element: Some("<entry name=\"x\"/>".to_owned()),
                    destructive_confirmation: None,
                    move_position: None,
                    move_destination: None,
                })
                .expect("action serializes"),
            ],
            change_set_id: None,
            current: format!("sha256:{}", "b".repeat(64)),
            state: LifecycleState::Staging,
            job_id: Some("123".to_owned()),
            details: None,
            config_lock_held: true,
            policy_signature: "policy".to_owned(),
            attribution: None,
            rollback_deadline_unix: None,
            config_authority: Some("local".to_owned()),
        };
        let mut state = mecmcp_changeset::persistence::ChangesetState::default();
        state.operations.insert(id.clone(), record);
        write_mutation_state(&path, &state).expect("state write");
        drop(
            ChangesetCoordinator::load(
                Some(&path),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(900),
                false,
            )
            .expect("restart recovery"),
        );
        assert_eq!(
            read_mutation_state(&path)
                .expect("recovered state")
                .operations[&id]
                .state,
            LifecycleState::Indeterminate
        );
        assert!(
            resolve_persisted_operation(
                &path,
                &id,
                RecoveryDisposition::Discarded,
                "not enough",
                mecmcp_changeset::OperationLimits::default(),
            )
            .is_err()
        );
        let output = resolve_persisted_operation(
            &path,
            &id,
            RecoveryDisposition::Discarded,
            &format!("RESOLVED {id} AS DISCARDED"),
            mecmcp_changeset::OperationLimits::default(),
        )
        .expect("resolve");
        assert_eq!(output.state, "discarded");
        assert!(!read_mutation_state(&path).expect("reload").operations[&id].config_lock_held);
    }
}

#[cfg(test)]
mod release_lock_tests {
    use super::*;

    fn api_error(message: &str) -> PanosMcpError {
        PanosMcpError::Api {
            device: "fw".to_owned(),
            code: -1,
            name: "unknown",
            message: message.to_owned(),
        }
    }

    /// The exact message observed from PAN-OS 12.1.5 after a commit released the
    /// vsys lock on our behalf (#75).
    #[test]
    fn already_unlocked_is_recognised() {
        assert!(is_already_unlocked(&api_error(
            "Config is not currently locked for scope vsys1"
        )));
        assert!(is_already_unlocked(&api_error(
            "config is NOT CURRENTLY LOCKED for scope shared"
        )));
    }

    /// A release that failed for a reason leaving the lock genuinely held must
    /// still surface. Swallowing these would report a device as unlocked while it
    /// silently blocks every later change.
    #[test]
    fn other_failures_are_not_swallowed() {
        assert!(!is_already_unlocked(&api_error("Permission denied")));
        assert!(!is_already_unlocked(&api_error(
            "Config is locked by another administrator"
        )));
        assert!(!is_already_unlocked(&PanosMcpError::HttpStatus {
            device: "fw".to_owned(),
            status: 503,
        }));
    }
}
