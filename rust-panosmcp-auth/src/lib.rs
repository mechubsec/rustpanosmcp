//! PAN-OS authorization vocabulary over the shared mecmcp auth core.

pub mod bearer;
mod grant;
pub mod secret;

pub use bearer::{BearerHeaderError, parse_bearer_header};
pub use grant::{MutationAction, MutationGrant, canonicalize_xpath_quotes, is_strict_xpath_shape};
pub use secret::SecretString;

// Shared core, re-exported so downstream `use rust_panosmcp_auth::…` paths
// keep working unchanged.
pub use mecmcp_auth::{
    ActorType, CallerCtx, FileError as TokenStoreFileError, Grant, ScopeSet, StoreError, Tier,
    TokenDigest, TokenEntry as SharedTokenEntry, TokenError, TokenSecret,
    TokenStore as SharedStore, TokenStoreFile as SharedFile, file::KnownNames, write_atomic,
};

/// PAN-OS token entry: the shared entry specialised to the PAN-OS grant.
pub type TokenEntry = SharedTokenEntry<MutationGrant>;
/// PAN-OS token store.
pub type TokenStore = SharedStore<MutationGrant>;
/// PAN-OS token file.
pub type TokenStoreFile = SharedFile<MutationGrant>;
/// PAN-OS caller context with mutation grant.
pub type CallerContext = CallerCtx<MutationGrant>;

/// Exact tool registry used to validate token scopes.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_panos_change_set",
    "approve_panos_change_set",
    "commit_panos_candidate",
    "create_panos_change_set",
    "diff_panos_candidate",
    "discard_panos_candidate",
    "execute_panos_op",
    "gather_device_facts",
    "get_candidate_fingerprint",
    "get_panorama_push_status",
    "get_panos_change_set",
    "get_panos_config",
    "get_panos_content_status",
    "get_panos_entry_digest",
    "get_panos_feed_status",
    "get_panos_ha_state",
    "get_panos_license_info",
    "get_panos_operation",
    "get_panos_software_status",
    "list_devices",
    "list_panorama_device_groups",
    "list_panorama_templates",
    "list_panos_entries",
    "list_panos_rulebase_entries",
    "query_panos_logs",
    "stage_panos_config",
    "test_panos_security_policy_match",
    "validate_panos_candidate",
];

/// Tools that always require an explicit token allowlist entry.
pub const MUTATION_TOOLS: &[&str] = &[
    "commit_panos_candidate",
    "apply_panos_change_set",
    "approve_panos_change_set",
    "create_panos_change_set",
    "diff_panos_candidate",
    "discard_panos_candidate",
    "get_candidate_fingerprint",
    "get_panos_change_set",
    "get_panos_operation",
    "query_panos_logs",
    "stage_panos_config",
    "validate_panos_candidate",
];
