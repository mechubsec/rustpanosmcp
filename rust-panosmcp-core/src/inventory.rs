//! Validated device inventory and secret-provider loading.

use crate::{PanosMcpError, Result};
use mecmcp_inventory::InventoryError as MecmcpInventoryError;
use rust_panosmcp_auth::SecretString;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use url::Url;

const INVENTORY_VERSION: u32 = 1;
const MAX_SECRET_BYTES: u64 = 16 * 1024;
const MAX_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENCY: usize = 4;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_DEVICE_CONCURRENCY: usize = 5;
const MAX_DEVICE_NAME_BYTES: usize = 64;
const MAX_DEVICES: usize = 256;
const MAX_TAGS_PER_DEVICE: usize = 32;
const MAX_WRITE_ROOTS_PER_DEVICE: usize = 32;

/// Who owns the authoritative configuration for this firewall.
///
/// A Panorama- or Strata Cloud Manager-managed firewall accepts local commits
/// that get overwritten at the management plane's next push. This enum records
/// ownership so the audit trail stops claiming durability it cannot support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PanosMcpConfigAuthority {
    /// The firewall is standalone and we control its configuration.
    Local,
    /// Configuration is owned by Panorama.
    Panorama,
    /// Configuration is owned by Strata Cloud Manager.
    StrataCloudManager,
    /// Ownership is not declared in the inventory.
    ///
    /// Treated as local for behavior, but recorded distinctly so the audit
    /// trail can tell "nobody said" from "we own it".
    #[default]
    Unknown,
}

impl PanosMcpConfigAuthority {
    /// Returns true only when the server owns the device's configuration.
    ///
    /// Used to refuse destructive operations on plane-managed firewalls.
    /// `Unknown` is treated as local for behavior but recorded separately.
    pub fn is_local(self) -> bool {
        matches!(self, Self::Local | Self::Unknown)
    }

    /// String representation for audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Panorama => "panorama",
            Self::StrataCloudManager => "strata-cloud-manager",
            Self::Unknown => "unknown",
        }
    }
}

/// Source used to resolve environment-backed secrets.
pub trait Environment: Send + Sync {
    /// Return the exact value of an environment variable when it exists.
    fn variable(&self, name: &str) -> Option<String>;
}

/// Production environment resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn variable(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Non-secret metadata safe to return from `list_devices`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct DeviceMetadata {
    /// Stable inventory name used by all MCP calls.
    pub name: String,
    /// Configured HTTPS management endpoint.
    pub endpoint: String,
    /// Optional virtual-system identifier.
    pub vsys: Option<String>,
    /// Operator-provided classification tags.
    pub tags: Vec<String>,
}

/// TLS trust material loaded and validated with the inventory.
#[derive(Clone)]
pub enum LoadedTlsTrust {
    /// Use platform trust roots and normal hostname validation.
    System,
    /// Trust only the PEM certificates loaded from this inventory entry.
    CustomCa {
        /// Original operator path, used only for diagnostics.
        source: PathBuf,
        /// Validated PEM bundle bytes.
        pem: Arc<[u8]>,
    },
    /// Trust an exact SHA-256 fingerprint of the presented leaf certificate.
    LeafSha256([u8; 32]),
}

impl fmt::Debug for LoadedTlsTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => formatter.write_str("System"),
            Self::CustomCa { source, .. } => formatter
                .debug_struct("CustomCa")
                .field("source", source)
                .field("pem", &"[CERTIFICATE DATA]")
                .finish(),
            Self::LeafSha256(_) => formatter.write_str("LeafSha256([FINGERPRINT])"),
        }
    }
}

/// Fully loaded device entry used to build a pooled API client.
#[derive(Clone)]
pub struct DeviceConfig {
    /// Safe public metadata.
    pub metadata: DeviceMetadata,
    /// Parsed base endpoint with no path/query/credentials.
    pub endpoint: Url,
    /// Resolved PAN-OS API credential.
    pub api_key: Arc<SecretString>,
    /// Strict TLS trust strategy.
    pub tls: LoadedTlsTrust,
    /// TCP/TLS connect deadline.
    pub connect_timeout: Duration,
    /// Whole request deadline, including response body.
    pub request_timeout: Duration,
    /// Maximum in-flight API calls for this device.
    pub max_concurrency: usize,
    /// Hard cap applied while streaming a PAN-OS response.
    pub max_response_bytes: usize,
    /// Explicit write policy. Its absence keeps every mutation tool disabled.
    pub mutation: Option<MutationPolicy>,
    /// Per-device blocklist rules for read-only operational commands and config reads.
    pub(crate) blocklist: Option<BlocklistRules>,
    /// Who owns the authoritative configuration for this firewall.
    pub config_authority: PanosMcpConfigAuthority,
}

/// Per-device blocklist rules for read-only tools.
///
/// This is not a confidentiality control on its own (MEC-528 F2): a rule
/// denies an xpath that matches its glob literally, but reading an
/// *ancestor* of a blocked subtree (`/config`, the default when no xpath is
/// given, is an ancestor of every subtree) returns that subtree's content
/// too, and no glob written against the descendant path can catch that --
/// the ancestor request never contains the descendant's text. Rely on the
/// PAN-OS admin role restriction (this server's role must not be able to
/// read `<mgt-config>` or certificate private keys at all) and
/// `mecmcp_redact`'s structural/value-shape passes as the actual
/// confidentiality controls; treat this blocklist as an operator-facing
/// convenience for narrowing *intentional* reads, not a boundary a caller is
/// prevented from reading past.
#[derive(Debug, Clone)]
pub(crate) struct BlocklistRules {
    /// Glob patterns denying operational commands (execute_panos_op).
    ///
    /// Only consulted when the resolved [`PolicyMode`] is `Blocklist`.
    pub(crate) commands: Vec<String>,
    /// Glob patterns denying XPath config reads (get_panos_config).
    ///
    /// The config domain is mode-independent -- always a deny-pattern
    /// blocklist -- so this applies regardless of [`PolicyMode`].
    pub(crate) xpath: Vec<String>,
    /// Token-prefix entries added to the global `policy.allow` defaults for
    /// this device's `execute_panos_op` commands. Only consulted when the
    /// resolved [`PolicyMode`] is `Allowlist`.
    pub(crate) allow: Vec<String>,
    /// Token-prefix entries added to the global `policy.allowed_pipes`
    /// defaults for this device. Only consulted when the resolved
    /// [`PolicyMode`] is `Allowlist`.
    pub(crate) allowed_pipes: Vec<String>,
}

/// Which authorization model governs `execute_panos_op` commands.
///
/// Mirrors `mecmcp_policy::CommandMode`, kept as a separate, serde-friendly
/// type (the upstream enum has no `Deserialize`/`Serialize` impl) so the
/// inventory JSON key stays a stable `"allowlist"` / `"blocklist"` string
/// independent of the upstream crate's enum shape.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Fail-closed: a command is denied unless it matches an `allow` entry.
    /// The default for any inventory with no `policy` section and no legacy
    /// deny-only `blocklist.commands` rules.
    Allowlist,
    /// Fail-open: a command is denied only if it matches a deny rule under
    /// `blocklist.commands`. The pre-existing behavior, kept for deployments
    /// that request it explicitly, or that have legacy deny rules and no
    /// `policy.mode` key (see [`Inventory::load_with_environment`]'s
    /// migration logging).
    Blocklist,
}

impl From<PolicyMode> for mecmcp_policy::CommandMode {
    fn from(mode: PolicyMode) -> Self {
        match mode {
            PolicyMode::Allowlist => mecmcp_policy::CommandMode::Allowlist,
            PolicyMode::Blocklist => mecmcp_policy::CommandMode::Blocklist,
        }
    }
}

/// Operator-controlled guardrails for PAN-OS candidate mutations.
#[derive(Debug, Clone)]
pub struct MutationPolicy {
    /// PAN-OS administrator associated with the API key and partial commits.
    pub admin: String,
    /// Exact XPath subtrees within which mutation is permitted.
    pub allowed_xpath_roots: Vec<String>,
    /// Whether delete actions may pass the separate confirmation gate.
    pub allow_delete: bool,
    /// Whether cross-administrator PAN-OS configuration lock acquisition is mandatory.
    pub require_config_lock: bool,
}

impl fmt::Debug for DeviceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceConfig")
            .field("metadata", &self.metadata)
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key)
            .field("tls", &self.tls)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_concurrency", &self.max_concurrency)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Immutable, name-indexed validated inventory.
#[derive(Debug, Clone)]
pub struct Inventory {
    source: PathBuf,
    devices: BTreeMap<String, Arc<DeviceConfig>>,
    /// Resolved authorization model for `execute_panos_op`; see [`PolicyMode`]
    /// and the migration logic in [`Inventory::load_with_environment`].
    policy_mode: PolicyMode,
    /// Global `policy.allow` entries every device's allowlist starts from.
    policy_allow_defaults: Vec<String>,
    /// Global `policy.allowed_pipes` entries every device's allowlist starts from.
    policy_allowed_pipes_defaults: Vec<String>,
}

impl Inventory {
    /// Load an inventory using the process environment for environment-backed
    /// API keys.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_environment(path, &ProcessEnvironment)
    }

    /// Device names only, without resolving any credential.
    ///
    /// The token subcommands validate scope references against the inventory but
    /// never contact a device, so requiring every API key to be present in the
    /// environment just to mint a token blocks setup before credentials exist.
    pub fn device_names(path: impl AsRef<Path>) -> Result<Vec<String>> {
        // Load the raw inventory file directly to avoid async/blocking issues
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|e| PanosMcpError::Inventory(format!("failed to read inventory: {e}")))?;

        // Try to parse as PAN-OS envelope first (which is what we expect)
        #[derive(Deserialize)]
        struct MinimalEnvelope {
            version: u32,
            devices: Vec<MinimalDevice>,
        }

        #[derive(Deserialize)]
        struct MinimalDevice {
            name: String,
        }

        let envelope: MinimalEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| PanosMcpError::Inventory(format!("invalid JSON: {e}")))?;

        if envelope.version != INVENTORY_VERSION {
            return Err(PanosMcpError::Inventory(format!(
                "unsupported inventory version {}; expected {INVENTORY_VERSION}",
                envelope.version
            )));
        }

        // PAN-OS rejects empty inventory
        if envelope.devices.is_empty() {
            return Err(PanosMcpError::Inventory(
                "inventory must contain at least one device".to_owned(),
            ));
        }

        if envelope.devices.len() > MAX_DEVICES {
            return Err(PanosMcpError::Inventory(format!(
                "inventory contains more than {MAX_DEVICES} devices"
            )));
        }

        let mut names = Vec::with_capacity(envelope.devices.len());
        let mut seen = BTreeSet::new();
        for device in envelope.devices {
            mecmcp_inventory::validate_device_name(&device.name)
                .map_err(convert_inventory_error)?;
            if !seen.insert(device.name.clone()) {
                return Err(PanosMcpError::Inventory(format!(
                    "duplicate device name '{}'",
                    device.name
                )));
            }
            names.push(device.name);
        }

        Ok(names)
    }

    /// Paths of file-backed API keys, without reading those files.
    ///
    /// The inventory document itself is read with [`std::fs::read`] and is not
    /// mode-checked. Custom CA bundle paths are not returned: the inventory
    /// loader accepts those separately from secret files, and this list is the
    /// input to the startup secret-file check.
    ///
    /// # Errors
    /// Returns an inventory error when the file cannot be read, is not the
    /// expected JSON shape, or lists more devices than the server allows.
    pub fn api_key_file_paths(path: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|error| {
            PanosMcpError::Inventory(format!("failed to read inventory: {error}"))
        })?;

        // Unknown fields are ignored. This only needs `api_key`; the full
        // inventory load still rejects a document it cannot use.
        #[derive(Deserialize)]
        struct ApiKeyPathFile {
            devices: Vec<ApiKeyPathDevice>,
        }

        #[derive(Deserialize)]
        struct ApiKeyPathDevice {
            api_key: ApiKeySource,
        }

        let parsed: ApiKeyPathFile = serde_json::from_slice(&bytes)
            .map_err(|error| PanosMcpError::Inventory(format!("invalid JSON: {error}")))?;

        if parsed.devices.len() > MAX_DEVICES {
            return Err(PanosMcpError::Inventory(format!(
                "inventory contains more than {MAX_DEVICES} devices"
            )));
        }

        let mut paths = Vec::new();
        let mut seen = BTreeSet::new();
        for device in parsed.devices {
            if let ApiKeySource::File { path } = device.api_key
                && seen.insert(path.clone())
            {
                paths.push(path);
            }
        }
        Ok(paths)
    }

    /// Load an inventory with an injectable environment resolver.
    pub fn load_with_environment(
        path: impl AsRef<Path>,
        environment: &dyn Environment,
    ) -> Result<Self> {
        let path = path.as_ref();

        // Load the raw file to avoid FileInventory's blocking_read calls
        let bytes = std::fs::read(path)
            .map_err(|e| PanosMcpError::Inventory(format!("failed to read inventory: {e}")))?;

        #[derive(Deserialize)]
        struct InventoryFile {
            version: u32,
            devices: Vec<RawDevice>,
            #[serde(default)]
            policy: Option<RawPolicyConfig>,
        }

        let parsed: InventoryFile = serde_json::from_slice(&bytes)
            .map_err(|e| PanosMcpError::Inventory(format!("invalid JSON: {e}")))?;

        if parsed.version != INVENTORY_VERSION {
            return Err(PanosMcpError::Inventory(format!(
                "unsupported inventory version {}; expected {INVENTORY_VERSION}",
                parsed.version
            )));
        }

        // PAN-OS rejects empty inventory
        if parsed.devices.is_empty() {
            return Err(PanosMcpError::Inventory(
                "inventory must contain at least one device".to_owned(),
            ));
        }

        if parsed.devices.len() > MAX_DEVICES {
            return Err(PanosMcpError::Inventory(format!(
                "inventory contains more than {MAX_DEVICES} devices"
            )));
        }

        // Resolve the execute_panos_op policy mode before consuming `devices`
        // (`load_device` takes each entry by value).
        //
        // - An explicit `policy.mode` always wins.
        // - Otherwise, a config with at least one legacy deny rule
        //   (`blocklist.commands` on any device) is treated as `Blocklist`
        //   for backward compatibility, with one startup WARN: fail-open
        //   blocklist mode has no allowlist to fall back on, and staying on
        //   it silently would be a silent security regression relative to
        //   the new fail-closed default.
        // - Otherwise (no policy section, or a freshly generated sample
        //   config with no deny rules), the fail-closed default applies.
        let has_legacy_deny_rules = parsed.devices.iter().any(|device| {
            device
                .blocklist
                .as_ref()
                .is_some_and(|bl| !bl.commands.is_empty())
        });
        let policy_mode = match parsed.policy.as_ref().and_then(|p| p.mode) {
            Some(mode) => mode,
            None if has_legacy_deny_rules => {
                tracing::warn!(
                    "execute_panos_op policy has deny rules but no explicit \
                     \"policy\": {{\"mode\": ...}} key; loading as fail-open \
                     \"blocklist\" mode for backward compatibility. Fail-open \
                     blocklist mode allows any command that does not match a \
                     deny rule -- switch to fail-closed \"allowlist\" mode \
                     when convenient. See docs/ for migration guidance."
                );
                PolicyMode::Blocklist
            }
            None => PolicyMode::Allowlist,
        };
        let (policy_allow_defaults, policy_allowed_pipes_defaults) = match parsed.policy {
            Some(policy) => (policy.allow, policy.allowed_pipes),
            None => (Vec::new(), Vec::new()),
        };

        // Load and resolve all devices
        let mut devices = BTreeMap::new();
        for raw in parsed.devices {
            let loaded = Arc::new(load_device(raw, environment)?);
            if devices
                .insert(loaded.metadata.name.clone(), loaded.clone())
                .is_some()
            {
                return Err(PanosMcpError::Inventory(format!(
                    "duplicate device name '{}'",
                    loaded.metadata.name
                )));
            }
        }

        Ok(Self {
            source: path.to_path_buf(),
            devices,
            policy_mode,
            policy_allow_defaults,
            policy_allowed_pipes_defaults,
        })
    }

    /// Resolved authorization model for `execute_panos_op`; see [`PolicyMode`].
    #[must_use]
    pub(crate) fn policy_mode(&self) -> PolicyMode {
        self.policy_mode
    }

    /// Global `policy.allow` entries every device's allowlist starts from.
    #[must_use]
    pub(crate) fn policy_allow_defaults(&self) -> &[String] {
        &self.policy_allow_defaults
    }

    /// Global `policy.allowed_pipes` entries every device's allowlist starts from.
    #[must_use]
    pub(crate) fn policy_allowed_pipes_defaults(&self) -> &[String] {
        &self.policy_allowed_pipes_defaults
    }

    /// Source inventory path.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Resolve only an exact configured device name.
    pub fn device(&self, name: &str) -> Result<Arc<DeviceConfig>> {
        self.devices
            .get(name)
            .cloned()
            .ok_or_else(|| PanosMcpError::UnknownDevice(name.to_owned()))
    }

    /// Safe metadata in stable name order.
    #[must_use]
    pub fn metadata(&self) -> Vec<DeviceMetadata> {
        self.devices
            .values()
            .map(|device| device.metadata.clone())
            .collect()
    }

    /// Iterate the validated device entries in stable name order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = Arc<DeviceConfig>> + '_ {
        self.devices.values().cloned()
    }
}

#[derive(Debug, Deserialize, serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawDevice {
    name: String,
    endpoint: String,
    #[serde(default)]
    vsys: Option<String>,
    api_key: ApiKeySource,
    #[serde(default)]
    tls: TlsTrust,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_connect_timeout_secs")]
    connect_timeout_secs: u64,
    #[serde(default = "default_request_timeout_secs")]
    request_timeout_secs: u64,
    #[serde(default = "default_max_concurrency")]
    max_concurrency: usize,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: usize,
    #[serde(default)]
    mutation: Option<RawMutationPolicy>,
    #[serde(default)]
    blocklist: Option<RawBlocklistRules>,
    #[serde(default)]
    config_authority: PanosMcpConfigAuthority,
}

#[derive(Debug, Deserialize, serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawMutationPolicy {
    admin: String,
    allowed_xpath_roots: Vec<String>,
    #[serde(default)]
    allow_delete: bool,
    #[serde(default = "default_true")]
    require_config_lock: bool,
}

#[derive(Debug, Deserialize, serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawBlocklistRules {
    #[serde(default)]
    commands: Vec<String>,
    #[serde(default)]
    xpath: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    allowed_pipes: Vec<String>,
}

/// Global `execute_panos_op` policy section (top-level `policy` key).
#[derive(Debug, Default, Deserialize, serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawPolicyConfig {
    /// `allowlist` (fail-closed) or `blocklist` (fail-open). See [`PolicyMode`].
    #[serde(default)]
    mode: Option<PolicyMode>,
    /// Default token-prefix allowlist entries, shared by every device.
    #[serde(default)]
    allow: Vec<String>,
    /// Default token-prefix pipe-stage entries, shared by every device.
    #[serde(default)]
    allowed_pipes: Vec<String>,
}

#[derive(Debug, Deserialize, serde::Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ApiKeySource {
    Env { name: String },
    File { path: PathBuf },
}

#[derive(Debug, Default, Deserialize, serde::Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TlsTrust {
    #[default]
    System,
    CustomCa {
        path: PathBuf,
    },
    LeafSha256 {
        fingerprint: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum FilePurpose {
    Secret,
    CaBundle,
}

impl FilePurpose {
    const fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::CaBundle => "CA bundle",
        }
    }

    const fn max_bytes(self) -> u64 {
        match self {
            Self::Secret => MAX_SECRET_BYTES,
            Self::CaBundle => MAX_CA_BUNDLE_BYTES,
        }
    }
}

fn convert_inventory_error(err: MecmcpInventoryError) -> PanosMcpError {
    match err {
        MecmcpInventoryError::InvalidName(s) => {
            PanosMcpError::Inventory(format!("invalid device name: {s}"))
        }
        MecmcpInventoryError::DuplicateName(s) => {
            PanosMcpError::Inventory(format!("duplicate device name '{s}'"))
        }
        MecmcpInventoryError::UnknownDevice(s) => PanosMcpError::UnknownDevice(s),
        MecmcpInventoryError::ParseError(s) => {
            PanosMcpError::Inventory(format!("parse error: {s}"))
        }
        MecmcpInventoryError::IoError(e) => PanosMcpError::Inventory(format!("I/O error: {e}")),
        MecmcpInventoryError::UnsupportedVersion(v) => PanosMcpError::Inventory(format!(
            "unsupported inventory version {v}; expected {INVENTORY_VERSION}"
        )),
        MecmcpInventoryError::EmptyInventory => {
            PanosMcpError::Inventory("inventory must contain at least one device".to_owned())
        }
    }
}

fn load_device(raw: RawDevice, environment: &dyn Environment) -> Result<DeviceConfig> {
    validate_identifier("device name", &raw.name, MAX_DEVICE_NAME_BYTES)?;
    if let Some(vsys) = &raw.vsys {
        validate_identifier("vsys", vsys, MAX_DEVICE_NAME_BYTES)?;
    }

    let endpoint = validate_endpoint(&raw.endpoint)?;
    let api_key = Arc::new(SecretString::new(load_api_key(&raw.api_key, environment)?));
    let tls = load_tls(raw.tls)?;
    let mutation = raw
        .mutation
        .map(|policy| load_mutation_policy(&raw.name, policy))
        .transpose()?;
    let blocklist = raw.blocklist.map(|rules| BlocklistRules {
        commands: rules.commands,
        xpath: rules.xpath,
        allow: rules.allow,
        allowed_pipes: rules.allowed_pipes,
    });

    if !(1..=MAX_DEVICE_CONCURRENCY).contains(&raw.max_concurrency) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' max_concurrency must be between 1 and {MAX_DEVICE_CONCURRENCY}",
            raw.name
        )));
    }
    if !(1..=300).contains(&raw.connect_timeout_secs) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' connect_timeout_secs must be between 1 and 300",
            raw.name
        )));
    }
    if !(1..=3600).contains(&raw.request_timeout_secs) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' request_timeout_secs must be between 1 and 3600",
            raw.name
        )));
    }
    if !(1024..=DEFAULT_MAX_RESPONSE_BYTES).contains(&raw.max_response_bytes) {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' max_response_bytes must be between 1024 and {DEFAULT_MAX_RESPONSE_BYTES}",
            raw.name
        )));
    }

    let mut seen_tags = BTreeSet::new();
    if raw.tags.len() > MAX_TAGS_PER_DEVICE {
        return Err(PanosMcpError::Inventory(format!(
            "device '{}' contains more than {MAX_TAGS_PER_DEVICE} tags",
            raw.name
        )));
    }
    let mut tags = Vec::with_capacity(raw.tags.len());
    for tag in raw.tags {
        validate_identifier("tag", &tag, MAX_DEVICE_NAME_BYTES)?;
        if seen_tags.insert(tag.clone()) {
            tags.push(tag);
        }
    }

    Ok(DeviceConfig {
        metadata: DeviceMetadata {
            name: raw.name,
            endpoint: endpoint.as_str().trim_end_matches('/').to_owned(),
            vsys: raw.vsys,
            tags,
        },
        endpoint,
        api_key,
        tls,
        connect_timeout: Duration::from_secs(raw.connect_timeout_secs),
        request_timeout: Duration::from_secs(raw.request_timeout_secs),
        max_concurrency: raw.max_concurrency,
        max_response_bytes: raw.max_response_bytes,
        mutation,
        blocklist,
        config_authority: raw.config_authority,
    })
}

fn load_mutation_policy(device: &str, raw: RawMutationPolicy) -> Result<MutationPolicy> {
    validate_identifier("mutation admin", &raw.admin, MAX_DEVICE_NAME_BYTES)?;
    if raw.allowed_xpath_roots.is_empty() {
        return Err(PanosMcpError::Inventory(format!(
            "device '{device}' mutation policy must specify at least one allowed_xpath_roots entry"
        )));
    }
    if raw.allowed_xpath_roots.len() > MAX_WRITE_ROOTS_PER_DEVICE {
        return Err(PanosMcpError::Inventory(format!(
            "device '{device}' mutation policy contains more than {MAX_WRITE_ROOTS_PER_DEVICE} roots"
        )));
    }
    for root in &raw.allowed_xpath_roots {
        if !root.starts_with("/config/") {
            return Err(PanosMcpError::Inventory(format!(
                "device '{device}' mutation XPath root '{root}' must start with '/config/'"
            )));
        }
        if root.contains("//") {
            return Err(PanosMcpError::Inventory(format!(
                "device '{device}' mutation XPath root '{root}' contains '//' (empty path component)"
            )));
        }
    }
    Ok(MutationPolicy {
        admin: raw.admin,
        allowed_xpath_roots: raw.allowed_xpath_roots,
        allow_delete: raw.allow_delete,
        require_config_lock: raw.require_config_lock,
    })
}

fn load_api_key(source: &ApiKeySource, environment: &dyn Environment) -> Result<String> {
    match source {
        ApiKeySource::Env { name } => environment.variable(name).ok_or_else(|| {
            PanosMcpError::Inventory(format!(
                "api_key references environment variable '{name}' which is not set"
            ))
        }),
        ApiKeySource::File { path } => {
            let bytes = read_validated_file(path, FilePurpose::Secret)?;
            let value = String::from_utf8(bytes).map_err(|_| {
                PanosMcpError::Inventory(format!(
                    "API key file '{}' is not valid UTF-8",
                    path.display()
                ))
            })?;
            Ok(value.trim().to_owned())
        }
    }
}

fn load_tls(trust: TlsTrust) -> Result<LoadedTlsTrust> {
    match trust {
        TlsTrust::System => Ok(LoadedTlsTrust::System),
        TlsTrust::CustomCa { path } => {
            let pem = read_validated_file(&path, FilePurpose::CaBundle)?;
            Ok(LoadedTlsTrust::CustomCa {
                source: path,
                pem: pem.into(),
            })
        }
        TlsTrust::LeafSha256 { fingerprint } => {
            let digest = parse_sha256(&fingerprint)?;
            Ok(LoadedTlsTrust::LeafSha256(digest))
        }
    }
}

fn validate_identifier(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(PanosMcpError::Inventory(format!(
            "{label} must be 1-{max_bytes} bytes"
        )));
    }
    if value.starts_with('-') {
        return Err(PanosMcpError::Inventory(format!(
            "{label} cannot start with '-'"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(PanosMcpError::Inventory(format!(
            "{label} may only contain ASCII alphanumeric, '_', '.', or '-'"
        )));
    }
    Ok(())
}

fn validate_endpoint(raw: &str) -> Result<Url> {
    let endpoint = Url::parse(raw)
        .map_err(|error| PanosMcpError::Inventory(format!("invalid endpoint URL: {error}")))?;
    if endpoint.scheme() != "https" {
        return Err(PanosMcpError::Inventory(
            "device endpoint must use https".to_owned(),
        ));
    }
    if endpoint.host_str().is_none() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must include a host".to_owned(),
        ));
    }
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must not include credentials".to_owned(),
        ));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must not include a query or fragment".to_owned(),
        ));
    }
    if endpoint.path() != "/" && !endpoint.path().is_empty() {
        return Err(PanosMcpError::Inventory(
            "device endpoint must not include a path".to_owned(),
        ));
    }
    Ok(endpoint)
}

fn parse_sha256(s: &str) -> Result<[u8; 32]> {
    let hex = s.strip_prefix("sha256:").unwrap_or(s);
    if hex.len() != 64 {
        return Err(PanosMcpError::Inventory(
            "SHA-256 fingerprint must be exactly 64 hex characters".to_owned(),
        ));
    }
    let mut digest = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| {
            PanosMcpError::Inventory("SHA-256 fingerprint contains invalid UTF-8".to_owned())
        })?;
        digest[index] = u8::from_str_radix(byte_str, 16).map_err(|_| {
            PanosMcpError::Inventory("SHA-256 fingerprint contains non-hex characters".to_owned())
        })?;
    }
    Ok(digest)
}

fn read_validated_file(path: &Path, purpose: FilePurpose) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        let descriptor = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error: error.into(),
        })?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = {
        let link_metadata = fs::symlink_metadata(path).map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error,
        })?;
        if link_metadata.file_type().is_symlink() {
            return Err(PanosMcpError::FileSecurity {
                purpose: purpose.label(),
                path: path.to_path_buf(),
                reason: "symbolic links are forbidden".to_owned(),
            });
        }
        fs::File::open(path).map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error,
        })?
    };
    let metadata = file.metadata().map_err(|error| PanosMcpError::FileIo {
        purpose: purpose.label(),
        path: path.to_path_buf(),
        error,
    })?;
    if !metadata.is_file() {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: "must be a regular file".to_owned(),
        });
    }
    if metadata.len() > purpose.max_bytes() {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("exceeds the {}-byte limit", purpose.max_bytes()),
        });
    }

    #[cfg(unix)]
    validate_unix_file_security(path, &metadata, purpose)?;

    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(purpose.max_bytes() as usize));
    file.take(purpose.max_bytes() + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PanosMcpError::FileIo {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            error,
        })?;
    if bytes.len() as u64 > purpose.max_bytes() {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("exceeds the {}-byte limit", purpose.max_bytes()),
        });
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_unix_file_security(
    path: &Path,
    metadata: &fs::Metadata,
    purpose: FilePurpose,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode() & 0o777;
    let forbidden = match purpose {
        FilePurpose::Secret => 0o077,
        FilePurpose::CaBundle => 0o022,
    };
    if mode & forbidden != 0 {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("mode {mode:04o} is too permissive"),
        });
    }

    let owner = metadata.uid();
    let effective = rustix::process::geteuid().as_raw();
    if owner != effective && owner != 0 {
        return Err(PanosMcpError::FileSecurity {
            purpose: purpose.label(),
            path: path.to_path_buf(),
            reason: format!("owner uid {owner} is neither the effective uid {effective} nor root"),
        });
    }
    Ok(())
}

const fn default_connect_timeout_secs() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

const fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

const fn default_max_concurrency() -> usize {
    DEFAULT_MAX_CONCURRENCY
}

const fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    struct TestEnvironment {
        variables: HashMap<String, String>,
    }

    impl TestEnvironment {
        fn with(mut self, name: &str, value: &str) -> Self {
            self.variables.insert(name.to_owned(), value.to_owned());
            self
        }
    }

    impl Environment for TestEnvironment {
        fn variable(&self, name: &str) -> Option<String> {
            self.variables.get(name).cloned()
        }
    }

    fn write_inventory(directory: &Path, content: &str) -> PathBuf {
        let path = directory.join("devices.json");
        fs::write(&path, content).expect("write inventory");
        path
    }

    #[test]
    fn loads_real_panos_fixture_structure() {
        // The example file references paths that don't exist, so we can only validate
        // that device_names() works (which doesn't require credential resolution).
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("parent directory exists")
            .join("config/devices.example.json");

        let names =
            Inventory::device_names(&path).expect("load device names from example devices.json");
        assert_eq!(names, vec!["lab-fw-01"]);
    }

    #[test]
    fn rejects_empty_inventory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(directory.path(), r#"{"version": 1, "devices": []}"#);
        let error = Inventory::load(&path).expect_err("empty inventory rejected");
        assert!(
            error
                .to_string()
                .contains("must contain at least one device")
        );
    }

    #[test]
    fn device_names_loads_without_credential_resolution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [
                    {"name": "fw", "endpoint": "https://fw.test", "api_key": {"type": "env", "name": "MISSING_KEY"}}
                ]
            }"#,
        );
        let names = Inventory::device_names(&path).expect("device names without credentials");
        assert_eq!(names, vec!["fw"]);
    }

    /// A world-readable inventory is still readable. Only file-backed API keys
    /// are returned; an env key and a custom CA bundle are not secret files.
    #[test]
    fn api_key_file_paths_lists_secret_files_and_skips_ca_bundles() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let key_a = directory.path().join("a.key");
        let key_b = directory.path().join("b.key");
        let ca = directory.path().join("ca.pem");
        let inventory = directory.path().join("devices.json");
        fs::write(
            &inventory,
            format!(
                r#"{{
                    "version": 1,
                    "devices": [
                        {{"name": "fw-a", "endpoint": "https://a.test", "api_key": {{"type": "file", "path": "{}"}}, "tls": {{"type": "custom_ca", "path": "{}"}}}},
                        {{"name": "fw-b", "endpoint": "https://b.test", "api_key": {{"type": "env", "name": "PANOS_TEST_KEY"}}}},
                        {{"name": "fw-c", "endpoint": "https://c.test", "api_key": {{"type": "file", "path": "{}"}}}},
                        {{"name": "fw-d", "endpoint": "https://d.test", "api_key": {{"type": "file", "path": "{}"}}}}
                    ]
                }}"#,
                key_a.display(),
                ca.display(),
                key_b.display(),
                key_a.display(),
            ),
        )
        .expect("write inventory");
        fs::set_permissions(&inventory, fs::Permissions::from_mode(0o644)).expect("mode");

        let paths = Inventory::api_key_file_paths(&inventory).expect("list api key files");
        assert_eq!(paths, vec![key_a, key_b]);
    }

    #[test]
    fn resolves_env_api_key() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [
                    {"name": "fw", "endpoint": "https://fw.test", "api_key": {"type": "env", "name": "FW_KEY"}}
                ]
            }"#,
        );
        let environment = TestEnvironment::default().with("FW_KEY", "env-backed-key");
        let inventory = Inventory::load_with_environment(&path, &environment).expect("load");
        assert_eq!(
            inventory
                .device("fw")
                .expect("device")
                .api_key
                .expose_secret(),
            "env-backed-key"
        );
    }

    #[test]
    fn resolves_file_api_key() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let key_file = directory.path().join("key.txt");
        fs::write(&key_file, "file-backed-api-key\n").expect("write key file");
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).expect("chmod");
        let path = write_inventory(
            directory.path(),
            &format!(
                r#"{{
                    "version": 1,
                    "devices": [
                        {{"name": "fw", "endpoint": "https://fw.test", "api_key": {{"type": "file", "path": "{}"}}}}
                    ]
                }}"#,
                key_file.display()
            ),
        );
        let inventory = Inventory::load(&path).expect("load");
        assert_eq!(
            inventory
                .device("fw")
                .expect("device")
                .api_key
                .expose_secret(),
            "file-backed-api-key"
        );
    }

    #[test]
    fn parses_prefixed_leaf_fingerprint() {
        let digest = parse_sha256(&format!("sha256:{}", "a5".repeat(32))).expect("fingerprint");
        assert!(digest.iter().all(|byte| *byte == 0xa5));
        assert!(parse_sha256("short").is_err());
    }

    #[test]
    fn device_names_succeeds_without_credentials() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [
                    {"name": "fw-one", "endpoint": "https://one.test", "api_key": {"type": "env", "name": "MISSING_KEY_ONE"}},
                    {"name": "fw-two", "endpoint": "https://two.test", "api_key": {"type": "env", "name": "MISSING_KEY_TWO"}}
                ]
            }"#,
        );

        let names = Inventory::device_names(&path).expect("device names without credentials");
        assert_eq!(names, vec!["fw-one", "fw-two"]);

        let error = Inventory::load_with_environment(&path, &TestEnvironment::default())
            .expect_err("full load must fail without credentials");
        assert!(error.to_string().contains("MISSING_KEY_ONE"));
    }

    #[test]
    fn device_names_rejects_bad_version() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{"version": 999, "devices": [{"name": "fw", "endpoint": "https://fw.test", "api_key": {"type": "env", "name": "KEY"}}]}"#,
        );
        let error = Inventory::device_names(&path).expect_err("bad version rejected");
        assert!(error.to_string().contains("unsupported inventory version"));
    }

    #[test]
    fn device_names_rejects_duplicate_names() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{"version": 1, "devices": [
                {"name": "fw", "endpoint": "https://one.test", "api_key": {"type": "env", "name": "KEY"}},
                {"name": "fw", "endpoint": "https://two.test", "api_key": {"type": "env", "name": "KEY"}}
            ]}"#,
        );
        let error = Inventory::device_names(&path).expect_err("duplicate names rejected");
        assert!(error.to_string().contains("duplicate device name"));
    }

    #[test]
    fn loads_valid_environment_backed_inventory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [{
                    "name": "lab-fw-01",
                    "endpoint": "https://fw.example.test:4443",
                    "api_key": {"type": "env", "name": "PANOS_TEST_KEY"},
                    "tags": ["lab", "lab"]
                }]
            }"#,
        );

        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");
        let inventory =
            Inventory::load_with_environment(path, &environment).expect("valid inventory");
        let device = inventory.device("lab-fw-01").expect("known device");
        assert_eq!(device.metadata.endpoint, "https://fw.example.test:4443");
        assert_eq!(device.metadata.tags, ["lab"]);
        assert_eq!(device.max_concurrency, 4);
        assert!(device.mutation.is_none());
        assert_eq!(device.api_key.expose_secret(), "test-api-key-value");
        assert!(!format!("{device:?}").contains("test-api-key-value"));
    }

    #[test]
    fn mutation_policy_is_explicit_narrow_and_validated() {
        let directory = tempfile::tempdir().expect("tempdir");
        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");

        let valid = write_inventory(
            directory.path(),
            r#"{"version":1,"devices":[{"name":"fw","endpoint":"https://one.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"},"mutation":{"admin":"mcp-admin","allowed_xpath_roots":["/config/shared/address"],"allow_delete":true}}]}"#,
        );
        let inventory =
            Inventory::load_with_environment(valid, &environment).expect("mutation policy");
        let policy = inventory
            .device("fw")
            .expect("device")
            .mutation
            .clone()
            .expect("explicit mutation policy");
        assert_eq!(policy.admin, "mcp-admin");
        assert!(policy.allow_delete);
        assert!(policy.require_config_lock);

        let broad = write_inventory(
            directory.path(),
            r#"{"version":1,"devices":[{"name":"fw","endpoint":"https://one.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"},"mutation":{"admin":"mcp-admin","allowed_xpath_roots":["/config"]}}]}"#,
        );
        assert!(Inventory::load_with_environment(broad, &environment).is_err());
    }

    #[test]
    fn rejects_plaintext_api_key_field() {
        let directory = tempfile::tempdir().expect("tempdir");
        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");

        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [{
                    "name": "fw",
                    "endpoint": "https://fw.example.test",
                    "api_key": {"type": "env", "name": "PANOS_TEST_KEY", "value": "secret"}
                }]
            }"#,
        );
        let error = Inventory::load_with_environment(path, &environment)
            .expect_err("unknown plaintext field must be refused");
        assert!(error.to_string().contains("unknown field"));
        assert!(!error.to_string().contains("test-api-key-value"));
    }

    #[test]
    fn rejects_non_https_and_endpoint_paths() {
        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");
        for endpoint in ["http://fw.example.test", "https://fw.example.test/api"] {
            let directory = tempfile::tempdir().expect("tempdir");
            let path = write_inventory(
                directory.path(),
                &format!(
                    r#"{{"version":1,"devices":[{{"name":"fw","endpoint":"{endpoint}","api_key":{{"type":"env","name":"PANOS_TEST_KEY"}}}}]}}"#
                ),
            );
            assert!(Inventory::load_with_environment(path, &environment).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_names_and_excessive_concurrency() {
        let directory = tempfile::tempdir().expect("tempdir");
        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");

        let duplicate = write_inventory(
            directory.path(),
            r#"{"version":1,"devices":[
                {"name":"fw","endpoint":"https://one.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"}},
                {"name":"fw","endpoint":"https://two.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"}}
            ]}"#,
        );
        assert!(Inventory::load_with_environment(duplicate, &environment).is_err());

        let too_many = write_inventory(
            directory.path(),
            r#"{"version":1,"devices":[
                {"name":"fw","endpoint":"https://one.test","api_key":{"type":"env","name":"PANOS_TEST_KEY"},"max_concurrency":6}
            ]}"#,
        );
        assert!(Inventory::load_with_environment(too_many, &environment).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("tempdir");
        let environment = TestEnvironment::default();

        let secret = directory.path().join("api-key");
        fs::write(&secret, "file-backed-api-key").expect("write secret");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).expect("chmod");
        let path = write_inventory(
            directory.path(),
            &format!(
                r#"{{"version":1,"devices":[{{"name":"fw","endpoint":"https://one.test","api_key":{{"type":"file","path":"{}"}}}}]}}"#,
                secret.display()
            ),
        );
        let error = Inventory::load_with_environment(&path, &environment)
            .expect_err("world-readable secret must be refused");
        assert!(error.to_string().contains("too permissive"));

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("chmod");
        let inventory =
            Inventory::load_with_environment(path, &environment).expect("private secret");
        assert_eq!(
            inventory
                .device("fw")
                .expect("device")
                .api_key
                .expose_secret(),
            "file-backed-api-key"
        );
    }

    #[test]
    fn config_authority_field_is_optional_for_backward_compatibility() {
        // This test verifies that existing devices.json files (LXC 601 and 608)
        // load unchanged when the config_authority field is absent.
        let directory = tempfile::tempdir().expect("tempdir");
        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");

        // A minimal device entry without config_authority field
        let path = write_inventory(
            directory.path(),
            r#"{
                "version": 1,
                "devices": [{
                    "name": "fw",
                    "endpoint": "https://fw.test",
                    "api_key": {"type": "env", "name": "PANOS_TEST_KEY"}
                }]
            }"#,
        );

        // This must NOT fail - config_authority is optional
        let inventory = Inventory::load_with_environment(&path, &environment)
            .expect("inventory without config_authority must load");

        let device = inventory.device("fw").expect("device");
        assert_eq!(device.metadata.name, "fw");
        // When absent, defaults to Unknown
        assert_eq!(device.config_authority, PanosMcpConfigAuthority::Unknown);
    }

    #[test]
    fn config_authority_accepts_valid_values() {
        let directory = tempfile::tempdir().expect("tempdir");
        let environment = TestEnvironment::default().with("PANOS_TEST_KEY", "test-api-key-value");

        // Test all valid config_authority values
        for (value, expected) in [
            ("local", PanosMcpConfigAuthority::Local),
            ("panorama", PanosMcpConfigAuthority::Panorama),
            (
                "strata-cloud-manager",
                PanosMcpConfigAuthority::StrataCloudManager,
            ),
            ("unknown", PanosMcpConfigAuthority::Unknown),
        ] {
            let path = write_inventory(
                directory.path(),
                &format!(
                    r#"{{
                        "version": 1,
                        "devices": [{{
                            "name": "fw",
                            "endpoint": "https://fw.test",
                            "api_key": {{"type": "env", "name": "PANOS_TEST_KEY"}},
                            "config_authority": "{value}"
                        }}]
                    }}"#
                ),
            );

            let inventory = Inventory::load_with_environment(&path, &environment)
                .expect("inventory with config_authority must load");

            let device = inventory.device("fw").expect("device");
            assert_eq!(
                device.config_authority, expected,
                "config_authority={value} should parse to {expected:?}"
            );
        }
    }

    #[test]
    fn config_authority_is_local_distinguishes_ownership() {
        // Local and Unknown are treated as local for behavior, but recorded distinctly
        assert!(PanosMcpConfigAuthority::Local.is_local());
        assert!(PanosMcpConfigAuthority::Unknown.is_local());
        assert!(!PanosMcpConfigAuthority::Panorama.is_local());
        assert!(!PanosMcpConfigAuthority::StrataCloudManager.is_local());

        // Each has a distinct audit representation
        assert_eq!(PanosMcpConfigAuthority::Local.as_str(), "local");
        assert_eq!(PanosMcpConfigAuthority::Unknown.as_str(), "unknown");
        assert_eq!(PanosMcpConfigAuthority::Panorama.as_str(), "panorama");
        assert_eq!(
            PanosMcpConfigAuthority::StrataCloudManager.as_str(),
            "strata-cloud-manager"
        );
    }
}
