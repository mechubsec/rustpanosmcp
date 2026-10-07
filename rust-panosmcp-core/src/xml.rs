//! Bounded PAN-OS XML parsing and read-only input validation.

use crate::{PanosMcpError, Result};
use quick_xml::{Reader, XmlVersion, events::Event};
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Maximum accepted operational command body.
pub const MAX_OP_COMMAND_BYTES: usize = 64 * 1024;
/// Maximum accepted configuration XPath.
pub const MAX_XPATH_BYTES: usize = 4096;
/// Maximum accepted XML element for one candidate mutation.
pub const MAX_CONFIG_ELEMENT_BYTES: usize = 256 * 1024;
const MAX_EXTRACTED_TEXT_BYTES: usize = 4096;
const MAX_ENVELOPE_ATTRIBUTE_BYTES: usize = 64;
/// Maximum accepted PAN-OS job identifier length (ASCII digits only).
const MAX_JOB_ID_BYTES: usize = 32;
/// Maximum `name` attribute accepted from a Panorama device-group/template/push entry.
const MAX_ENTRY_NAME_BYTES: usize = 256;
/// Maximum top-level entries (device-groups, templates, pushed devices) parsed from one response.
const MAX_LIST_ENTRIES: usize = 4096;
/// Maximum nested members (member firewalls, template variables) parsed per entry.
const MAX_MEMBERS_PER_ENTRY: usize = 4096;

/// Parser limits applied before semantic response processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    /// Maximum raw response size in bytes.
    pub max_bytes: usize,
    /// Maximum nested element depth.
    pub max_depth: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_bytes: 5 * 1024 * 1024,
            max_depth: 64,
        }
    }
}

/// Minimal metadata from a validated PAN-OS `<response>` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSummary {
    /// `status` attribute, when present.
    pub status: Option<String>,
    /// PAN-OS numeric `code` attribute, when present.
    pub code: Option<String>,
}

/// Validated PAN-OS response and its stable envelope fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanosResponse {
    /// PAN-OS status attribute.
    pub status: String,
    /// PAN-OS numeric response code, if supplied.
    pub code: Option<i32>,
    /// Bounded human-readable message extracted from `<msg>`.
    pub message: String,
    /// Complete, already size-bounded response XML.
    pub xml: String,
}

impl PanosResponse {
    /// Whether PAN-OS declared the request successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.eq_ignore_ascii_case("success") && !matches!(self.code, Some(1..=18 | 21..))
    }

    /// Convert a PAN-OS error envelope to a stable typed error.
    pub fn ensure_success(self, device: &str) -> Result<Self> {
        if self.is_success() {
            return Ok(self);
        }
        let code = self.code.unwrap_or(-1);
        let message = if self.message.is_empty() {
            "PAN-OS returned an error without a message".to_owned()
        } else {
            self.message.clone()
        };
        Err(PanosMcpError::api(
            device,
            code,
            panos_api_code_name(code),
            message,
        ))
    }
}

/// Selected, stable fields returned by `show system info`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DeviceFacts {
    /// Configured hostname.
    pub hostname: Option<String>,
    /// Management IP address.
    pub management_ip: Option<String>,
    /// Hardware or VM model.
    pub model: Option<String>,
    /// Device serial number.
    pub serial: Option<String>,
    /// PAN-OS software version.
    pub software_version: Option<String>,
    /// Application content version.
    pub app_version: Option<String>,
    /// Threat content version.
    pub threat_version: Option<String>,
    /// Device uptime as reported by PAN-OS.
    pub uptime: Option<String>,
    /// Device family when supplied by the release.
    pub family: Option<String>,
}

/// One `<entry>` captured from a PAN-OS list container, with its exact source
/// bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ConfigEntry {
    /// Value of the entry's `name` attribute, or empty when absent.
    pub name: String,
    /// The entry's exact source XML, including its own `<entry>` tags.
    pub xml: String,
    /// `sha256:<hex>` over `xml`. Changes if and only if this entry's source
    /// XML changes -- the point of hashing per entry rather than hashing the
    /// whole config root just to notice one rule moved.
    pub digest: String,
}

/// Result of scanning a PAN-OS list response for its top-level `<entry>`
/// children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryScanResult {
    /// PAN-OS envelope status.
    pub status: String,
    /// PAN-OS numeric response code, when supplied.
    pub code: Option<i32>,
    /// Entries within the requested `[offset, offset + limit)` window.
    pub entries: Vec<ConfigEntry>,
    /// Count of complete entries observed in the (possibly truncated) response.
    pub total_seen: usize,
    /// True when the response ended before its root element closed.
    pub truncated: bool,
}

/// Maximum nesting depth the entry scanner will track before refusing input.
///
/// Not `XmlLimits::max_depth`: that guards a strict single-document parse,
/// this guards a stack of owned tag names built up over a scan that
/// deliberately tolerates a truncated tail, so it needs its own bound.
const MAX_SCAN_DEPTH: usize = 128;

/// Scan a PAN-OS `<response><result>...</result></response>` document for the
/// `<entry>` elements nested at least `min_depth` levels below the root --
/// `3` for a container fetch (`response`/`result`/`container`/`entry`), `2`
/// for an XPath that already resolves to one entry directly under `<result>`.
///
/// Only complete entries are returned, sliced out of `raw` byte-for-byte, and
/// only those inside `[offset, offset + limit)` are materialized; entries
/// outside the window are counted but never copied, so a huge rulebase costs
/// one pass over the bytes rather than one allocation per rule.
///
/// Tolerant of a response the caller intentionally truncated mid-stream to
/// stay under a byte budget: once the envelope's root start tag has been
/// read, a read error or an early `Eof` ends the scan rather than failing it,
/// and any entry still open at that point is dropped rather than
/// half-reported. A read error or missing envelope *before* the root's own
/// start tag closes is still a hard failure -- that is not a size problem,
/// it is not PAN-OS XML.
pub fn scan_config_entries(
    raw: &[u8],
    offset: usize,
    limit: usize,
    min_depth: usize,
) -> Result<EntryScanResult> {
    let mut reader = Reader::from_reader(raw);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;

    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut status: Option<String> = None;
    let mut code: Option<String> = None;
    let mut saw_root = false;
    let mut root_closed = false;
    let mut entries = Vec::new();
    let mut total_seen = 0_usize;
    // (depth before the entry's own tag was pushed, start byte offset, name)
    let mut pending: Option<(usize, usize, String)> = None;
    let end_truncated;
    let window_end = offset.saturating_add(limit);

    loop {
        let pos_before = reader.buffer_position() as usize;
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(error) => {
                if saw_root {
                    end_truncated = true;
                    break;
                }
                return Err(PanosMcpError::Xml(error.to_string()));
            }
        };
        match event {
            Event::DocType(_) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Event::Start(element) => {
                if stack.len() >= MAX_SCAN_DEPTH {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {MAX_SCAN_DEPTH}-level limit"
                    )));
                }
                let name = element.name().as_ref().as_bytes().to_vec();
                if !saw_root {
                    if name != b"response" {
                        return Err(PanosMcpError::Xml(
                            "root element must be 'response'".to_owned(),
                        ));
                    }
                    saw_root = true;
                    read_status_and_code(&element, &mut status, &mut code)?;
                } else if pending.is_none() && name == b"entry" && stack.len() >= min_depth {
                    let entry_name = read_name_attribute(&element)?;
                    pending = Some((stack.len(), pos_before, entry_name));
                }
                stack.push(name);
            }
            Event::Empty(element) => {
                if stack.len() >= MAX_SCAN_DEPTH {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {MAX_SCAN_DEPTH}-level limit"
                    )));
                }
                let name = element.name().as_ref().as_bytes().to_vec();
                if !saw_root {
                    if name != b"response" {
                        return Err(PanosMcpError::Xml(
                            "root element must be 'response'".to_owned(),
                        ));
                    }
                    saw_root = true;
                    root_closed = true;
                    read_status_and_code(&element, &mut status, &mut code)?;
                } else if pending.is_none() && name == b"entry" && stack.len() >= min_depth {
                    let index = total_seen;
                    total_seen += 1;
                    if index >= offset && index < window_end {
                        let entry_name = read_name_attribute(&element)?;
                        let end = reader.buffer_position() as usize;
                        entries.push(owned_entry(raw, pos_before, end, entry_name)?);
                    }
                }
            }
            Event::End(element) => {
                let name = element.name().as_ref().as_bytes().to_vec();
                match stack.pop() {
                    Some(open) if open == name => {}
                    _ => {
                        return Err(PanosMcpError::Xml(
                            "input contains a mismatched closing element".to_owned(),
                        ));
                    }
                }
                if let Some((depth, start, entry_name)) = &pending
                    && stack.len() == *depth
                    && name == b"entry"
                {
                    let index = total_seen;
                    total_seen += 1;
                    if index >= offset && index < window_end {
                        let end = reader.buffer_position() as usize;
                        entries.push(owned_entry(raw, *start, end, entry_name.clone())?);
                    }
                    pending = None;
                }
                if saw_root && stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::Eof => {
                end_truncated = !root_closed;
                break;
            }
            _ => {}
        }
    }

    let code = code
        .as_deref()
        .map(str::parse::<i32>)
        .transpose()
        .map_err(|_| PanosMcpError::Xml("response code is not an integer".to_owned()))?;

    Ok(EntryScanResult {
        status: status.unwrap_or_default(),
        code,
        entries,
        total_seen,
        truncated: end_truncated || pending.is_some(),
    })
}

fn owned_entry(raw: &[u8], start: usize, end: usize, name: String) -> Result<ConfigEntry> {
    let xml = std::str::from_utf8(&raw[start..end])
        .map_err(|_| PanosMcpError::Xml("entry is not valid UTF-8".to_owned()))?
        .to_owned();
    let digest = format!("sha256:{}", hex_digest(&Sha256::digest(xml.as_bytes())));
    Ok(ConfigEntry { name, xml, digest })
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn read_name_attribute(element: &quick_xml::events::BytesStart<'_>) -> Result<String> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
        if attribute.key.as_ref() == "name" {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| PanosMcpError::Xml(error.to_string()))?
                .into_owned();
            return Ok(value);
        }
    }
    Ok(String::new())
}

fn read_status_and_code(
    element: &quick_xml::events::BytesStart<'_>,
    status: &mut Option<String>,
    code: &mut Option<String>,
) -> Result<()> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| PanosMcpError::Xml(error.to_string()))?
            .into_owned();
        match attribute.key.as_ref() {
            "status" => *status = Some(value),
            "code" => *code = Some(value),
            _ => {}
        }
    }
    Ok(())
}

/// Terminal and intermediate state from a PAN-OS asynchronous job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct JobStatus {
    /// PAN-OS job state, such as `PEND`, `ACT`, or `FIN`.
    pub status: Option<String>,
    /// Final result, such as `OK` or `FAIL`.
    pub result: Option<String>,
    /// Integer completion percentage when supplied.
    pub progress: Option<u8>,
    /// Bounded details from the job response.
    pub details: Option<String>,
}

impl JobStatus {
    /// Whether the job reached the documented terminal `FIN` state.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.status.as_deref() == Some("FIN")
    }

    /// Whether a terminal job reports success.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.is_finished() && self.result.as_deref() == Some("OK")
    }
}

/// `show high-availability state` result.
///
/// Fields are `None` on a standalone (non-HA) device, where PAN-OS omits the
/// `<group>` element entirely -- absence is a valid, common answer, not a
/// parse failure.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct HaState {
    /// Whether HA is configured on this device (`yes`/`no`).
    pub enabled: Option<String>,
    /// Configured HA mode, e.g. `Active-Passive`.
    pub mode: Option<String>,
    /// This device's own HA state, e.g. `active`, `passive`, `suspended`.
    pub local_state: Option<String>,
    /// The peer's last-known HA state.
    pub peer_state: Option<String>,
}

/// One `<entry>` under `request license info`'s `<licenses>` container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct LicenseEntry {
    /// Licensed feature name.
    pub feature: Option<String>,
    /// Human-readable feature description.
    pub description: Option<String>,
    /// Serial the license is issued to.
    pub serial: Option<String>,
    /// Issue date, as reported by PAN-OS.
    pub issued: Option<String>,
    /// Expiration date, or `Never`.
    pub expires: Option<String>,
    /// Whether the license has expired (`yes`/`no`).
    pub expired: Option<String>,
}

/// One `<entry>` under `request content upgrade info`'s content-version list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ContentVersionEntry {
    /// Content release version string.
    pub version: Option<String>,
    /// Content package filename.
    pub filename: Option<String>,
    /// Release date, as reported by PAN-OS.
    pub released_on: Option<String>,
    /// Whether this version is downloaded to the device (`yes`/`no`).
    pub downloaded: Option<String>,
    /// Whether this version is the one currently installed (`yes`/`no`).
    pub current: Option<String>,
}

/// One `<entry>` under `request system software info`'s version list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SoftwareVersionEntry {
    /// PAN-OS release version string.
    pub version: Option<String>,
    /// Release package filename.
    pub filename: Option<String>,
    /// Release date, as reported by PAN-OS.
    pub released_on: Option<String>,
    /// Whether this version is downloaded to the device (`yes`/`no`).
    pub downloaded: Option<String>,
    /// Whether this version is the one currently running (`yes`/`no`).
    pub current: Option<String>,
    /// Whether this is the latest version PAN-OS knows about (`yes`/`no`).
    pub latest: Option<String>,
}

/// Validate XML structure and return top-level PAN-OS response attributes.
///
/// DTD declarations are rejected, raw input and depth are bounded, and the
/// root element must be `response`. Entity expansion is therefore never
/// enabled by this parser.
pub fn validate_panos_response(input: &[u8], limits: XmlLimits) -> Result<EnvelopeSummary> {
    validate_xml_root(input, limits, b"response", "panos_xml_response")
}

/// Parse a validated PAN-OS response envelope.
pub fn parse_panos_response(input: &[u8], limits: XmlLimits) -> Result<PanosResponse> {
    let summary = validate_panos_response(input, limits)?;
    let xml = std::str::from_utf8(input)
        .map_err(|_| PanosMcpError::Xml("response is not valid UTF-8".to_owned()))?
        .to_owned();
    let code = summary
        .code
        .as_deref()
        .map(str::parse::<i32>)
        .transpose()
        .map_err(|_| PanosMcpError::Xml("response code is not an integer".to_owned()))?;
    let message = collect_text_for_elements(input, &[b"msg", b"line"], 1024)?;
    Ok(PanosResponse {
        status: summary.status.unwrap_or_default(),
        code,
        message,
        xml,
    })
}

/// Validate a caller-supplied, read-only operational command.
///
/// Only a single `<show>...</show>` command is accepted. PAN-OS operational
/// mutations use other roots and are intentionally outside Phase 1.
pub fn validate_read_only_op_command(input: &str) -> Result<()> {
    validate_xml_root(
        input.as_bytes(),
        XmlLimits {
            max_bytes: MAX_OP_COMMAND_BYTES,
            max_depth: 32,
        },
        b"show",
        "command",
    )?;
    let mut reader = Reader::from_reader(input.as_bytes());
    loop {
        match reader.read_event() {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                if element.attributes().next().is_some() {
                    return Err(PanosMcpError::Policy {
                        field: "command",
                        reason: "attributes on the show root are not permitted".to_owned(),
                    });
                }
                break;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    Ok(())
}

/// Convert a `<show>...</show>` operational command into a whitespace-joined
/// element tag path suitable for allowlist token-prefix matching, e.g.
/// `<show><system><info/></system></show>` becomes `"show system info"`.
///
/// Call only after [`validate_read_only_op_command`] has confirmed the input
/// is well-formed XML, within size/depth limits, rooted at an attribute-free
/// `<show>` element. Element attributes and leaf text content are dropped --
/// the allowlist governs which command *shape* may run, matching how the
/// PAN-OS CLI's own free-form allowlist entries (e.g. `show system info`)
/// are written, not the literal argument values ultimately sent to PAN-OS.
pub fn op_command_tag_path(input: &str) -> Result<String> {
    let mut reader = Reader::from_reader(input.as_bytes());
    reader.config_mut().trim_text(true);
    let mut tags: Vec<String> = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element) | Event::Empty(element)) => {
                let qname = element.name();
                let name = std::str::from_utf8(qname.as_ref().as_bytes())
                    .map_err(|_| PanosMcpError::Xml("non-UTF-8 element name".to_owned()))?;
                tags.push(name.to_owned());
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    Ok(tags.join(" "))
}

/// Validate the deliberately small read-only XPath subset accepted in Phase 1.
pub fn validate_read_xpath(xpath: &str) -> Result<()> {
    if xpath.is_empty() {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "value is empty".to_owned(),
        });
    }
    if xpath.len() > MAX_XPATH_BYTES {
        return Err(PanosMcpError::InputTooLarge {
            field: "xpath",
            limit: MAX_XPATH_BYTES,
        });
    }
    if xpath != "/config" && !xpath.starts_with("/config/") {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "path must be rooted at /config".to_owned(),
        });
    }
    if xpath.contains("//") || xpath.contains("..") {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "descendant and parent traversal are forbidden".to_owned(),
        });
    }
    if xpath.bytes().any(|byte| {
        !byte.is_ascii()
            || !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'-' | b'_' | b'.' | b':' | b'[' | b']' | b'@' | b'=' | b'\'' | b'"'
                ))
    }) {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "value contains unsupported XPath syntax".to_owned(),
        });
    }
    if xpath.matches('/').count() > 64 {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "path exceeds the 64-segment limit".to_owned(),
        });
    }

    let mut brackets = 0_u8;
    let mut quote = None;
    for byte in xpath.bytes() {
        match (quote, byte) {
            (Some(open), current) if current == open => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'[') => {
                brackets = brackets
                    .checked_add(1)
                    .ok_or_else(|| PanosMcpError::Policy {
                        field: "xpath",
                        reason: "predicate nesting is invalid".to_owned(),
                    })?;
                if brackets > 1 {
                    return Err(PanosMcpError::Policy {
                        field: "xpath",
                        reason: "nested predicates are forbidden".to_owned(),
                    });
                }
            }
            (None, b']') => {
                brackets = brackets
                    .checked_sub(1)
                    .ok_or_else(|| PanosMcpError::Policy {
                        field: "xpath",
                        reason: "predicate brackets are unbalanced".to_owned(),
                    })?;
            }
            _ => {}
        }
    }
    if brackets != 0 || quote.is_some() {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "quotes or predicate brackets are unbalanced".to_owned(),
        });
    }
    // The character allowlist above permits `:` (for `[@attr=...]`-adjacent
    // syntax) and lets brackets balance in pairs, which is not tight enough
    // to reject XPath axis steps (`parent::`, `ancestor::`, ...) or
    // predicates that are not a single attribute equality. Both pass the
    // checks above as plain text while addressing a different node once an
    // XPath engine evaluates them -- shared with `validate_write_xpath` and
    // `MutationGrant::allows_xpath` so none of the three can disagree about
    // what an xpath addresses (MEC-528 F1).
    if !rust_panosmcp_auth::is_strict_xpath_shape(xpath) {
        return Err(PanosMcpError::Policy {
            field: "xpath",
            reason: "value contains unsupported XPath syntax".to_owned(),
        });
    }
    Ok(())
}

/// Validate one bounded XML element supplied to a candidate set action.
pub fn validate_config_element(element: &str) -> Result<()> {
    if element.is_empty() {
        return Err(PanosMcpError::Policy {
            field: "element",
            reason: "value is empty".to_owned(),
        });
    }
    if element.len() > MAX_CONFIG_ELEMENT_BYTES {
        return Err(PanosMcpError::InputTooLarge {
            field: "element",
            limit: MAX_CONFIG_ELEMENT_BYTES,
        });
    }
    let mut reader = Reader::from_reader(element.as_bytes());
    let root = loop {
        match reader.read_event() {
            Ok(Event::Start(node) | Event::Empty(node)) => {
                break node.name().as_ref().as_bytes().to_vec();
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => {
                return Err(PanosMcpError::Xml(
                    "element contains no root node".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    };
    validate_xml_root(
        element.as_bytes(),
        XmlLimits {
            max_bytes: MAX_CONFIG_ELEMENT_BYTES,
            max_depth: 32,
        },
        &root,
        "element",
    )?;
    Ok(())
}

/// Enforce that a mutation XPath is inside one explicit operator-controlled root.
pub fn validate_write_xpath(xpath: &str, allowed_roots: &[String]) -> Result<()> {
    validate_read_xpath(xpath)?;
    // Canonicalise quote style on both sides before comparing. The same helper
    // backs the token grant check, so the two layers cannot disagree about
    // whether `[@name='x']` and `[@name="x"]` are the same path — which is
    // exactly what made LXC 608 unable to perform any mutation at all
    // (rustpanosmcp#82).
    let candidate = rust_panosmcp_auth::canonicalize_xpath_quotes(xpath);
    if allowed_roots.iter().any(|root| {
        let root = rust_panosmcp_auth::canonicalize_xpath_quotes(root);
        candidate == root
            || candidate
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }) {
        return Ok(());
    }
    Err(PanosMcpError::Policy {
        field: "xpath",
        reason: "path is outside every operator-configured mutation root".to_owned(),
    })
}

/// Extract and validate the numeric job identifier returned by an async request.
pub fn parse_job_id(response: &PanosResponse) -> Result<String> {
    let value = first_element_text(response.xml.as_bytes(), b"job")?
        .ok_or_else(|| PanosMcpError::Xml("response contains no job identifier".to_owned()))?;
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PanosMcpError::Xml(
            "response job identifier is not 1-32 ASCII digits".to_owned(),
        ));
    }
    Ok(value)
}

/// Extract the `yes`/`no` answer from a `check pending-changes` response.
///
/// PAN-OS documents exactly these two values for `<result>`; anything else
/// (a different word, a nested element, an empty result) is treated as an
/// unrecognized response rather than guessed at, since a wrong guess here
/// would let an operation proceed against a dirty candidate.
pub(crate) fn parse_pending_changes(response: &PanosResponse) -> Result<bool> {
    match first_element_text(response.xml.as_bytes(), b"result")?.as_deref() {
        Some("yes") => Ok(true),
        Some("no") => Ok(false),
        other => Err(PanosMcpError::Xml(format!(
            "check pending-changes returned an unrecognized result: {other:?}"
        ))),
    }
}

/// Extract common facts from a successful `show system info` response.
pub fn parse_device_facts(response: &PanosResponse) -> Result<DeviceFacts> {
    let input = response.xml.as_bytes();
    Ok(DeviceFacts {
        hostname: first_element_text(input, b"hostname")?,
        management_ip: first_element_text(input, b"ip-address")?,
        model: first_element_text(input, b"model")?,
        serial: first_element_text(input, b"serial")?,
        software_version: first_element_text(input, b"sw-version")?,
        app_version: first_element_text(input, b"app-version")?,
        threat_version: first_element_text(input, b"threat-version")?,
        uptime: first_element_text(input, b"uptime")?,
        family: first_element_text(input, b"family")?,
    })
}

/// Extract a PAN-OS job state from a successful job response.
pub fn parse_job_status(response: &PanosResponse) -> Result<JobStatus> {
    let input = response.xml.as_bytes();
    let progress = first_child_text(input, b"job", b"progress")?
        .map(|value| value.parse::<u8>())
        .transpose()
        .map_err(|_| PanosMcpError::Xml("job progress is not an integer".to_owned()))?;
    Ok(JobStatus {
        status: first_child_text(input, b"job", b"status")?,
        result: first_child_text(input, b"job", b"result")?,
        progress,
        // PAN-OS's own `<job><details>` text can embed the offending
        // config fragment for a validation/commit failure (a duplicate
        // object error naming its `pre-shared-key`, for example), so it is
        // redacted the same as any other device-sourced text before it
        // becomes part of a tool result (mecmcp-redact::redact_text).
        details: first_child_text(input, b"job", b"details")?
            .map(|details| mecmcp_redact::redact_text(&details)),
    })
}

/// Extract `show high-availability state` fields from a successful response.
///
/// `local-info`/`peer-info`/`group` are read by scanning for a match
/// anywhere in the document rather than requiring exact depth, so this
/// degrades to all-`None` on a standalone device's response instead of
/// failing -- HA is optional per device, not an error case.
pub fn parse_ha_state(response: &PanosResponse) -> Result<HaState> {
    let input = response.xml.as_bytes();
    Ok(HaState {
        enabled: first_element_text(input, b"enabled")?,
        mode: first_child_text(input, b"group", b"mode")?,
        local_state: first_child_text(input, b"local-info", b"state")?,
        peer_state: first_child_text(input, b"peer-info", b"state")?,
    })
}

/// Depth, in tag-name-stack entries, at which `<licenses>` and
/// `<content-updates>` list their `<entry>` children directly below
/// `<result>`: `response`/`result`/`container`/`entry`.
const LICENSE_CONTENT_ENTRY_DEPTH: usize = 3;
/// Depth for `request system software info`, which nests its version list
/// one level deeper than license/content: `response`/`result`/`sw-updates`/
/// `versions`/`entry`.
const SOFTWARE_ENTRY_DEPTH: usize = 4;
/// Depth for a `type=log&action=get` result's entries: `response`/`result`/
/// `log`/`logs`/`entry`.
const LOG_ENTRY_DEPTH: usize = 4;

/// Parse every `<entry>` in a successful `request license info` response.
///
/// Reuses [`scan_config_entries`] for the same bounded, tolerant-of-a-cut-
/// response scan every other list reader gets, then extracts named fields
/// from each entry's own self-contained XML slice.
pub fn parse_license_entries(response: &PanosResponse) -> Result<Vec<LicenseEntry>> {
    let raw = response.xml.as_bytes();
    let scan = scan_config_entries(raw, 0, usize::MAX, LICENSE_CONTENT_ENTRY_DEPTH)?;
    scan.entries
        .iter()
        .map(|entry| {
            let xml = entry.xml.as_bytes();
            Ok(LicenseEntry {
                feature: first_element_text(xml, b"feature")?,
                description: first_element_text(xml, b"description")?,
                serial: first_element_text(xml, b"serial")?,
                issued: first_element_text(xml, b"issued")?,
                expires: first_element_text(xml, b"expires")?,
                expired: first_element_text(xml, b"expired")?,
            })
        })
        .collect()
}

/// Parse every `<entry>` in a successful `request content upgrade info` response.
pub fn parse_content_entries(response: &PanosResponse) -> Result<Vec<ContentVersionEntry>> {
    let raw = response.xml.as_bytes();
    let scan = scan_config_entries(raw, 0, usize::MAX, LICENSE_CONTENT_ENTRY_DEPTH)?;
    scan.entries
        .iter()
        .map(|entry| {
            let xml = entry.xml.as_bytes();
            Ok(ContentVersionEntry {
                version: first_element_text(xml, b"version")?,
                filename: first_element_text(xml, b"filename")?,
                released_on: first_element_text(xml, b"released-on")?,
                downloaded: first_element_text(xml, b"downloaded")?,
                current: first_element_text(xml, b"current")?,
            })
        })
        .collect()
}

/// Parse every `<entry>` in a successful `request system software info` response.
pub fn parse_software_entries(response: &PanosResponse) -> Result<Vec<SoftwareVersionEntry>> {
    let raw = response.xml.as_bytes();
    let scan = scan_config_entries(raw, 0, usize::MAX, SOFTWARE_ENTRY_DEPTH)?;
    scan.entries
        .iter()
        .map(|entry| {
            let xml = entry.xml.as_bytes();
            Ok(SoftwareVersionEntry {
                version: first_element_text(xml, b"version")?,
                filename: first_element_text(xml, b"filename")?,
                released_on: first_element_text(xml, b"released-on")?,
                downloaded: first_element_text(xml, b"downloaded")?,
                current: first_element_text(xml, b"current")?,
                latest: first_element_text(xml, b"latest")?,
            })
        })
        .collect()
}

/// Parse the matched-rule entries from a `test security-policy-match`
/// response.
///
/// PAN-OS returns zero or more `<rules><entry name="...">...</entry></rules>`
/// children under `<result>`; an empty list is a valid "no rule matched"
/// answer, not an error, matching how PAN-OS documents this command.
pub fn parse_security_policy_match(response: &PanosResponse) -> Result<Vec<ConfigEntry>> {
    let raw = response.xml.as_bytes();
    let scan = scan_config_entries(raw, 0, usize::MAX, LICENSE_CONTENT_ENTRY_DEPTH)?;
    Ok(scan.entries)
}

/// Extract the first occurrence of `tag`'s text from an already-captured
/// entry's exact source XML (e.g. a [`ConfigEntry::xml`] slice).
///
/// Exposed so a caller with a single matched entry in hand -- such as
/// `test_panos_security_policy_match` reading a rule's `<action>` -- does
/// not need its own XML reader just to pull one field back out of text this
/// module already parsed once.
pub fn extract_element_text(xml: &str, tag: &str) -> Result<Option<String>> {
    first_element_text(xml.as_bytes(), tag.as_bytes())
}

/// Whether a polled `type=log&action=get` response reports a terminal job.
///
/// A log job's state is nested under `<result><job><status>FIN</status>...`,
/// the same shape a config/commit job uses -- but this scans for `<status>`
/// anywhere in the document rather than requiring that exact nesting under
/// `<job>`, both because the response has not been verified against a live
/// device and because [`parse_job_status`] is `<job>`-status typed
/// (`JobStatus`) while a log job's terminal payload also carries the log
/// entries this function has no reason to parse.
pub fn log_job_is_finished(response: &PanosResponse) -> Result<bool> {
    let input = response.xml.as_bytes();
    Ok(first_element_text(input, b"status")?.as_deref() == Some("FIN"))
}

/// Parse the bounded set of log entries from a finished log job's response.
pub fn parse_log_entries(response: &PanosResponse) -> Result<Vec<ConfigEntry>> {
    let raw = response.xml.as_bytes();
    let scan = scan_config_entries(raw, 0, usize::MAX, LOG_ENTRY_DEPTH)?;
    Ok(scan.entries)
}

/// Validate a caller-supplied PAN-OS asynchronous job identifier.
pub fn validate_job_id(job_id: &str) -> Result<()> {
    if job_id.is_empty()
        || job_id.len() > MAX_JOB_ID_BYTES
        || !job_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PanosMcpError::Policy {
            field: "job_id",
            reason: format!("job identifier must contain only 1-{MAX_JOB_ID_BYTES} ASCII digits"),
        });
    }
    Ok(())
}

/// One Panorama device-group and the serials of its member firewalls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DeviceGroupSummary {
    /// Device-group name.
    pub name: String,
    /// Serial numbers of firewalls assigned to this device-group.
    pub member_serials: Vec<String>,
}

/// One Panorama template and the names of its declared variables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct TemplateSummary {
    /// Template name.
    pub name: String,
    /// Names of variables declared on this template.
    pub variables: Vec<String>,
}

/// Per-device result inside a Panorama push (`CommitAll`) job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct PushDeviceStatus {
    /// Target firewall serial number.
    pub serial: String,
    /// Firewall name, when PAN-OS reports one.
    pub device_name: Option<String>,
    /// Per-device job state, such as `PEND`, `ACT`, or `FIN`.
    pub status: Option<String>,
    /// Per-device terminal result, such as `OK` or `FAIL`.
    pub result: Option<String>,
    /// Integer completion percentage when supplied.
    pub progress: Option<u8>,
    /// Bounded per-device details.
    pub details: Option<String>,
}

/// Overall and per-device state of a Panorama push job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct PushJobStatus {
    /// Overall push job state.
    pub job: JobStatus,
    /// Per-target-firewall push results, in document order.
    pub devices: Vec<PushDeviceStatus>,
}

/// Parse `<show><devicegroups></devicegroups></show>` operational output into
/// structured summaries.
///
/// Panorama's device-group op output already nests each group's connected
/// firewall serials under a `devices` container exactly like the config-tree
/// fetch does (`<devicegroups><entry name="DG"><devices><entry name="serial"
/// .../></devices></entry></devicegroups>`), so this alone answers
/// `list_panorama_device_groups`: no per-group config `get` is needed, and
/// the rulebases/address objects/etc. nested under the config equivalent
/// structurally cannot appear in an operational response (MEC-759).
pub fn parse_panorama_device_groups_op(
    response: &PanosResponse,
) -> Result<Vec<DeviceGroupSummary>> {
    let entries = parse_grouped_entries(response.xml.as_bytes(), b"devicegroups", b"devices")?;
    Ok(entries
        .into_iter()
        .map(|entry| DeviceGroupSummary {
            name: entry.name,
            member_serials: entry.members,
        })
        .collect())
}

/// Parse `<show><templates></templates></show>` operational output for
/// template *names* only.
///
/// Unlike device groups, Panorama's template op output reports per-target-
/// firewall commit/connection history, not the template's declared
/// variables -- those live only in the config tree, so `list_panorama_templates`
/// pairs this with a per-template `/variable` config read (see
/// `crate::tools::PanosService::list_panorama_templates`, MEC-759).
pub fn parse_panorama_templates_op(response: &PanosResponse) -> Result<Vec<String>> {
    let entries = list_child_entries(response.xml.as_bytes(), b"templates")?;
    Ok(entries
        .into_iter()
        .map(|entry| entry.name_attr.unwrap_or_default())
        .collect())
}

/// Parse a `show jobs id <id>` response for a Panorama push (`CommitAll`) job,
/// including the per-target-firewall `<devices>` breakdown PAN-OS nests inside it.
pub fn parse_push_job_status(response: &PanosResponse) -> Result<PushJobStatus> {
    let job = parse_job_status(response)?;
    let devices = parse_push_devices(response.xml.as_bytes())?;
    Ok(PushJobStatus { job, devices })
}

/// One `<parent><entry name="...">...<nested_container><entry name="..."/>...</nested_container></entry></parent>`
/// grouping, reduced to the outer name and the inner entries' names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GroupedEntries {
    name: String,
    members: Vec<String>,
}

/// Whether the tail of `stack` equals `tail`, element for element.
fn stack_ends_with(stack: &[Vec<u8>], tail: &[&[u8]]) -> bool {
    if stack.len() < tail.len() {
        return false;
    }
    stack[stack.len() - tail.len()..]
        .iter()
        .zip(tail)
        .all(|(actual, expected)| actual.as_slice() == *expected)
}

/// The `name` attribute of an XML start/empty element, bounded and validated.
fn entry_name_attribute(element: &quick_xml::events::BytesStart<'_>) -> Result<Option<String>> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
        if attribute.key.as_ref() == "name" {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| PanosMcpError::Xml(error.to_string()))?
                .into_owned();
            if value.len() > MAX_ENTRY_NAME_BYTES {
                return Err(PanosMcpError::Xml(format!(
                    "entry name attribute exceeds {MAX_ENTRY_NAME_BYTES} bytes"
                )));
            }
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// Record a `<entry>` open (`Start` or `Empty`) against the two shapes this
/// parser understands: a top-level entry directly under `list_element`, or a
/// nested member entry under `list_element/entry/nested_container`.
fn record_entry_open(
    stack: &[Vec<u8>],
    element: &quick_xml::events::BytesStart<'_>,
    list_element: &[u8],
    nested_container: &[u8],
    results: &mut Vec<GroupedEntries>,
) -> Result<()> {
    if element.name().as_ref().as_bytes() != b"entry" {
        return Ok(());
    }
    if stack_ends_with(stack, &[list_element]) {
        if results.len() >= MAX_LIST_ENTRIES {
            return Err(PanosMcpError::Xml(format!(
                "response contains more than {MAX_LIST_ENTRIES} entries"
            )));
        }
        results.push(GroupedEntries {
            name: entry_name_attribute(element)?.unwrap_or_default(),
            members: Vec::new(),
        });
    } else if stack_ends_with(stack, &[list_element, b"entry", nested_container])
        && let Some(current) = results.last_mut()
    {
        if current.members.len() >= MAX_MEMBERS_PER_ENTRY {
            return Err(PanosMcpError::Xml(format!(
                "entry '{}' contains more than {MAX_MEMBERS_PER_ENTRY} members",
                current.name
            )));
        }
        current
            .members
            .push(entry_name_attribute(element)?.unwrap_or_default());
    }
    Ok(())
}

/// Parse `<list_element><entry name="X"><nested_container><entry name="Y"/>...
/// </nested_container></entry>...</list_element>` groupings anywhere in the
/// document, keyed by ancestor path rather than absolute position -- the
/// caller already scoped the request to one XPath, so the shape is exact.
fn parse_grouped_entries(
    input: &[u8],
    list_element: &[u8],
    nested_container: &[u8],
) -> Result<Vec<GroupedEntries>> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut results: Vec<GroupedEntries> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                record_entry_open(
                    &stack,
                    &element,
                    list_element,
                    nested_container,
                    &mut results,
                )?;
                stack.push(element.name().as_ref().as_bytes().to_vec());
            }
            Ok(Event::Empty(element)) => {
                record_entry_open(
                    &stack,
                    &element,
                    list_element,
                    nested_container,
                    &mut results,
                )?;
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    Ok(results)
}

/// Parse the `<job><devices><entry><serial-no>...</serial-no>...</entry></devices></job>`
/// per-target-firewall breakdown PAN-OS attaches to a push (`CommitAll`) job.
///
/// The serial is a `<serial-no>` *child* element, not a `name` attribute on
/// `<entry>` -- pan-os-python's own job-result parser
/// (`panos/base.py::_parse_job_results`) reads `device["serial-no"]`, and a
/// live Panorama response was not available to double-check this locally.
/// Falling back to the `name` attribute (which some other PAN-OS list
/// responses do use) covers the case where a future PAN-OS version reports it
/// that way instead; refusing when neither is present, rather than defaulting
/// to an empty serial, keeps a per-device result readable instead of blank.
fn parse_push_devices(input: &[u8]) -> Result<Vec<PushDeviceStatus>> {
    // Unlike a device-group/template's `<entry><container><entry/></container></entry>`
    // nesting, `<devices>` entries under a job are the container's *direct*
    // children -- there is no extra wrapper level to skip.
    let entries = list_child_entries(input, b"devices")?;
    // Each device entry's serial/devicename/status/result/progress/details
    // live as its own direct children. Read them with `first_child_text`
    // (depth-aware) rather than `first_element_text`, which is not depth-aware
    // and would take a `<status>`/`<result>` nested inside `<details>` as the
    // device's own value.
    let mut devices = Vec::with_capacity(entries.len());
    for entry in entries {
        let slice = entry.xml.as_slice();
        let serial = first_child_text(slice, b"entry", b"serial-no")?
            .filter(|value| !value.is_empty())
            .or(entry.name_attr)
            .ok_or_else(|| {
                PanosMcpError::Xml(
                    "push device entry has neither a 'serial-no' child nor a 'name' attribute"
                        .to_owned(),
                )
            })?;
        let progress = first_child_text(slice, b"entry", b"progress")?
            .map(|value| value.parse::<u8>())
            .transpose()
            .map_err(|_| PanosMcpError::Xml("push device progress is not an integer".to_owned()))?;
        devices.push(PushDeviceStatus {
            serial,
            device_name: first_child_text(slice, b"entry", b"devicename")?,
            status: first_child_text(slice, b"entry", b"status")?,
            result: first_child_text(slice, b"entry", b"result")?,
            progress,
            // Same text class as `parse_job_status`'s `<job><details>` above:
            // PAN-OS's per-device push `<details>` can also quote the
            // offending config fragment for that device's own commit/push
            // failure, so it gets the same redaction pass before reaching a
            // tool result.
            details: first_child_text(slice, b"entry", b"details")?
                .map(|details| mecmcp_redact::redact_text(&details)),
        });
    }
    Ok(devices)
}

/// One `<entry>` that is a direct child of some container, with its raw XML
/// (for parsing its own children) and its `name` attribute, if any.
struct ChildEntry {
    name_attr: Option<String>,
    xml: Vec<u8>,
}

/// Return every `<entry>` that is a direct child of `parent`, in document
/// order. Unlike this function's predecessor, which looked entries up by
/// `name` attribute, this returns entries regardless of whether they have
/// one -- keying by `name` broke on duplicate or absent names, exactly the
/// shape a push job's `<devices>` entries have.
fn list_child_entries(input: &[u8], parent: &[u8]) -> Result<Vec<ChildEntry>> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut entries: Vec<ChildEntry> = Vec::new();
    let mut entry_depth: Option<usize> = None;
    let mut start = 0_u64;
    let mut pending_name: Option<String> = None;

    loop {
        let position_before = reader.buffer_position();
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = element.name().as_ref().as_bytes().to_vec();
                if entry_depth.is_none() && name == b"entry" && stack_ends_with(&stack, &[parent]) {
                    if entries.len() >= MAX_LIST_ENTRIES {
                        return Err(PanosMcpError::Xml(format!(
                            "response contains more than {MAX_LIST_ENTRIES} entries"
                        )));
                    }
                    pending_name = entry_name_attribute(&element)?;
                    start = position_before;
                    stack.push(name);
                    entry_depth = Some(stack.len());
                    continue;
                }
                stack.push(name);
            }
            Ok(Event::Empty(element)) => {
                if entry_depth.is_none()
                    && element.name().as_ref().as_bytes() == b"entry"
                    && stack_ends_with(&stack, &[parent])
                {
                    if entries.len() >= MAX_LIST_ENTRIES {
                        return Err(PanosMcpError::Xml(format!(
                            "response contains more than {MAX_LIST_ENTRIES} entries"
                        )));
                    }
                    let end = reader.buffer_position();
                    entries.push(ChildEntry {
                        name_attr: entry_name_attribute(&element)?,
                        xml: input[position_before as usize..end as usize].to_vec(),
                    });
                }
            }
            Ok(Event::End(_)) => {
                if entry_depth == Some(stack.len()) {
                    let end = reader.buffer_position();
                    entries.push(ChildEntry {
                        name_attr: pending_name.take(),
                        xml: input[start as usize..end as usize].to_vec(),
                    });
                    entry_depth = None;
                }
                stack.pop();
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    Ok(entries)
}

/// Stable name for the documented PAN-OS XML API response code.
#[must_use]
pub const fn panos_api_code_name(code: i32) -> &'static str {
    match code {
        1 => "unknown-command",
        2..=5 | 11 | 21 => "internal-error",
        6 => "bad-xpath",
        7 => "object-not-present",
        8 => "object-not-unique",
        10 => "reference-count-not-zero",
        12 => "invalid-object",
        13 => "object-not-found",
        14 => "operation-not-possible",
        15 => "operation-denied",
        16 => "unauthorized",
        17 => "invalid-command",
        18 => "malformed-command",
        19 => "success",
        20 => "success-command-completed",
        22 => "session-timed-out",
        _ => "unknown",
    }
}

fn validate_xml_root(
    input: &[u8],
    limits: XmlLimits,
    expected_root: &[u8],
    input_field: &'static str,
) -> Result<EnvelopeSummary> {
    if input.len() > limits.max_bytes {
        return Err(PanosMcpError::InputTooLarge {
            field: input_field,
            limit: limits.max_bytes,
        });
    }

    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut root_closed = false;
    let mut summary = EnvelopeSummary {
        status: None,
        code: None,
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                if root_closed {
                    return Err(PanosMcpError::Xml(
                        "input contains multiple root elements".to_owned(),
                    ));
                }
                depth = depth.saturating_add(1);
                if depth > limits.max_depth {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {}-level limit",
                        limits.max_depth
                    )));
                }
                if !saw_root {
                    if element.name().as_ref().as_bytes() != expected_root {
                        return Err(PanosMcpError::Xml(format!(
                            "root element must be '{}'",
                            String::from_utf8_lossy(expected_root)
                        )));
                    }
                    saw_root = true;
                    read_envelope_attributes(&reader, &element, &mut summary)?;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Err(PanosMcpError::Xml(
                        "input contains an unexpected closing element".to_owned(),
                    ));
                }
                depth -= 1;
                if saw_root && depth == 0 {
                    root_closed = true;
                }
            }
            Ok(Event::Empty(element)) => {
                if depth.saturating_add(1) > limits.max_depth {
                    return Err(PanosMcpError::Xml(format!(
                        "element depth exceeds the {}-level limit",
                        limits.max_depth
                    )));
                }
                if !saw_root {
                    if element.name().as_ref().as_bytes() != expected_root {
                        return Err(PanosMcpError::Xml(format!(
                            "root element must be '{}'",
                            String::from_utf8_lossy(expected_root)
                        )));
                    }
                    saw_root = true;
                    root_closed = true;
                    read_envelope_attributes(&reader, &element, &mut summary)?;
                } else if depth == 0 {
                    return Err(PanosMcpError::Xml(
                        "input contains multiple root elements".to_owned(),
                    ));
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Text(text))
                if depth == 0
                    && text
                        .as_bytes()
                        .iter()
                        .any(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r')) =>
            {
                return Err(PanosMcpError::Xml(
                    "non-whitespace text is forbidden outside the root element".to_owned(),
                ));
            }
            Ok(Event::CData(text)) if depth == 0 && !text.is_empty() => {
                return Err(PanosMcpError::Xml(
                    "CDATA is forbidden outside the root element".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    if !saw_root {
        return Err(PanosMcpError::Xml(
            "input contains no root element".to_owned(),
        ));
    }
    if depth != 0 || !root_closed {
        return Err(PanosMcpError::Xml(
            "input ended with unclosed elements".to_owned(),
        ));
    }
    Ok(summary)
}

fn read_envelope_attributes(
    _reader: &Reader<&[u8]>,
    element: &quick_xml::events::BytesStart<'_>,
    summary: &mut EnvelopeSummary,
) -> Result<()> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| PanosMcpError::Xml(error.to_string()))?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| PanosMcpError::Xml(error.to_string()))?
            .into_owned();
        if value.len() > MAX_ENVELOPE_ATTRIBUTE_BYTES {
            return Err(PanosMcpError::Xml(format!(
                "response envelope attribute exceeds {MAX_ENVELOPE_ATTRIBUTE_BYTES} bytes"
            )));
        }
        match attribute.key.as_ref() {
            "status" => summary.status = Some(value),
            "code" => summary.code = Some(value),
            _ => {}
        }
    }
    Ok(())
}

/// Trim only the four characters XML calls whitespace.
///
/// `str::trim` uses Unicode `White_Space`, which includes U+00A0 and friends.
/// Those are ordinary text in an XML document -- and one of them is what
/// `&#160;` resolves to, so trimming Unicode-wide would silently delete a
/// character reference this parser had just been careful to resolve. XML's
/// production is `#x20 | #x9 | #xD | #xA` and nothing else, which is also what
/// quick-xml's own `trim_text` applied before accumulation replaced it.
fn trim_xml_whitespace(value: &str) -> &str {
    value.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Append an entity reference's value to `out`.
///
/// Since quick-xml 0.38 an entity reference is its own `Event::GeneralRef`
/// rather than part of the surrounding `Event::Text`, so a reader that returns
/// on the first `Text` stops at the first `&` in a value. Accumulating across
/// both is what keeps `fw&amp;01` from reading back as `fw`.
///
/// Numeric character references and the five predefined entities resolve.
/// Anything else is preserved verbatim as `&name;`: this parser forbids
/// DOCTYPE, so a custom entity cannot have been defined, and there is nothing
/// to expand it to. Writing the reference back is lossless and invents
/// nothing, where dropping it silently is the failure this whole change is
/// about.
fn push_entity_ref(out: &mut String, entity: &quick_xml::events::BytesRef<'_>) -> Result<()> {
    let name: &str = entity;
    // A numeric reference is either resolvable or the document is malformed --
    // `&#xZZ;` and an out-of-range codepoint both land here. Preserving it
    // verbatim like an unknown named entity would put a literal `&#xZZ;` into a
    // hostname or a job status, which is neither the text nor an error.
    if name.starts_with('#') {
        let resolved = entity
            .resolve_char_ref()
            .map_err(|error| PanosMcpError::Xml(format!("invalid character reference: {error}")))?
            .ok_or_else(|| {
                PanosMcpError::Xml(format!("character reference &{name}; does not resolve"))
            })?;
        if !is_xml_char(resolved) {
            return Err(PanosMcpError::Xml(format!(
                "character reference &{name}; is U+{:04X}, which XML 1.0 forbids",
                resolved as u32
            )));
        }
        out.push(resolved);
        return Ok(());
    }
    // `resolve_xml_entity`, not `resolve_predefined_entity`. The latter is
    // `resolve_html5_entity` when quick-xml's `escape-html` feature is on, and
    // Cargo unifies features across the whole graph -- so an unrelated
    // dependency turning that on would silently start resolving `&nbsp;` to
    // U+00A0 here instead of preserving it, and this parser's output would
    // depend on something no PAN-OS response can see. The five predefined XML
    // entities are the whole set this format has.
    match quick_xml::escape::resolve_xml_entity(name) {
        Some(resolved) => out.push_str(resolved),
        // DOCTYPE is forbidden here, so a named entity cannot have been defined
        // and there is nothing to expand it to. Writing the reference back is
        // lossless and invents nothing.
        None => {
            out.push('&');
            out.push_str(name);
            out.push(';');
        }
    }
    Ok(())
}

/// Whether a codepoint is legal in an XML 1.0 document.
///
/// `Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`.
/// A numeric reference can name a codepoint outside this set -- `&#1;` is the
/// common one -- and accepting it puts a control character into an extracted
/// fact or an error message.
const fn is_xml_char(value: char) -> bool {
    matches!(value, '\u{9}' | '\u{A}' | '\u{D}'
        | '\u{20}'..='\u{D7FF}'
        | '\u{E000}'..='\u{FFFD}'
        | '\u{10000}'..='\u{10FFFF}')
}

/// Refuse an accumulating value once it passes the extraction bound.
///
/// Checked while accumulating rather than only at the end: a hostile document
/// can otherwise drive unbounded growth through many small text runs before
/// anything looks at the total.
fn guard_extracted_len(value: &str) -> Result<()> {
    if value.len() > MAX_EXTRACTED_TEXT_BYTES {
        return Err(PanosMcpError::Xml(format!(
            "extracted element text exceeds {MAX_EXTRACTED_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn first_element_text(input: &[u8], wanted: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::from_reader(input);
    // Raw, then trimmed once on return: per-run trimming would eat the
    // whitespace either side of an entity. See `collect_text_for_elements`.
    reader.config_mut().trim_text(false);
    let mut inside = false;
    // `None` until the element opens, so an element that is present but empty
    // is still distinguishable from one that never appeared.
    let mut collected: Option<String> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) if element.name().as_ref().as_bytes() == wanted => {
                inside = true;
                collected.get_or_insert_with(String::new);
            }
            // `<hostname/>` is `Event::Empty`, not Start+End. Without this the
            // element reads as absent while `<hostname></hostname>` reads as
            // present-and-empty, so two equivalent serializations of the same
            // document disagree.
            Ok(Event::Empty(element)) if element.name().as_ref().as_bytes() == wanted => {
                return Ok(Some(String::new()));
            }
            Ok(Event::Text(text)) if inside => {
                let value = collected.get_or_insert_with(String::new);
                value.push_str(&text);
                guard_extracted_len(value)?;
            }
            Ok(Event::CData(text)) if inside => {
                let value = collected.get_or_insert_with(String::new);
                value.push_str(&text);
                guard_extracted_len(value)?;
            }
            Ok(Event::GeneralRef(entity)) if inside => {
                let value = collected.get_or_insert_with(String::new);
                push_entity_ref(value, &entity)?;
                guard_extracted_len(value)?;
            }
            Ok(Event::End(element)) if element.name().as_ref().as_bytes() == wanted => {
                return Ok(collected.map(|value| trim_xml_whitespace(&value).to_owned()));
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => return Ok(None),
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
}

fn first_child_text(input: &[u8], parent: &[u8], wanted: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::from_reader(input);
    // Raw, then trimmed once on return: per-run trimming would eat the
    // whitespace either side of an entity. See `collect_text_for_elements`.
    reader.config_mut().trim_text(false);
    let mut parent_depth = None;
    let mut depth = 0_usize;
    let mut inside_wanted = false;
    // Pieces plus a running buffer, exactly as `collect_text_for_elements`
    // does, because the wanted element is not always leaf text. A PAN-OS job
    // `<details>` carries `<line>` children, and appending straight into one
    // buffer glued them together: `firstsecond`, one corrupted diagnostic where
    // there were two. `None` until the element opens keeps present-but-empty
    // distinguishable from absent.
    let mut pieces: Option<Vec<String>> = None;
    let mut current = String::new();
    let flush = |current: &mut String, pieces: &mut Option<Vec<String>>| {
        let piece = std::mem::take(current);
        let piece = trim_xml_whitespace(&piece);
        if !piece.is_empty() {
            pieces.get_or_insert_with(Vec::new).push(piece.to_owned());
        }
    };
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                depth += 1;
                if parent_depth.is_none() && element.name().as_ref().as_bytes() == parent {
                    parent_depth = Some(depth);
                } else if parent_depth.is_some_and(|value| depth == value + 1)
                    && element.name().as_ref().as_bytes() == wanted
                {
                    inside_wanted = true;
                    pieces.get_or_insert_with(Vec::new);
                } else if inside_wanted {
                    // A nested child opens: whatever preceded it is its own
                    // piece, not the same value continued.
                    flush(&mut current, &mut pieces);
                }
            }
            // As in `first_element_text`: a self-closing *wanted* child is
            // present and empty.
            Ok(Event::Empty(element))
                if !inside_wanted
                    && parent_depth.is_some_and(|value| depth + 1 == value + 1)
                    && element.name().as_ref().as_bytes() == wanted =>
            {
                return Ok(Some(String::new()));
            }
            // Any *other* self-closing element inside the wanted one is a
            // boundary, exactly like a Start or End would be. Matching only the
            // wanted name let `<details>first<line/>second</details>` keep both
            // runs in one buffer and come back as `firstsecond`.
            Ok(Event::Empty(_)) if inside_wanted => {
                flush(&mut current, &mut pieces);
            }
            Ok(Event::Text(text)) if inside_wanted => {
                current.push_str(&text);
                guard_extracted_len(&current)?;
            }
            Ok(Event::CData(text)) if inside_wanted => {
                current.push_str(&text);
                guard_extracted_len(&current)?;
            }
            Ok(Event::GeneralRef(entity)) if inside_wanted => {
                push_entity_ref(&mut current, &entity)?;
                guard_extracted_len(&current)?;
            }
            Ok(Event::End(element)) => {
                if inside_wanted && element.name().as_ref().as_bytes() == wanted {
                    flush(&mut current, &mut pieces);
                    // Bound the joined value, not only each piece. Per-piece
                    // checks let a hundred short `<line>` children add up well
                    // past the limit -- and `JobStatus::details` is contracted
                    // to be bounded, so the join is what has to be checked.
                    return match pieces.map(|pieces| pieces.join("; ")) {
                        Some(joined) => {
                            guard_extracted_len(&joined)?;
                            Ok(Some(joined))
                        }
                        None => Ok(None),
                    };
                }
                if inside_wanted {
                    // A nested child closes: same reason as its opening.
                    flush(&mut current, &mut pieces);
                }
                if parent_depth == Some(depth) && element.name().as_ref().as_bytes() == parent {
                    return Ok(None);
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => return Ok(None),
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
}

pub(crate) fn collect_text_for_elements(
    input: &[u8],
    wanted: &[&[u8]],
    max_bytes: usize,
) -> Result<String> {
    let mut reader = Reader::from_reader(input);
    // Not `trim_text(true)`: that trims every *run*, and an entity splits one
    // value into several runs. `done &amp; dusted` arrives as "done ", "&",
    // " dusted", and per-run trimming eats both spaces to give `done&dusted`.
    // Accumulate raw and trim once, at the element boundary.
    reader.config_mut().trim_text(false);
    let mut matched_depth = 0_usize;
    let mut pieces = Vec::new();
    let mut current = String::new();
    // Flush at an element boundary rather than on every text run. A run break
    // caused by an entity is not a value break -- pushing each run separately
    // put the `; ` separator *inside* a value, so `done &amp; dusted` was
    // reported as `done; dusted`, which reads like two messages. A real
    // boundary still separates, so sibling `<line>` elements still join.
    let flush = |current: &mut String, pieces: &mut Vec<String>| {
        let piece = std::mem::take(current);
        let piece = trim_xml_whitespace(&piece);
        if !piece.is_empty() {
            pieces.push(piece.to_owned());
        }
    };
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                if matched_depth > 0 {
                    flush(&mut current, &mut pieces);
                    matched_depth += 1;
                } else if wanted.contains(&element.name().as_ref().as_bytes()) {
                    matched_depth += 1;
                }
            }
            Ok(Event::End(_)) if matched_depth > 0 => {
                matched_depth -= 1;
                flush(&mut current, &mut pieces);
            }
            // A self-closing child is a boundary too. `<msg>first<line/>second</msg>`
            // emits `Empty`, which the Start and End arms both miss, so the two
            // runs shared one buffer and came back as `firstsecond`.
            Ok(Event::Empty(_)) if matched_depth > 0 => {
                flush(&mut current, &mut pieces);
            }
            // No `guard_extracted_len` here: this collector has its own
            // `max_bytes`, applied by truncation at the end, and
            // `parse_panos_response` passes 1024. Applying the 4096-byte
            // scalar-field *rejection* limit turned a long-but-valid error
            // envelope into malformed XML, losing the API code and message it
            // carried -- exactly when the message matters most. Growth is
            // bounded by the response size, which `XmlLimits` already caps.
            Ok(Event::Text(text)) if matched_depth > 0 => {
                current.push_str(&text);
            }
            Ok(Event::CData(text)) if matched_depth > 0 => {
                current.push_str(&text);
            }
            Ok(Event::GeneralRef(entity)) if matched_depth > 0 => {
                push_entity_ref(&mut current, &entity)?;
            }
            Ok(Event::DocType(_)) => {
                return Err(PanosMcpError::Xml(
                    "DOCTYPE declarations are forbidden".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PanosMcpError::Xml(error.to_string())),
        }
    }
    // A document that ends inside a matched element still has text worth
    // reporting -- this is the error path, and truncated input is exactly when
    // the message matters.
    flush(&mut current, &mut pieces);
    let mut message = pieces.join("; ");
    if message.len() > max_bytes {
        let mut boundary = max_bytes;
        while !message.is_char_boundary(boundary) {
            boundary -= 1;
        }
        message.truncate(boundary);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_doctype_before_entity_processing() {
        let xml = br#"<!DOCTYPE response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                     <response status="success"><result>&xxe;</result></response>"#;
        let error = validate_panos_response(xml, XmlLimits::default())
            .expect_err("DOCTYPE input must be rejected");
        assert!(error.to_string().contains("DOCTYPE"));
    }

    #[test]
    fn rejects_excessive_depth_size_multiple_roots_and_trailing_text() {
        assert!(
            validate_panos_response(
                b"<response><a><b/></a></response>",
                XmlLimits {
                    max_bytes: 1024,
                    max_depth: 2
                }
            )
            .is_err()
        );
        assert!(matches!(
            validate_panos_response(
                b"<response/>",
                XmlLimits {
                    max_bytes: 4,
                    max_depth: 64
                }
            ),
            Err(PanosMcpError::InputTooLarge { .. })
        ));
        assert!(
            validate_panos_response(
                b"<response status=\"success\"/><response status=\"success\"/>",
                XmlLimits::default()
            )
            .is_err()
        );
        assert!(
            validate_panos_response(
                b"<response status=\"success\"/>trailing",
                XmlLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn maps_error_response_and_extracts_message() {
        let response = parse_panos_response(
            br#"<response status="error" code="7"><msg><line>Object is not present</line></msg></response>"#,
            XmlLimits::default(),
        ).expect("valid response");
        assert_eq!(response.message, "Object is not present");
        let error = response.ensure_success("fw").expect_err("API error");
        assert!(matches!(
            error,
            PanosMcpError::Api {
                code: 7,
                name: "object-not-present",
                ..
            }
        ));
    }

    #[test]
    fn accepts_only_show_operational_commands() {
        validate_read_only_op_command("<show><system><info/></system></show>")
            .expect("read command");
        assert!(validate_read_only_op_command("<show mode=\"unsafe\"/>").is_err());
        assert!(
            validate_read_only_op_command("<request><restart><system/></restart></request>")
                .is_err()
        );
        assert!(validate_read_only_op_command("<show/><show/>").is_err());
        assert!(validate_read_only_op_command("<!DOCTYPE show><show/>").is_err());
    }

    #[test]
    fn validates_safe_config_xpath_subset() {
        validate_read_xpath(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']",
        )
        .expect("normal PAN-OS XPath");
        assert!(validate_read_xpath("/config//entry").is_err());
        assert!(validate_read_xpath("/config/../mgt-config").is_err());
        assert!(validate_read_xpath("/op/commands").is_err());
        assert!(validate_read_xpath("/config/*").is_err());
    }

    /// MEC-528 F1: an XPath axis step (`name::`, including axes that move
    /// *up* the tree, such as `parent::` or `ancestor::`) passed the old
    /// character-allowlist-plus-prefix check as plain text while addressing
    /// a node outside the path the string appears to name. `mgt-config` is
    /// otherwise blocked by device role restriction and the xpath
    /// blocklist -- an axis step must not be a way around either.
    /// MEC-528 N1: interface names contain `/`; both validators must accept
    /// them (the strict grammar used to split inside the quoted value).
    #[test]
    fn accepts_interface_xpaths_with_slashes() {
        let base =
            "/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet";
        let roots = vec![base.to_owned()];
        for xpath in [
            format!("{base}/entry[@name='ethernet1/1']"),
            format!(
                "{base}/entry[@name='ethernet1/1']/layer3/units/entry[@name='ethernet1/1.100']"
            ),
        ] {
            assert!(
                validate_read_xpath(&xpath).is_ok(),
                "read must accept: {xpath}"
            );
            assert!(
                validate_write_xpath(&xpath, &roots).is_ok(),
                "write must accept: {xpath}"
            );
        }
    }

    #[test]
    fn rejects_axis_steps_on_read() {
        for xpath in [
            "/config/devices/parent::node()",
            "/config/shared/address/entry[@name='x']/ancestor::config",
            "/config/shared/address/entry[@name='x']/following-sibling::entry",
        ] {
            assert!(
                validate_read_xpath(xpath).is_err(),
                "axis syntax must be rejected: {xpath}"
            );
        }
    }

    /// MEC-528 F1: a predicate that is not a single `@attr='literal'`
    /// equality -- an attribute existence test, or comparing one attribute
    /// to another -- matches every sibling under a step, not the one entry
    /// the granted root's own predicate names.
    #[test]
    fn rejects_non_equality_predicates_on_read() {
        for xpath in [
            "/config/shared/address/entry[@name]",
            "/config/shared/address/entry[@name=@other]",
            "/config/shared/address/entry[position()=1]",
        ] {
            assert!(
                validate_read_xpath(xpath).is_err(),
                "a non-equality predicate must be rejected: {xpath}"
            );
        }
    }

    /// The same axis escape must be refused on the write path, even when the
    /// axis step appears after every character of an operator's granted
    /// root -- a text-prefix match alone cannot see that the axis moves the
    /// evaluated node outside that root (MEC-528 F1).
    #[test]
    fn rejects_axis_escape_on_write() {
        let roots = vec![
            "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address-book".to_owned(),
        ];
        let escape = "/config/devices/entry[@name='fw']/vsys/entry[@name='vsys1']/address-book/entry[@name='x']/parent::node()/entry[@name='y']";
        assert!(validate_write_xpath(escape, &roots).is_err());
    }

    #[test]
    fn extracts_facts_and_job_status() {
        let response = parse_panos_response(
            br#"<response status="success" code="19"><result><system><hostname>fw-1</hostname><sw-version>11.2.3</sw-version><serial>001</serial></system></result></response>"#,
            XmlLimits::default(),
        ).expect("facts response");
        let facts = parse_device_facts(&response).expect("facts");
        assert_eq!(facts.hostname.as_deref(), Some("fw-1"));
        assert_eq!(facts.software_version.as_deref(), Some("11.2.3"));

        let response = parse_panos_response(
            br#"<response status="success"><result><job><status>FIN</status><result>OK</result><progress>100</progress></job></result></response>"#,
            XmlLimits::default(),
        ).expect("job response");
        let job = parse_job_status(&response).expect("job");
        assert!(job.succeeded());
    }
}

#[cfg(test)]
mod entity_tests {
    use super::*;

    /// #149: element text was returned on the first `Event::Text`, and since
    /// quick-xml 0.38 an entity reference arrives as its own `GeneralRef`
    /// event — so every value was cut at its first `&`, `<` or `>`, with no
    /// error. A hostname or a job `details` string came back plausible and
    /// wrong, which is the worst way to be wrong.
    #[test]
    fn element_text_survives_an_entity() {
        let cases: &[(&str, &str)] = &[
            ("fw&amp;01", "fw&01"),
            ("a&lt;b&gt;c", "a<b>c"),
            ("x&#38;y", "x&y"),
            ("x&#x26;y", "x&y"),
            ("&quot;q&quot;", "\"q\""),
            ("it&apos;s", "it's"),
            ("plain-fw-01", "plain-fw-01"),
            ("caf\u{e9}-11.1", "caf\u{e9}-11.1"),
            ("a&amp;b&amp;c", "a&b&c"),
        ];
        for (input, expected) in cases {
            let xml = format!(
                "<response status=\"success\"><result><hostname>{input}</hostname></result></response>"
            );
            let got =
                first_element_text(xml.as_bytes(), b"hostname").expect("well-formed input parses");
            assert_eq!(
                got.as_deref(),
                Some(*expected),
                "input {input} truncated or mangled"
            );
        }
    }

    /// The same defect, one level down.
    #[test]
    fn child_text_survives_an_entity() {
        let xml = br#"<result><entry><name>fw&amp;01</name></entry></result>"#;
        let got = first_child_text(xml, b"entry", b"name").expect("parses");
        assert_eq!(got.as_deref(), Some("fw&01"));
    }

    /// `collect_text_for_elements` joins with `; `. Pushing each text run
    /// separately put that separator *inside* a value split by an entity, so
    /// `done &amp; dusted` was reported as `done; dusted` — a message that
    /// reads like two messages.
    #[test]
    fn collected_text_does_not_gain_a_separator_from_an_entity() {
        let xml = br#"<response><msg>done &amp; dusted</msg></response>"#;
        let got = collect_text_for_elements(xml, &[b"msg"], 4096).expect("parses");
        assert_eq!(got, "done & dusted");
    }

    /// Genuinely separate elements still join, so the fix did not merge them.
    #[test]
    fn separate_elements_still_join_with_the_separator() {
        let xml = br#"<response><line>first</line><line>second</line></response>"#;
        let got = collect_text_for_elements(xml, &[b"line"], 4096).expect("parses");
        assert_eq!(got, "first; second");
    }

    /// An element that is present but empty is not the same as one that is
    /// absent, and the accumulating form must keep them apart.
    #[test]
    fn an_empty_element_is_not_a_missing_one() {
        let empty = br#"<result><hostname></hostname></result>"#;
        assert_eq!(
            first_element_text(empty, b"hostname")
                .expect("parses")
                .as_deref(),
            Some("")
        );
        let absent = br#"<result><model>x</model></result>"#;
        assert_eq!(
            first_element_text(absent, b"hostname").expect("parses"),
            None
        );
    }

    /// DOCTYPE is forbidden, so a non-predefined entity cannot have been
    /// defined and there is nothing to expand it to. Preserving the reference
    /// verbatim is lossless; dropping it silently is the bug this fixes.
    #[test]
    fn an_unresolvable_entity_is_preserved_not_dropped() {
        let xml = br#"<result><hostname>a&custom;b</hostname></result>"#;
        let got = first_element_text(xml, b"hostname").expect("parses");
        assert_eq!(got.as_deref(), Some("a&custom;b"));
    }

    /// The extraction bound still applies, and now applies while accumulating
    /// rather than only to a single run.
    #[test]
    fn accumulated_text_is_still_bounded() {
        let big = "a&amp;".repeat(3000);
        let xml = format!("<result><hostname>{big}</hostname></result>");
        let error = first_element_text(xml.as_bytes(), b"hostname")
            .expect_err("an over-long accumulation must be refused");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }
}

#[cfg(test)]
mod entity_edge_tests {
    use super::*;

    /// A long `<msg>` must still produce a typed API error with a bounded
    /// message. Applying the 4096-byte scalar *rejection* limit here turned a
    /// valid long error envelope into malformed XML and lost the code and
    /// message it carried.
    #[test]
    fn a_long_message_is_truncated_not_rejected() {
        let long = "e".repeat(9000);
        let xml = format!("<response status=\"error\" code=\"7\"><msg>{long}</msg></response>");
        let got = collect_text_for_elements(xml.as_bytes(), &[b"msg"], 1024)
            .expect("a long message must not be rejected as malformed");
        assert_eq!(got.len(), 1024, "should be truncated to max_bytes");
    }

    /// A numeric reference that cannot resolve is malformed XML, not text.
    /// Preserving `&#xZZ;` verbatim would put that literal into a hostname.
    #[test]
    fn an_invalid_numeric_reference_is_an_error() {
        for bad in ["&#xZZ;", "&#x110000;"] {
            let xml = format!("<result><hostname>a{bad}b</hostname></result>");
            let result = first_element_text(xml.as_bytes(), b"hostname");
            assert!(
                result.is_err(),
                "{bad} should be refused, got {:?}",
                result.ok()
            );
        }
    }

    /// XML 1.0 forbids most control characters, and a numeric reference can
    /// name one. Accepting it puts a control character into an extracted fact.
    #[test]
    fn a_control_character_reference_is_refused() {
        let xml = br#"<result><hostname>a&#1;b</hostname></result>"#;
        let error =
            first_element_text(xml, b"hostname").expect_err("U+0001 is not a legal XML char");
        assert!(error.to_string().contains("forbids"), "{error}");
    }

    /// The legal ones still work, including the boundary cases.
    #[test]
    fn legal_character_references_still_resolve() {
        for (input, expected) in [("&#9;", "\t"), ("&#xA;", "\n"), ("&#x20;", " ")] {
            let xml = format!("<result><model>x{input}y</model></result>");
            let got = first_element_text(xml.as_bytes(), b"model")
                .expect("a legal reference resolves")
                .expect("present");
            assert_eq!(got, format!("x{expected}y").trim(), "{input}");
        }
    }

    /// `<hostname/>` and `<hostname></hostname>` are the same document. They
    /// must extract the same way, or the present-versus-absent distinction is
    /// decided by the serializer.
    #[test]
    fn a_self_closing_element_is_present_and_empty() {
        let self_closing = br#"<result><hostname/></result>"#;
        let expanded = br#"<result><hostname></hostname></result>"#;
        assert_eq!(
            first_element_text(self_closing, b"hostname").expect("parses"),
            first_element_text(expanded, b"hostname").expect("parses"),
        );
        assert_eq!(
            first_element_text(self_closing, b"hostname")
                .expect("parses")
                .as_deref(),
            Some("")
        );

        let child_self_closing = br#"<result><entry><name/></entry></result>"#;
        assert_eq!(
            first_child_text(child_self_closing, b"entry", b"name")
                .expect("parses")
                .as_deref(),
            Some("")
        );
    }
}

#[cfg(test)]
mod entity_resolver_tests {
    use super::*;

    /// The named-entity set must be the five XML ones, whatever any other crate
    /// in the graph asks quick-xml for.
    ///
    /// `resolve_predefined_entity` becomes `resolve_html5_entity` when the
    /// `escape-html` feature is enabled, and Cargo unifies features across the
    /// whole dependency graph -- so this parser's output would otherwise depend
    /// on a crate that has nothing to do with PAN-OS. `&nbsp;` is the canary:
    /// HTML5 resolves it to U+00A0, XML does not define it at all.
    #[test]
    fn only_the_five_xml_entities_resolve() {
        let xml = br#"<result><hostname>a&nbsp;b</hostname></result>"#;
        let got = first_element_text(xml, b"hostname").expect("parses");
        assert_eq!(
            got.as_deref(),
            Some("a&nbsp;b"),
            "an HTML5-only entity must be preserved, not resolved"
        );

        for (entity, expected) in [
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&amp;", "&"),
            ("&apos;", "'"),
            ("&quot;", "\""),
        ] {
            let xml = format!("<result><model>x{entity}y</model></result>");
            let got = first_element_text(xml.as_bytes(), b"model")
                .expect("parses")
                .expect("present");
            assert_eq!(got, format!("x{expected}y"), "{entity}");
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    /// A PAN-OS job `<details>` carries `<line>` children. Accumulating them
    /// into one buffer glued distinct diagnostic lines together -- one
    /// corrupted message where there were two.
    #[test]
    fn nested_children_stay_separate_lines() {
        let xml = br#"<result><job><details><line>first</line><line>second</line></details></job></result>"#;
        let got = first_child_text(xml, b"job", b"details").expect("parses");
        assert_eq!(got.as_deref(), Some("first; second"));
    }

    /// ...while an entity inside one of those lines is still not a boundary.
    #[test]
    fn an_entity_inside_a_nested_line_is_not_a_boundary() {
        let xml =
            br#"<result><job><details><line>done &amp; dusted</line></details></job></result>"#;
        let got = first_child_text(xml, b"job", b"details").expect("parses");
        assert_eq!(got.as_deref(), Some("done & dusted"));
    }

    /// Plain leaf text is unaffected by the piece machinery.
    #[test]
    fn leaf_text_is_returned_whole() {
        let xml = br#"<result><job><status>FIN</status></job></result>"#;
        assert_eq!(
            first_child_text(xml, b"job", b"status")
                .expect("parses")
                .as_deref(),
            Some("FIN")
        );
    }

    /// A self-closing child inside a collected element is a boundary. Neither
    /// the Start nor the End arm sees `Event::Empty`, so both runs shared one
    /// buffer and came back joined.
    #[test]
    fn a_self_closing_child_separates_the_text_around_it() {
        let xml = br#"<response><msg>first<line/>second</msg></response>"#;
        let got = collect_text_for_elements(xml, &[b"msg"], 4096).expect("parses");
        assert_eq!(got, "first; second");
    }
}

#[cfg(test)]
mod bound_and_trim_tests {
    use super::*;

    /// The bound belongs on the joined value. Checking each `<line>` separately
    /// let a hundred short ones add up well past the limit, while
    /// `JobStatus::details` is contracted to be bounded.
    #[test]
    fn joined_child_text_is_bounded_in_total() {
        let lines: String = (0..100)
            .map(|_| format!("<line>{}</line>", "x".repeat(100)))
            .collect();
        let xml = format!("<result><job><details>{lines}</details></job></result>");
        let error = first_child_text(xml.as_bytes(), b"job", b"details")
            .expect_err("100 x 100 bytes joined must exceed the extraction bound");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    /// A self-closing element that is not the wanted one is still a boundary.
    #[test]
    fn a_self_closing_descendant_separates_text() {
        let xml = br#"<result><job><details>first<line/>second</details></job></result>"#;
        let got = first_child_text(xml, b"job", b"details").expect("parses");
        assert_eq!(got.as_deref(), Some("first; second"));
    }

    /// U+00A0 is text, not whitespace, in XML. `str::trim` removes it -- which
    /// would silently delete a `&#160;` this parser had just resolved.
    #[test]
    fn non_xml_whitespace_is_content_not_padding() {
        let xml = "<result><hostname>\u{a0}fw01\u{a0}</hostname></result>";
        let got = first_element_text(xml.as_bytes(), b"hostname")
            .expect("parses")
            .expect("present");
        assert_eq!(got, "\u{a0}fw01\u{a0}", "U+00A0 was trimmed away");

        let resolved = "<result><hostname>&#160;fw01</hostname></result>";
        let got = first_element_text(resolved.as_bytes(), b"hostname")
            .expect("parses")
            .expect("present");
        assert_eq!(got, "\u{a0}fw01", "a resolved &#160; was trimmed away");
    }

    /// XML's own four whitespace characters are still trimmed.
    #[test]
    fn xml_whitespace_is_still_trimmed() {
        let xml = b"<result><hostname>\n  fw01\t\r\n</hostname></result>";
        let got = first_element_text(xml, b"hostname")
            .expect("parses")
            .expect("present");
        assert_eq!(got, "fw01");
    }
}

#[cfg(test)]
mod entry_scan_tests {
    use super::*;

    fn rules_response(rules: &str) -> String {
        format!(r#"<response status="success"><result><rules>{rules}</rules></result></response>"#)
    }

    #[test]
    fn lists_entries_with_names_and_stable_digests() {
        let xml = rules_response(
            r#"<entry name="allow-dns"><action>allow</action></entry><entry name="deny-all"><action>deny</action></entry>"#,
        );
        let scan = scan_config_entries(xml.as_bytes(), 0, 10, 3).expect("scan");
        assert_eq!(scan.status, "success");
        assert_eq!(scan.total_seen, 2);
        assert!(!scan.truncated);
        assert_eq!(scan.entries.len(), 2);
        assert_eq!(scan.entries[0].name, "allow-dns");
        assert_eq!(scan.entries[1].name, "deny-all");
        assert!(scan.entries[0].digest.starts_with("sha256:"));
        assert_ne!(scan.entries[0].digest, scan.entries[1].digest);

        // Same entry, fetched again unchanged, hashes identically.
        let again = scan_config_entries(xml.as_bytes(), 0, 10, 3).expect("scan");
        assert_eq!(again.entries[0].digest, scan.entries[0].digest);
    }

    #[test]
    fn a_changed_entry_changes_only_its_own_digest() {
        let before = rules_response(r#"<entry name="r1"><action>allow</action></entry>"#);
        let after = rules_response(r#"<entry name="r1"><action>deny</action></entry>"#);
        let before_digest = scan_config_entries(before.as_bytes(), 0, 10, 3)
            .expect("scan")
            .entries
            .remove(0)
            .digest;
        let after_digest = scan_config_entries(after.as_bytes(), 0, 10, 3)
            .expect("scan")
            .entries
            .remove(0)
            .digest;
        assert_ne!(before_digest, after_digest);
    }

    #[test]
    fn self_closing_entries_are_captured_like_open_ones() {
        let xml = rules_response(r#"<entry name="empty-rule"/>"#);
        let scan = scan_config_entries(xml.as_bytes(), 0, 10, 3).expect("scan");
        assert_eq!(scan.total_seen, 1);
        assert_eq!(scan.entries[0].name, "empty-rule");
        assert_eq!(scan.entries[0].xml, r#"<entry name="empty-rule"/>"#);
    }

    #[test]
    fn pagination_returns_only_the_requested_window() {
        let rules: String = (0..25)
            .map(|i| format!(r#"<entry name="r{i}"/>"#))
            .collect();
        let xml = rules_response(&rules);

        let page = scan_config_entries(xml.as_bytes(), 10, 5, 3).expect("scan");
        assert_eq!(page.total_seen, 25);
        assert_eq!(page.entries.len(), 5);
        assert_eq!(page.entries[0].name, "r10");
        assert_eq!(page.entries[4].name, "r14");
        // "N of M shown": more entries exist beyond this page.
        assert!(10 + page.entries.len() < page.total_seen);
    }

    #[test]
    fn a_response_truncated_mid_entry_drops_the_partial_entry_and_is_marked() {
        let full = rules_response(
            r#"<entry name="r1"/><entry name="r2"><action>allow</action></entry><entry name="r3"/>"#,
        );
        // Cut the byte stream partway through r2's body, well before its
        // closing tag -- this is what a byte-capped device fetch produces.
        let cut = full.find("<action>").expect("marker") + 4;
        let truncated = &full.as_bytes()[..cut];

        let scan = scan_config_entries(truncated, 0, 10, 3).expect("scan");
        assert!(scan.truncated);
        // r1 completed before the cut; r2 was still open and must not appear.
        assert_eq!(scan.total_seen, 1);
        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].name, "r1");
    }

    #[test]
    fn a_response_truncated_before_the_envelope_opens_is_an_error() {
        let truncated = br#"<respo"#;
        assert!(scan_config_entries(truncated, 0, 10, 3).is_err());
    }

    #[test]
    fn an_error_envelope_is_still_reported() {
        let xml = r#"<response status="error" code="7"><msg><line>Object not present</line></msg></response>"#;
        let scan = scan_config_entries(xml.as_bytes(), 0, 10, 3).expect("scan");
        assert_eq!(scan.status, "error");
        assert_eq!(scan.code, Some(7));
        assert!(scan.entries.is_empty());
    }

    #[test]
    fn min_depth_two_finds_an_entry_resolved_directly_by_its_own_xpath() {
        let xml = r#"<response status="success"><result><entry name="allow-dns"><action>allow</action></entry></result></response>"#;
        let scan = scan_config_entries(xml.as_bytes(), 0, 1, 2).expect("scan");
        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].name, "allow-dns");
    }

    #[test]
    fn nested_entries_inside_a_captured_entry_are_not_double_counted() {
        // Defensive: a rule containing something that itself looks like an
        // <entry> must not be treated as a second top-level list entry.
        let xml = rules_response(
            r#"<entry name="outer"><profile-setting><entry name="inner"/></profile-setting></entry>"#,
        );
        let scan = scan_config_entries(xml.as_bytes(), 0, 10, 3).expect("scan");
        assert_eq!(scan.total_seen, 1);
        assert_eq!(scan.entries[0].name, "outer");
        assert!(scan.entries[0].xml.contains("inner"));
    }

    #[test]
    fn rejects_doctype_even_mid_scan() {
        let xml = br#"<response status="success"><result><rules><!DOCTYPE x><entry name="r1"/></rules></result></response>"#;
        assert!(scan_config_entries(xml, 0, 10, 3).is_err());
    }
}

#[cfg(test)]
mod panorama_tests {
    use super::*;

    fn response(xml: &str) -> PanosResponse {
        parse_panos_response(xml.as_bytes(), XmlLimits::default()).expect("valid envelope")
    }

    #[test]
    fn validates_job_id_shape() {
        validate_job_id("10").expect("plain digits accepted");
        assert!(validate_job_id("").is_err());
        assert!(validate_job_id("12x").is_err());
        assert!(validate_job_id(&"1".repeat(33)).is_err());
    }

    #[test]
    fn parses_op_device_groups_with_members_and_an_empty_group() {
        // MEC-759: `<show><devicegroups/></show>` output nests connected
        // serials the same way the config `device-group` container does, and
        // may carry sibling per-firewall connection/commit detail (`<conn-
        // status>`, `<last-commit-all-state-sp>`, ...) this parser must
        // ignore rather than mistake for a member serial.
        let response = response(
            r#"<response status="success"><result><devicegroups>
                <entry name="DG-Branch"><devices>
                    <entry name="0011C1"><hostname>fw-01</hostname><conn-status>up</conn-status></entry>
                    <entry name="0011C2"/>
                </devices></entry>
                <entry name="DG-Empty"/>
            </devicegroups></result></response>"#,
        );
        let groups = parse_panorama_device_groups_op(&response).expect("device groups parse");
        assert_eq!(
            groups,
            vec![
                DeviceGroupSummary {
                    name: "DG-Branch".to_owned(),
                    member_serials: vec!["0011C1".to_owned(), "0011C2".to_owned()],
                },
                DeviceGroupSummary {
                    name: "DG-Empty".to_owned(),
                    member_serials: vec![],
                },
            ]
        );
    }

    #[test]
    fn parses_op_template_names_ignoring_non_variable_op_detail() {
        // MEC-759: `<show><templates/></show>` reports per-target-firewall
        // commit/connection history, not variables -- this parser must
        // extract only the template names and ignore that nested detail.
        let response = response(
            r#"<response status="success"><result><templates>
                <entry name="TMPL-Base"><devices><entry name="0011C1"><conn-status>up</conn-status></entry></devices></entry>
                <entry name="TMPL-NoDevices"/>
            </templates></result></response>"#,
        );
        let names = parse_panorama_templates_op(&response).expect("template names parse");
        assert_eq!(
            names,
            vec!["TMPL-Base".to_owned(), "TMPL-NoDevices".to_owned()]
        );
    }

    #[test]
    fn an_empty_device_group_op_container_yields_no_entries() {
        let response =
            response(r#"<response status="success"><result><devicegroups/></result></response>"#);
        assert_eq!(
            parse_panorama_device_groups_op(&response).expect("parses"),
            vec![]
        );
    }

    #[test]
    fn parses_push_job_status_with_overall_and_per_device_state() {
        // Real PAN-OS reports the per-device serial as a `<serial-no>` child,
        // not a `name` attribute on `<entry>` -- see `parse_push_devices`.
        // A fixture using `name="..."` instead would pass without proving
        // anything about the actual wire shape.
        let response = response(
            r#"<response status="success"><result><job>
                <id>10</id>
                <type>CommitAll</type>
                <status>FIN</status>
                <result>OK</result>
                <progress>100</progress>
                <details><line>Configuration committed successfully</line></details>
                <devices>
                    <entry>
                        <serial-no>0011C1</serial-no>
                        <devicename>fw-01</devicename>
                        <status>FIN</status>
                        <result>OK</result>
                        <progress>100</progress>
                        <details><line>commit succeeded</line></details>
                    </entry>
                    <entry>
                        <serial-no>0011C2</serial-no>
                        <devicename>fw-02</devicename>
                        <status>ACT</status>
                        <result></result>
                        <progress>42</progress>
                    </entry>
                </devices>
            </job></result></response>"#,
        );
        let status = parse_push_job_status(&response).expect("push status parses");
        assert_eq!(status.job.status.as_deref(), Some("FIN"));
        assert_eq!(status.job.result.as_deref(), Some("OK"));
        assert_eq!(status.job.progress, Some(100));
        assert_eq!(
            status.devices,
            vec![
                PushDeviceStatus {
                    serial: "0011C1".to_owned(),
                    device_name: Some("fw-01".to_owned()),
                    status: Some("FIN".to_owned()),
                    result: Some("OK".to_owned()),
                    progress: Some(100),
                    details: Some("commit succeeded".to_owned()),
                },
                PushDeviceStatus {
                    serial: "0011C2".to_owned(),
                    device_name: Some("fw-02".to_owned()),
                    status: Some("ACT".to_owned()),
                    result: Some(String::new()),
                    progress: Some(42),
                    details: None,
                },
            ]
        );
    }

    #[test]
    fn push_device_details_with_nested_errors_are_not_read_as_the_devices_status() {
        // `<details><msg><errors><line>` nests its own text a few levels
        // inside the device entry. A depth-unaware reader for `status`/
        // `result` would find nothing of that shape here, but this guards
        // against ever reintroducing one that walks into `<details>` and
        // mistakes an unrelated descendant for the device's own field.
        let response = response(
            r#"<response status="success"><result><job>
                <id>12</id><status>FIN</status>
                <devices>
                    <entry>
                        <serial-no>0011C3</serial-no>
                        <devicename>fw-03</devicename>
                        <status>FIN</status>
                        <result>FAIL</result>
                        <details><msg><errors><line>commit failed: syntax error</line></errors></msg></details>
                    </entry>
                </devices>
            </job></result></response>"#,
        );
        let status = parse_push_job_status(&response).expect("push status parses");
        assert_eq!(
            status.devices,
            vec![PushDeviceStatus {
                serial: "0011C3".to_owned(),
                device_name: Some("fw-03".to_owned()),
                status: Some("FIN".to_owned()),
                result: Some("FAIL".to_owned()),
                progress: None,
                details: Some("commit failed: syntax error".to_owned()),
            }]
        );
    }

    #[test]
    fn push_device_details_are_redacted_like_the_overall_job_details() {
        // Same text class as `parse_job_status`'s `<job><details>`: a
        // per-device commit/push failure can quote the offending config
        // line, which can itself carry a stored secret value. Fake-shaped
        // master-key blob and crypt hash, never real device output.
        let response = response(
            r#"<response status="success"><result><job>
                <id>13</id><status>FIN</status>
                <devices>
                    <entry>
                        <serial-no>0011C6</serial-no>
                        <status>FIN</status>
                        <result>FAIL</result>
                        <details><msg><errors><line>duplicate pre-shared-key FAKE_MASTER_KEY_BLOB-AQ== and encrypted-password $6$FAKE_CRYPT_HASH_1a2b3c</line></errors></msg></details>
                    </entry>
                </devices>
            </job></result></response>"#,
        );
        let status = parse_push_job_status(&response).expect("push status parses");
        let details = status.devices[0]
            .details
            .as_deref()
            .expect("device details");
        assert!(
            !details.contains("FAKE_MASTER_KEY_BLOB-AQ=="),
            "master-key blob leaked verbatim: {details}"
        );
        assert!(
            !details.contains("FAKE_CRYPT_HASH_1a2b3c"),
            "crypt hash leaked verbatim: {details}"
        );
        assert!(
            details.contains("[REDACTED"),
            "expected a redaction placeholder in: {details}"
        );
    }

    #[test]
    fn push_device_falls_back_to_name_attribute_when_serial_no_is_absent() {
        let response = response(
            r#"<response status="success"><result><job><devices>
                <entry name="0011C4"><devicename>fw-04</devicename></entry>
            </devices></job></result></response>"#,
        );
        let status = parse_push_job_status(&response).expect("push status parses");
        assert_eq!(status.devices[0].serial, "0011C4");
    }

    #[test]
    fn push_device_with_neither_serial_no_nor_name_is_refused() {
        let response = response(
            r#"<response status="success"><result><job><devices>
                <entry><devicename>fw-05</devicename></entry>
            </devices></job></result></response>"#,
        );
        let error =
            parse_push_job_status(&response).expect_err("device with no serial must be refused");
        assert!(error.to_string().contains("serial-no"));
    }

    #[test]
    fn push_job_with_no_devices_yields_an_empty_device_list() {
        let response = response(
            r#"<response status="success"><result><job>
                <id>11</id><status>ACT</status><progress>10</progress>
            </job></result></response>"#,
        );
        let status = parse_push_job_status(&response).expect("parses");
        assert_eq!(status.job.status.as_deref(), Some("ACT"));
        assert!(status.devices.is_empty());
    }

    #[test]
    fn rejects_a_non_numeric_push_device_progress() {
        let response = response(
            r#"<response status="success"><result><job><devices>
                <entry><serial-no>0011C1</serial-no><progress>not-a-number</progress></entry>
            </devices></job></result></response>"#,
        );
        let error = parse_push_job_status(&response).expect_err("bad progress must be refused");
        assert!(error.to_string().contains("integer"));
    }

    #[test]
    fn device_group_member_count_is_bounded() {
        let mut members = String::new();
        for index in 0..=MAX_MEMBERS_PER_ENTRY {
            members.push_str(&format!("<entry name=\"serial-{index}\"/>"));
        }
        let xml = format!(
            r#"<response status="success"><result><devicegroups><entry name="DG"><devices>{members}</devices></entry></devicegroups></result></response>"#
        );
        let response = response(&xml);
        let error =
            parse_panorama_device_groups_op(&response).expect_err("excess members must be refused");
        assert!(error.to_string().contains("more than"));
    }
}
