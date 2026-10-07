//! Boundary helper for scrubbing device-sourced XML before it reaches a tool
//! result.
//!
//! PAN-OS's own read APIs return exactly what an operator would see over the
//! GUI or CLI -- `phash` values, IPsec/IKE pre-shared keys, RADIUS/LDAP
//! server secrets, and the SNMP community string all come back inline in
//! config and op-command XML. This server hands that XML to a model with no
//! duty of confidentiality, so every place a device's raw XML becomes part
//! of a tool's return value must pass through here first.
//!
//! `redact_device_xml` is deliberately the *only* function this module
//! exports: callers pass the exact XML string they are about to embed in a
//! result, at the point it is about to leave the device-facing layer,
//! rather than earlier (before the caller has the whole document) or later
//! (after it has already been serialized into a `BoundedText` or a JSON
//! tool result, where a truncated or already-escaped copy is harder to
//! redact correctly).
//!
//! `PANOS_PROFILE` declares this server's extensions to the generic
//! denylist-and-shape scan, mirroring the fixture profile mecmcp-redact's
//! own test suite proves against PAN-OS response shapes
//! (`mecmcp-redact/tests/panos_profile.rs`). Two different things ride on it:
//!
//! - The BGP route-community *value* shape (`65000:100`) is exempted
//!   wherever it appears directly under a `bgp` scope -- this applies on
//!   both the JSON and XML redaction paths.
//! - The `key_exemptions` list (`show session info`'s
//!   `sessions`/`sessions-active`/... counters, BGP's
//!   `community-list`/`match-community`/... route-map clauses) currently has
//!   effect only through [`mecmcp_redact::redact_json_value_with_profile`];
//!   as of mecmcp-redact v0.26.0 the XML path has no key-exemption
//!   equivalent yet (`mecmcp_redact::xml`'s own doc comment says so), so a
//!   raw PAN-OS XML document containing those field names is still redacted
//!   wholesale by [`redact_device_xml`] below. That is the safe direction to
//!   fail in -- a false positive loses a diagnostic counter, not a secret --
//!   so this module does not work around the gap; it is tracked for
//!   mecmcp-redact to close, not duplicated here. Nothing this crate already
//!   redacts by default is narrowed -- a profile only adds exceptions scoped
//!   to fields this vendor's schema is known to use non-secretly.

use mecmcp_redact::Profile;

/// This server's PAN-OS redaction profile -- kept in sync with the fixture
/// mecmcp-redact's own `panos_profile.rs` test proves exemptions against, so
/// a future mecmcp-redact release that tightens or renames an exemption is
/// caught by `panos_profile_key_exemptions_do_not_collide_with_the_denylist`
/// below rather than silently drifting.
pub(crate) const PANOS_PROFILE: Profile = Profile::new(
    &[],
    &[
        "sessions",
        "sessionsactive",
        "maxsessions",
        "sessiontimeout",
        "idletimeouttcpsession",
        "communitylist",
        "matchcommunity",
        "addcommunity",
        "removecommunity",
    ],
)
.with_bgp_route_communities();

/// Redact secret-shaped values out of a raw PAN-OS XML document.
///
/// Tries [`mecmcp_redact::redact_xml_str_with_profile`] first -- the
/// structured pass that understands element and attribute names, not just
/// line shapes, narrowed by [`PANOS_PROFILE`] so BGP route communities
/// survive (see the module doc for the XML/JSON key-exemption asymmetry).
/// PAN-OS responses are well-formed XML, so this succeeds in the
/// overwhelmingly common case.
///
/// Falls back to [`mecmcp_redact::redact_text`] (which always succeeds, and
/// has no profile-aware variant -- it has no key names to exempt by) when the
/// input does not parse as XML -- an unusual, but not impossible, device
/// response (a stray control character, a non-UTF-8 byte PAN-OS itself
/// mangled). The contract this module exists to hold is "never return raw
/// device XML," not "always use the XML-aware pass," so a parse failure
/// must never become a reason to skip redaction altogether.
#[must_use]
pub(crate) fn redact_device_xml(xml: &str) -> String {
    mecmcp_redact::redact_xml_str_with_profile(xml, &PANOS_PROFILE)
        .unwrap_or_else(|_| mecmcp_redact::redact_text(xml))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_xml_is_redacted_structurally() {
        let xml =
            r#"<response status="success"><result><phash>FAKEphash123</phash></result></response>"#;
        let out = redact_device_xml(xml);
        assert!(!out.contains("FAKEphash123"), "got: {out}");
        assert!(out.contains("<result>"), "structure must survive: {out}");
    }

    #[test]
    fn malformed_input_still_gets_the_text_fallback() {
        let malformed = "<unclosed><phash>FAKEphash456</phash>";
        let out = redact_device_xml(malformed);
        assert!(
            !out.contains("FAKEphash456"),
            "a parse failure must not skip redaction: {out}"
        );
    }

    #[test]
    fn panos_profile_key_exemptions_do_not_collide_with_the_denylist() {
        assert_eq!(PANOS_PROFILE.check_exemptions(), Ok(()));
    }

    /// Documents the current mecmcp-redact v0.26.0 limitation this module's
    /// doc comment calls out: `PANOS_PROFILE`'s `key_exemptions` have no
    /// effect on the XML path yet, so `show session info` counters embedded
    /// in a raw PAN-OS op-command response are still redacted wholesale
    /// through `redact_device_xml`. If a future mecmcp-redact release adds
    /// XML key-exemption support, this assertion flips and should be updated
    /// alongside it rather than silently starting to fail.
    #[test]
    fn show_session_info_counters_are_still_redacted_via_the_xml_path_today() {
        let xml = r#"<response status="success"><result><sessions>10</sessions><sessions-active>3</sessions-active></result></response>"#;
        let out = redact_device_xml(xml);
        assert!(!out.contains("<sessions>10</sessions>"), "got: {out}");
        assert!(
            !out.contains("<sessions-active>3</sessions-active>"),
            "got: {out}"
        );
    }

    #[test]
    fn bgp_route_community_survives_the_profile() {
        let xml =
            r#"<bgp><policy><community><member>65000:100</member></community></policy></bgp>"#;
        let out = redact_device_xml(xml);
        assert!(out.contains("65000:100"), "got: {out}");
    }

    #[test]
    fn snmp_community_string_is_still_redacted_despite_the_bgp_exemption() {
        let xml = r#"<snmp-setting><access-setting><version><v2c><community>FAKEsnmpCommunity789</community></v2c></version></access-setting></snmp-setting>"#;
        let out = redact_device_xml(xml);
        assert!(!out.contains("FAKEsnmpCommunity789"), "got: {out}");
    }

    #[test]
    fn session_token_leaf_outside_the_diagnostic_container_is_still_redacted() {
        let xml = r#"<response status="success"><result><session>FAKEsessiontoken001</session></result></response>"#;
        let out = redact_device_xml(xml);
        assert!(!out.contains("FAKEsessiontoken001"), "got: {out}");
    }
}
