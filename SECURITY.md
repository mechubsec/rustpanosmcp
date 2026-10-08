# Security policy

## Supported versions

The latest `0.16.x` release and the default branch receive security
fixes. Pre-release branches are supported only while their pull request is
active.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory form for this repository:

https://github.com/mechubsec/rustpanosmcp/security/advisories/new

Include the affected commit/version, deployment mode, reproduction steps,
impact, and whether any bearer token or PAN-OS API key may have been exposed.
Do not include live credentials, configuration payloads, or customer data.

The maintainers will acknowledge a complete report within five business days,
coordinate validation and remediation privately, and publish an advisory after
a fix and operator guidance are available.

## Immediate credential response

If a bearer token may be exposed, revoke it, reload the service, and inspect
audit logs for its non-secret token name. If a PAN-OS API key may be exposed,
revoke/regenerate it on PAN-OS, replace its protected secret source, reload the
service, and inspect both PAN-OS administrator logs and rust-panosmcp audit
events. Never paste a live credential into an issue, log, test fixture, or
support transcript.
