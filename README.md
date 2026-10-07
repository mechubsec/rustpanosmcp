<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-panosmcp</h1>

<p align="center"><strong>Async Rust Model Context Protocol server for Palo Alto Networks PAN-OS firewalls</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Palo Alto Networks. Product names and trademarks are used only to identify the systems with which the software interoperates.

The repository contains the v0.15.0 release: a bearer-protected server with structured audit logging, guarded PAN-OS candidate configuration lifecycle, and hardened release packaging, with authentication and auditing provided by the shared [`mecmcp-auth`](https://github.com/mechubsec/mecmcp) and [`mecmcp-audit`](https://github.com/mechubsec/mecmcp) crates.

The project goal is a small, fast, production-oriented server with the same
security posture as `rust-junosmcp`: bearer-token authentication, per-token
device and tool scopes, TLS, strict remote-bind refusal rules, bounded input
and output, auditable change operations, and efficient connection reuse.

The architecture and delivery plan are in [PLAN.md](PLAN.md). Security
boundaries and release-blocking controls are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Workspace

```text
rust-panosmcp/          # MCP binary and stdio adapter
rust-panosmcp-auth/     # bearer and secret-handling foundations
rust-panosmcp-core/     # inventory, PAN-OS client, validation, tool logic
config/                 # secret-free inventory examples
docs/                   # operator guidance and phase notes
fuzz/                   # isolated cargo-fuzz workspace
packaging/              # distroless/container and systemd assets
scripts/                # release, matrix, fuzz, and benchmark gates
```

## Quick start

### Installation

Choose one of three install paths:

#### Release tarball (Linux x86_64)

Download the latest release from [GitHub releases](https://github.com/mechubsec/rustpanosmcp/releases). Assets follow the pattern `rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz` with a corresponding `.sha256` file.

```bash
# Download and verify
curl -LO https://github.com/mechubsec/rustpanosmcp/releases/download/v0.15.0/rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/mechubsec/rustpanosmcp/releases/download/v0.15.0/rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# Extract
tar xzf rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz
cd rust-panosmcp-v0.15.0

# Install the binary and systemd assets
sudo install -m 0755 bin/rust-panosmcp /usr/local/bin/rust-panosmcp
sudo install -m 0644 packaging/systemd/rust-panosmcp.sysusers /usr/lib/sysusers.d/rust-panosmcp.conf
sudo install -m 0644 packaging/systemd/rust-panosmcp.tmpfiles /usr/lib/tmpfiles.d/rust-panosmcp.conf
sudo install -m 0644 packaging/systemd/rust-panosmcp.service /etc/systemd/system/rust-panosmcp.service

# Create the service user and directories
sudo systemd-sysusers
sudo systemd-tmpfiles --create

# Generate the HMAC key for audit redaction (required).
# Guarded: NEVER overwrite an existing key. The key is what makes an HMAC-redacted
# device identifier comparable across audit history, so replacing it silently
# breaks correlation with every record already written. These steps are safe to
# re-run during an upgrade only because of this guard.
sudo sh -c '[ -f /etc/rust-panosmcp/audit-hmac.key ] ||
    head -c 32 /dev/urandom | base64 > /etc/rust-panosmcp/audit-hmac.key'
sudo chmod 0600 /etc/rust-panosmcp/audit-hmac.key
sudo chown rust-panosmcp:rust-panosmcp /etc/rust-panosmcp/audit-hmac.key

# Start the service
sudo systemctl daemon-reload
sudo systemctl enable --now rust-panosmcp
```

This creates a dedicated `rust-panosmcp` system user and provisions `/etc/rust-panosmcp` (config, root-owned) and `/var/lib/rust-panosmcp` (state). The HMAC key at `/etc/rust-panosmcp/audit-hmac.key` is required for device-redaction in audit logs — the service will not start without it. The extracted archive includes configuration examples in `config/` — use `devices.example.json` and `tokens.example.json` as starting templates under `/etc/rust-panosmcp` before starting. See [packaging/systemd/](packaging/systemd/) for unit details.

#### LXC (Debian 13)

For a dedicated unprivileged LXC container on Proxmox or standalone systemd-nspawn, the release tarball includes an idempotent installer that automates the manual sequence above. For a complete setup guide including container creation, see [HOW-TO-SETUP-LXC.md](docs/HOW-TO-SETUP-LXC.md).

```bash
# Download and verify
curl -LO https://github.com/mechubsec/rustpanosmcp/releases/download/v0.15.0/rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/mechubsec/rustpanosmcp/releases/download/v0.15.0/rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# Extract and run the installer
tar xzf rust-panosmcp-v0.15.0-x86_64-unknown-linux-gnu.tar.gz
cd rust-panosmcp-v0.15.0
sudo packaging/lxc/install.sh

# Configure the inventory and mint the first token
sudo vi /etc/rust-panosmcp/devices.json
sudo rust-panosmcp token add \
  --tokens-file /var/lib/rust-panosmcp/tokens.json \
  --name initial-token \
  --devices fw-example \
  --tools list_devices,gather_device_facts,execute_panos_op,get_panos_config

# Start the service
sudo systemctl enable --now rust-panosmcp.service
```

The installer creates the `rust-panosmcp` user and directories via `systemd-sysusers` and `systemd-tmpfiles`, installs the binary and unit, creates an empty `tokens.json` with mode 0600, and never overwrites `/var/lib/rust-panosmcp/mutation-state.json` if it exists (change-set audit trail). The endpoint listens on `http://127.0.0.1:30031/mcp` by default. See `packaging/lxc/install.sh` for environment-variable overrides and upgrade behavior.

#### Docker / GHCR

Prebuilt images are published to `ghcr.io/mechubsec/rustpanosmcp` on every release tag. See [.github/workflows/release-image.yml](.github/workflows/release-image.yml) for the build pipeline. For a complete setup guide including both two-person and lab modes, see [HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md).

```bash
# Pull the image
docker pull ghcr.io/mechubsec/rustpanosmcp:latest
```

The default `CMD` binds `127.0.0.1:30031` *inside* the container, so a bare
`docker run` with no `-p` and no `--host`/`--allowed-host`/`--allowed-origin`
starts cleanly but is not reachable from outside the container. Follow
[HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md) for a working two-person
or lab-mode `docker run` invocation (including the port publish and the flags
the baked-in ENTRYPOINT already supplies) or use the included
`compose.example.yaml`.

#### Run with Docker (stdio)

For MCP clients that launch a server over stdin/stdout, prepare an inventory
with the same shape as `config/devices.example.json`:

```json
{
  "version": 1,
  "policy": {
    "mode": "allowlist",
    "allow": ["show system info", "show interface all"]
  },
  "devices": [
    {
      "name": "panos-demo",
      "endpoint": "https://panos-demo.example.net",
      "vsys": "vsys1",
      "api_key": { "type": "env", "name": "PANOS_DEMO_API_KEY" },
      "tags": ["lab", "read-only"]
    }
  ]
}
```

Export the API-key variable before launching the container. This passthrough
form keeps the key out of the command line and Docker's inspect output:

```bash
export PANOS_DEMO_API_KEY=replace-with-runtime-secret
```

Make the mounted inventory and state files readable and writable only by the
container user (`uid:gid 65532:65532`); secret-bearing files must have mode
`0600`. Stdio is unauthenticated at the process boundary: the launcher can
use every device in the mounted inventory and every tool, so scope access by
limiting that inventory and using a read-only PAN-OS API role. The state
directory must be writable because the server creates its audit state there.

```bash
mkdir -p state
chmod 0600 devices.json
sudo chown 65532:65532 devices.json state

docker run --rm -i \
  --user 65532:65532 \
  -e PANOS_DEMO_API_KEY \
  -v "$PWD/devices.json:/etc/rust-panosmcp/devices.json:ro" \
  -v "$PWD/state:/var/lib/rust-panosmcp" \
  ghcr.io/mechubsec/rustpanosmcp:0.15.0 \
  --transport stdio
```

The image ENTRYPOINT already supplies the config, token, state, and audit-key
paths, so do not repeat those flags after the image name. The token path is
only used by HTTP. This invocation leaves HTTP and listener TLS off: supplying
`--transport stdio` replaces the image CMD, including its HTTP bind and port
flags. Connections to the firewall still use HTTPS according to the
inventory's TLS trust settings.

#### Build from source

Requires Rust 1.89 or newer (MSRV).

```bash
git clone https://github.com/mechubsec/rustpanosmcp.git
cd rustpanosmcp
cargo build --release --locked
./target/release/rust-panosmcp --version
```

### Run (stdio)

Start from [config/devices.example.json](config/devices.example.json), keep the
real inventory out of Git, and provide the referenced environment secret:

```bash
export PANOS_LAB_API_KEY='runtime-secret'
cargo run --locked --release -- --device-mapping /absolute/path/devices.json
```

### Run (streamable-http with auth)

First mint a least-privilege token, then start the TLS Streamable HTTP transport:

```bash
cargo run --locked --release -- \
  --device-mapping /etc/rust-panosmcp/devices.json \
  token add \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --name read-only-client \
  --devices fw-example \
  --tools list_devices,gather_device_facts,execute_panos_op,get_panos_config

cargo run --locked --release -- \
  --device-mapping /etc/rust-panosmcp/devices.json \
  --transport streamable-http \
  --host 0.0.0.0 --port 30031 \
  --tokens-file /etc/rust-panosmcp/tokens.json \
  --tls-cert /etc/rust-panosmcp/server.crt \
  --tls-key /etc/rust-panosmcp/server.key \
  --allowed-host mcp.example.net \
  --allowed-origin https://client.example.net
```

Capture the first command's stdout securely: that is the only display of the
new bearer secret. See [docs/PHASE2_OPERATIONS.md](docs/PHASE2_OPERATIONS.md)
for token rotation, reload, refusal rules, reverse-proxy deployment, and all
security defaults. Phase 1 inventory and firewall TLS details remain in
[docs/PHASE1_OPERATIONS.md](docs/PHASE1_OPERATIONS.md).

> Next: [Learn the reader, writer, and reviewer MCP role
> workflow](docs/MCP_ROLE_WORKFLOW.md).

## Status

Phase 1 implemented validated inventory and secret providers, strict HTTPS with
system roots/custom CA/exact leaf pinning, pooled async PAN-OS XML API calls,
typed errors, timeouts, cancellation, output caps, and a per-device semaphore.
Phase 2 added digest-only bearer tokens, exact device/tool scopes, atomic
inventory/token reload, TLS Streamable HTTP, Host/Origin validation, bounded
request bodies, IP/token rate limits, and audit-safe request tracing. Both
transports share the same 27 tools described in [MCP tools
reference](#mcp-tools-reference) below; wildcard `*` token scopes reach only
the 16 read-only ones (`list_devices`, `gather_device_facts`,
`execute_panos_op`, `get_panos_config`, `list_panos_entries`,
`get_panos_entry_digest`, `list_panorama_device_groups`,
`list_panorama_templates`, `get_panorama_push_status`,
`list_panos_rulebase_entries`, `get_panos_ha_state`, `get_panos_license_info`,
`get_panos_content_status`, `get_panos_software_status`,
`test_panos_security_policy_match`, `query_panos_logs`); the 11
lifecycle/change tools must be named explicitly.

Phase 3 adds opt-in candidate fingerprints, narrow XPath policy, PAN-OS config
locks, per-device serialization, stage/diff/full validation, admin-scoped
partial commit/revert, job reconciliation, and structured mutation audit. Write
tools require explicit token scopes; `*` remains read-only.

Phase 4 adds a digest-pinned non-root distroless image, hardened systemd unit,
read-only deployment guidance, PAN-OS release-family matrix, five parser fuzz
targets, byte-reproducible archives, security/runbook documentation, and
published Rust/Python measurements.

v0.2 adds persistent multi-action change sets, token-specific XPath/action
grants and expiry, canonical-endpoint serialization, and independent approval
bound to the exact owner/device/fingerprint/action digest. Approved sets apply
under one PAN-OS config lock and automatically admin-revert if a later action
fails. They then use the existing diff, full-validation, commit, or discard
lifecycle. See [docs/V0.2_CHANGE_SETS.md](docs/V0.2_CHANGE_SETS.md).

v0.2.1 makes PAN-OS configuration-lock release a confirmed state transition:
commit/discard records clear `config_lock_held` only after the device accepts
unlock, while a failed unlock is persisted as `indeterminate` for explicit
reconciliation. It also records the default-trusted TLS and lab rollout
evidence in [docs/V0.2.1_ACCEPTANCE.md](docs/V0.2.1_ACCEPTANCE.md).

v0.2.2 updates the maintained Rust dependency graph and GitHub Actions while
preserving the v0.2.1 PAN-OS tool, authorization, inventory, and mutation-state
interfaces. The published release and guarded lab rollout evidence is in
[docs/V0.2.2_ACCEPTANCE.md](docs/V0.2.2_ACCEPTANCE.md). Multi-vsys, HA, and
Panorama work remains deferred.

v0.3.0 moves authentication onto the shared
[`mecmcp-auth`](https://github.com/mechubsec/mecmcp) crate, retiring this
repository's own token, store, and token-file implementations in favour of one
shared, separately tested crate. The PAN-OS tool surface, authorization scopes,
inventory, and mutation-state interfaces are unchanged. Two operator-visible
changes: `tokens.json` must be mode 0600 or the server refuses to start, and the
on-disk envelope version is now preserved on write so a file this release touches
stays readable by the previous one. See [CHANGELOG.md](CHANGELOG.md) for the
upgrade steps.

The full HTTPS mock, MCP end-to-end, and explicitly configured `panosvm` lab
firewall acceptance suites pass. Phase 1 is complete; the reproducible evidence
is recorded in [docs/PHASE1_ACCEPTANCE.md](docs/PHASE1_ACCEPTANCE.md).

Phase 2 acceptance evidence is recorded in
[docs/PHASE2_ACCEPTANCE.md](docs/PHASE2_ACCEPTANCE.md). Configuration mutation
acceptance is in [docs/PHASE3_ACCEPTANCE.md](docs/PHASE3_ACCEPTANCE.md), with
operator requirements in [docs/PHASE3_OPERATIONS.md](docs/PHASE3_OPERATIONS.md).
Phase 4 release evidence is in
[docs/PHASE4_ACCEPTANCE.md](docs/PHASE4_ACCEPTANCE.md). Production deployment,
rotation, backup/recovery, and upgrades are covered by
[docs/OPERATIONS.md](docs/OPERATIONS.md); see also
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md),
[docs/BENCHMARKS.md](docs/BENCHMARKS.md), and [SECURITY.md](SECURITY.md). For
the PAN-OS-side least-privilege administrator accounts (distinct from the MCP
bearer roles above), see
[docs/PANOS_ADMIN_ROLES.md](docs/PANOS_ADMIN_ROLES.md).

## MCP tools reference

The server exposes 27 MCP tools, grouped by operation type:

### Read-only tools

- **`list_devices`** — List authorized PAN-OS devices and safe metadata; never returns API keys.
- **`gather_device_facts`** — Gather hostname, model, serial, version, management IP, and uptime from an authorized device.
- **`execute_panos_op`** — Execute a read-only PAN-OS XML command rooted at `<show>` on an authorized device, with output caps.
- **`get_panos_config`** — Read running or candidate PAN-OS configuration at a validated `/config` XPath on an authorized device.
- **`list_panos_entries`** — Page through a rule or object list container's `<entry>` children as structured JSON, truncation-marked rather than erroring on a large rulebase.
- **`get_panos_entry_digest`** — Fetch and hash exactly one PAN-OS config entry by XPath, for single-rule drift detection.
- **`list_panorama_device_groups`** — List Panorama device groups and the serial numbers of their member firewalls.
- **`list_panorama_templates`** — List Panorama templates and the names of their declared variables.
- **`get_panorama_push_status`** — Read a Panorama commit-all/push job's overall and per-target-firewall status by job id.
- **`list_panos_rulebase_entries`** — List security rules, NAT rules, address objects, or service objects for a vsys as structured JSON, paginated and truncation-marked.
- **`get_panos_ha_state`** — Read PAN-OS high-availability state (enabled, mode, local and peer state) on an authorized device.
- **`get_panos_license_info`** — Read PAN-OS license status (feature, serial, issued, expires, expired) on an authorized device.
- **`get_panos_content_status`** — Read PAN-OS content version status (version, released, downloaded, current) on an authorized device.
- **`get_panos_software_status`** — Read PAN-OS software version status (version, released, downloaded, current, latest) on an authorized device.
- **`test_panos_security_policy_match`** — Test which PAN-OS security rule, if any, a simulated packet would match on an authorized device.
- **`query_panos_logs`** — Fetch a bounded window of PAN-OS logs (traffic, threat, system, or config) on an authorized device; always capped, never unbounded.

### Candidate lifecycle tools (mutation)

- **`get_candidate_fingerprint`** — Return a SHA-256 fingerprint over all operator-authorized candidate subtrees.
- **`stage_panos_config`** — Stage one policy-bounded PAN-OS candidate set/delete using an expected fingerprint.
- **`diff_panos_candidate`** — Return a bounded PAN-OS change summary for the exact staged candidate fingerprint.
- **`validate_panos_candidate`** — Validate a staged candidate and make only the same fingerprint eligible for commit.
- **`commit_panos_candidate`** — Commit only a successfully validated operation using an exact candidate fingerprint.
- **`discard_panos_candidate`** — Discard a staged operation through an admin-scoped partial candidate revert.
- **`get_panos_operation`** — Return safe status for an owned PAN-OS candidate lifecycle operation.

### Change-set tools (v0.2+)

- **`create_panos_change_set`** — Plan and persist 1-64 ordered PAN-OS candidate actions under inventory and token XPath/action scopes.
- **`approve_panos_change_set`** — Approve an unexpired exact change-set digest; self-approval is refused.
- **`get_panos_change_set`** — Return the exact actions, digest, approval, expiry, and operation state for review or recovery.
- **`apply_panos_change_set`** — Apply an independently approved exact change set under one endpoint/config lock, reverting partial failure.

Write tools require explicit token scopes; wildcard `*` grants remain read-only.

## Configuration

Three example files in [config/](config/) demonstrate the configuration surface:

- **[`devices.example.json`](config/devices.example.json)** — Device inventory with authentication, TLS validation modes (system roots, custom CA, or exact leaf pin), per-device concurrency limits, and optional admin override for candidate operations.
- **[`tokens.example.json`](config/tokens.example.json)** — Bearer-token store shape: digest-only storage, per-token device and tool allowlists, optional mutation grants (XPath roots, allowed actions), and expiry timestamps.
- **[`devices.mutation.example.json`](config/devices.mutation.example.json)** — Inventory variant demonstrating mutation-root configuration and admin-scoped candidate workflow fields.

Inventory files never hold inline credentials: each device's `api_key` is a reference — `{"type": "env", "name": "VAR_NAME"}` for an environment variable or `{"type": "file", "path": "/protected/path"}` for a mode-restricted secret file.

### Command policy (`execute_panos_op`, `test_panos_security_policy_match`)

A top-level `policy` key in the inventory file governs which operational
commands `execute_panos_op` will run, and the same gate applies to the
server-built `<test><security-policy-match>` command issued by
`test_panos_security_policy_match`:

- **`mode: "allowlist"`** (fail-closed, the default) — a command is refused
  unless it matches an entry in `allow` (or, for piped output, `allowed_pipes`).
  This is what a freshly generated inventory, or one with no `policy` section
  at all, resolves to. [`config/devices.example.json`](config/devices.example.json)
  ships a starter read-only set:

  ```json
  "policy": {
    "mode": "allowlist",
    "allow": [
      "show system info",
      "show interface all",
      "show routing route",
      "show running security-policy",
      "show session info",
      "test security-policy-match"
    ]
  }
  ```

  Allowlist entries are matched as exact element-tag paths taken from the
  command's own XML structure, not CLI text — there is no abbreviation
  expansion, so a shortened form such as `sh sys info` is refused just like
  any other command that isn't in `allow`. The `test security-policy-match`
  entry is required for `test_panos_security_policy_match` to run at all in
  allowlist mode — without it, every call is refused regardless of any other
  configuration.

- **`mode: "blocklist"`** (fail-open, legacy) — every command is allowed
  except one matching a deny rule under a device's `blocklist.commands`. An
  inventory that has deny rules but no explicit `policy.mode` key loads in
  this mode for backward compatibility, and the server logs one startup WARN
  because fail-open blocklist mode has no allowlist to fall back on if a rule
  is missing a case. New deployments should set `mode: "allowlist"` instead.

Each device may extend the shared `policy.allow` / `policy.allowed_pipes`
lists with device-specific entries via that device's own `blocklist.allow` /
`blocklist.allowed_pipes` arrays, merged the same way `blocklist.commands`
deny rules are merged today.

Every refusal — either mode — is written to the audit log with the reason
code from the underlying policy library.

## Audit logging

v0.4.0 introduces structured audit logging via the shared [`mecmcp-audit`](https://github.com/mechubsec/mecmcp) crate. One event is emitted per tool call with caller attribution, target devices, outcome, and execution duration.

Change-set lifecycle auditing provides independent evidence of approval: the `approve_panos_change_set` event carries both the change-set id and the fingerprint digest, proving that a second principal reviewed the exact digest later applied via `apply_panos_change_set`.

### Audit configuration flags

- **`--audit-format {text|json}`** — Choose `text` (default, human-readable) or `json` (machine-parseable).
- **`--audit-log-file <PATH>`** — Write audit events to a file path.
- **`--audit-journald`** — Emit audit events to the systemd journal.
- **`--audit-redact`** — HMAC-pseudonymise declared fields (device names, caller identity) so the log can be shipped to a SIEM without leaking operational identifiers.
- **`--audit-hmac-key-file <PATH>`** — Path to the HMAC key for redaction; required when `--audit-redact` is enabled.

All audit targets are optional and can be combined. When no audit target is specified, audit events are not emitted.

### Forwarding to the event store

The audit trail does not stay on this host. This server follows the family
standard — [AUDIT-FORWARDING-STANDARD.md](https://github.com/mechubsec/mecmcp/blob/main/docs/AUDIT-FORWARDING-STANDARD.md).

An audit record that only exists on the machine that produced it is not an audit
trail: it is a log file on a box whose operator is the party the record is about.

### Emission (in effect now)

```
--audit-format json \
--audit-log-file /var/lib/rust-panosmcp/audit.jsonl
```

JSON is mandatory. The `text` format is for reading in a terminal and is not a
parse target. The file is the operator-facing artifact and must be rotated — the
server never truncates it.

### Transport (specified, not yet implemented)

Records are written directly into SSDF's `ssdf.audit` as **hash-chained** rows,
per SSDF's merged evidence contract, so that deleting or editing a row is
detectable. Tracked in [mecmcp#292](https://github.com/mechubsec/mecmcp/issues/292).

A cheaper syslog path was designed and rejected: it works, but the records are
unchained, and every other link here is tamper-evident by construction — plan
digests bind approvals, approvals name a distinct principal, and
`token_verified_fields` separates vouched-for provenance from asserted. An
unchained final hop would discard that guarantee exactly where an auditor needs
it. The reasoning is recorded in the standard.

### Reading the result

`token_verified_fields` names the provenance fields the **token** vouched for.
The rest of that group — `client_name`, `model_id`, `session_id` — is
client-asserted and authenticated by nothing. Do not read them as equivalent.

`request_id` correlates the transport event, the handler event, and (on Junos)
the device commit comment.

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) for complete coverage. Key points:

- **Authentication required for HTTP** — bearer tokens with SHA-256 digest-only storage; no plaintext secrets persist.
- **Loopback-only defaults** — off-loopback HTTP requires TLS or explicit `--allow-insecure-bind`; off-loopback TLS requires `--allowed-host`.
- **TLS verification always on** — system roots, custom CA bundle, or exact leaf pin; no trust-on-first-use or disabled verification.
- **Bounded I/O** — output caps (512 KiB default, 5 MiB max), request body limits (1 MiB default), timeouts on all PAN-OS calls.
- **Audited mutations** — candidate operations serialize per device, record principal and fingerprint, require explicit commit after validation, and persist lock/job state for recovery.

## CLI reference

```text
Secure, async MCP server for PAN-OS firewalls

Usage: rust-panosmcp [OPTIONS] [COMMAND]

Commands:
  token  Manage the digest-only bearer-token store
  state  Perform offline recovery on the private mutation-state file
  help   Print this message or the help of the given subcommand(s)

Options:
  -f, --device-mapping <DEVICE_MAPPING>
          Validated JSON device inventory [default: devices.json]
  -t, --transport <TRANSPORT>
          MCP transport [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>
          Numeric bind address for Streamable HTTP [default: 127.0.0.1]
  -p, --port <PORT>
          TCP port for Streamable HTTP [default: 30031]
      --tokens-file <TOKENS_FILE>
          Absolute digest-only bearer-token file path
      --state-file <STATE_FILE>
          Absolute private JSON file for persistent change-set and operation state
      --lab-mode
          Run without two-person control: change sets are approved on creation
      --approval-timeout-secs <APPROVAL_TIMEOUT_SECS>
          Seconds a change-set approval stays valid before it expires [default: 900]
      --allow-plane-owned-writes
          Allow destructive operations on devices owned by a management plane
      --allow-direct-commit
          Allow committing an operation with no change-set approval at all
      --tls-cert <TLS_CERT>
          Absolute PEM certificate path; requires `--tls-key`
      --tls-key <TLS_KEY>
          Absolute PEM private-key path; requires `--tls-cert`
      --allow-no-auth
          Disable bearer auth for a loopback-only development listener
      --allow-insecure-bind
          Permit a non-loopback plaintext listener behind a trusted TLS proxy
      --allowed-host <ALLOWED_HOST>
          Additional accepted HTTP Host authority. Repeat for multiple values
      --allowed-origin <ALLOWED_ORIGIN>
          Accepted browser Origin URL. Repeat for multiple values
      --ip-rate-per-minute <IP_RATE_PER_MINUTE>
          Per-source-IP requests allowed per rolling minute window [default: 120]
      --token-rate-per-minute <TOKEN_RATE_PER_MINUTE>
          Per-authenticated-token requests allowed per rolling minute window [default: 240]
      --request-body-limit <REQUEST_BODY_LIMIT>
          Maximum Streamable HTTP request body in bytes [default: 1048576]
      --max-inflight-requests <MAX_INFLIGHT_REQUESTS>
          Max concurrent in-flight requests across all callers. 0 = unlimited [default: 64]
      --max-inflight-requests-per-token <MAX_INFLIGHT_REQUESTS_PER_TOKEN>
          Max concurrent in-flight requests per bearer token. 0 = unlimited [default: 16]
      --max-inflight-requests-per-target <MAX_INFLIGHT_REQUESTS_PER_TARGET>
          Max concurrent in-flight requests per target device. 0 = unlimited [default: 4]
      --max-sessions <MAX_SESSIONS>
          Max concurrent MCP sessions. 0 = unlimited [default: 128]
      --max-sessions-per-token <MAX_SESSIONS_PER_TOKEN>
          Max concurrent MCP sessions per bearer token. 0 = unlimited [default: 16]
      --enable-metrics
          Expose unauthenticated Prometheus metrics at /metrics (streamable-http only)
      --audit-format <AUDIT_FORMAT>
          Audit log format: `text` or `json` [default: text]
      --audit-log-file <AUDIT_LOG_FILE>
          Optional dedicated JSON audit log file path
      --audit-journald
          Enable journald audit sink for `target="audit"` events
      --audit-redact <AUDIT_REDACT>
          Optional per-field redaction policy (e.g., `devices=hmac,host=drop`)
      --audit-hmac-key-file <AUDIT_HMAC_KEY_FILE>
          HMAC key file for audit redaction (required if audit-redact requests hmac)
      --ssdf-audit-endpoint <SSDF_AUDIT_ENDPOINT>
          ClickHouse endpoint for the SSDF evidence sink. Enables the pipeline
      --ssdf-audit-server-id <SSDF_AUDIT_SERVER_ID>
          This writer's chain identity. Required whenever the endpoint is set
      --ssdf-audit-database <SSDF_AUDIT_DATABASE>
          ClickHouse database holding the audit table [default: ssdf]
      --ssdf-audit-user <SSDF_AUDIT_USER>
          INSERT-only write identity [default: ssdf_audit]
      --ssdf-audit-password-file <SSDF_AUDIT_PASSWORD_FILE>
          File holding the write identity's password. Must be 0600
      --ssdf-audit-verify-user <SSDF_AUDIT_VERIFY_USER>
          SELECT-only read identity, used for the high-water and tail reads [default: ssdf_audit_verify]
      --ssdf-audit-verify-password-file <SSDF_AUDIT_VERIFY_PASSWORD_FILE>
          File holding the read identity's password. Must be 0600
      --ssdf-audit-ca-file <SSDF_AUDIT_CA_FILE>
          PEM trust anchor for the ClickHouse certificate. Required for `https://`
      --ssdf-audit-outbox <SSDF_AUDIT_OUTBOX>
          Durable outbox for closed segments. Required when the endpoint is set
      --ssdf-audit-ledger <SSDF_AUDIT_LEDGER>
          Delivery ledger. Required when the endpoint is set
      --ssdf-audit-interval-secs <SSDF_AUDIT_INTERVAL_SECS>
          Seconds between delivery attempts. Must be positive [default: 30]
      --ssdf-audit-records-per-segment <SSDF_AUDIT_RECORDS_PER_SEGMENT>
          Records per segment before one is closed and spooled [default: 64]
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version

Token subcommands:
  add         Mint a token, store only its digest, and print the secret once
  list        List token names and scopes without secrets or digests
  revoke      Revoke a named token
  rotate      Replace a token secret while preserving its scopes
  set-scopes  Replace a token's scopes or mutation grant, keeping its secret

State subcommands:
  resolve  Mark an indeterminate operation terminal after manual PAN-OS reconciliation
```

### `--lab-mode`

`--lab-mode` waives the second principal, for a single-operator lab where two-person control is theatre rather than a control. **It is off by default and should stay off anywhere the estate matters.**

What it does and does not change:

- The waiver is applied automatically when the change set is created. There is no waive tool, and the flow stays create → apply, identical to production.
- Planning, the plan digest, drift detection, and apply-time revalidation all still run. Lab mode removes the second reviewer, not the change record.
- **No approver is ever fabricated.** A waived change set records `approver: null` alongside `approval_waiver: "lab-mode"`, and carries a waiver digest over `(change_set_id, plan_digest, owner, approved_at)`. It is cryptographically distinguishable from a genuine two-person approval and cannot be relabelled afterwards — which matters if anyone later has to prove which changes had real separation of duties.
- The server warns loudly at startup whenever it is enabled.

If you want solo write-testing without waiving the control, mint two tokens with different names and use one to create and the other to approve: the principal is the token name, and self-approval is refused. That gives one person the complete lifecycle with the control intact, and is the better choice wherever the ceremony has any value.

#### Enabling it

Add the flag to the service unit. On a package install, use a drop-in rather than editing the shipped unit, so an upgrade does not silently drop it:

```console
sudo systemctl edit rust-panosmcp
```

Replacing `ExecStart` means restating it in full, so **copy the shipped command and append the flag** rather than writing a shorter one. Dropping other arguments would silently change the state file location or transport settings as a side effect of enabling lab mode:

```ini
[Service]
# Clear the shipped ExecStart before replacing it; systemd appends otherwise.
ExecStart=
ExecStart=/usr/local/bin/rust-panosmcp \
    --device-mapping /etc/rust-panosmcp/devices.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30031 \
    --tokens-file /var/lib/rust-panosmcp/tokens.json \
    --state-file /var/lib/rust-panosmcp/mutation-state.json \
    --lab-mode
```

Check it against `packaging/systemd/rust-panosmcp.service` before applying it — the shipped arguments are the authority, and this snippet is a copy that can age.

```console
sudo systemctl daemon-reload && sudo systemctl restart rust-panosmcp
```

Confirm it took effect. The startup warning uses `lab mode` in the prose and `approval_waiver=lab-mode` in the outcome description:

```console
sudo journalctl -u rust-panosmcp --since='5 minutes ago' | grep -i lab
```

Expected output:

```text
Aug 15 12:34:56 host rust-panosmcp[1234]: lab mode enabled: change sets are approved on creation with no second principal. Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

### Approver tokens must be `human`

`approve_panos_change_set` only accepts a second principal whose token is marked `actor_type: human`. Tokens issued without `--actor-type` are `unknown`, and they are refused as approvers, as are `agent` tokens. Issue approver tokens with `rust-panosmcp token add ... --actor-type human`. stdio sessions carry no caller identity and **cannot approve**; approvals go over authenticated HTTP.

### `--allow-direct-commit`

`commit_panos_candidate` on an operation created by `stage_config` directly — not via `create_panos_change_set` / `approve_panos_change_set` / `apply_panos_change_set` — stages, validates, and commits in one lifecycle, with no independent second-principal review at all: there is no change set to point one at. **Off by default**: without this flag, that commit is refused before the firewall is ever touched, identically over stdio and HTTP (stdio carries no caller context at all, so it cannot be treated any more leniently than an authenticated session).

**Residual risk.** `--allow-direct-commit` is an escape hatch, not a fix. An operator who sets it has decided that running this specific path with no independent review is an acceptable risk for this deployment. That decision is:

- **Logged loudly at startup**, same as `--lab-mode` above.
- **Audited on every call.** A `commit_panos_candidate` call that ran under the flag carries `direct_commit_allowed=true` in its audit record; a refusal is audited too, as `authorization=denied` with `reason=direct_commit_disabled`.

It does not add a second-principal review; it only makes running without one visible. Prefer the change-set flow (`create_panos_change_set` → `approve_panos_change_set` → `apply_panos_change_set`) wherever your workflow can use it, and reserve this flag for operations that genuinely cannot fit that shape.

Enable it the same way as `--lab-mode`: append `--allow-direct-commit` to the service unit's `ExecStart` via a systemd drop-in, copying the shipped command in full. Confirm it took effect — unlike the lab-mode banner, this one is deliberately **not** grouped with the audit stream's per-call schema, so grep the plain startup message:

```console
sudo journalctl -u rust-panosmcp --since='5 minutes ago' | grep -i "allow-direct-commit is enabled"
```

## Validate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
scripts/verify-packaging.sh
```

Create a deterministic release archive with `scripts/build-release.sh`, or
compile it twice and require byte identity with
`scripts/verify-reproducible-build.sh`. Container/systemd installation is
documented in the operator runbook.

## License

Licensed under [MIT](LICENSE).

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>
