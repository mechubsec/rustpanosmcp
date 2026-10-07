# Operator runbook

This runbook covers the Phase 4 systemd and container packages. Read
`PHASE1_OPERATIONS.md`, `PHASE2_OPERATIONS.md`, and `PHASE3_OPERATIONS.md`
before enabling device access, remote HTTP, or mutation respectively.

## Release verification

Release archives contain `BUILD-INFO` and a sibling `.sha256` file. Verify the
checksum before extracting and compare the recorded Git commit with the release
you approved:

```bash
sha256sum --check rust-panosmcp-v0.16.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf rust-panosmcp-v0.16.0-x86_64-unknown-linux-gnu.tar.gz
cat rust-panosmcp-v0.16.0/BUILD-INFO
```

The build uses `Cargo.lock`, a fixed Rust MSRV, path remapping, a fixed source
date, deterministic tar ordering/ownership/timestamps, and no incremental
compilation. `scripts/verify-reproducible-build.sh` compiles twice in isolated
target directories and requires byte-identical archives. The container pins
both multi-architecture base-image indexes by digest; treat a digest refresh as
a dependency upgrade requiring CI and image scanning.

## systemd installation

Install the archive and create the static unprivileged account/directories:

```bash
install -o root -g root -m 0755 bin/rust-panosmcp /usr/local/bin/rust-panosmcp
install -o root -g root -m 0644 packaging/systemd/rust-panosmcp.service \
  /etc/systemd/system/rust-panosmcp.service
install -o root -g root -m 0644 packaging/systemd/rust-panosmcp.sysusers \
  /usr/lib/sysusers.d/rust-panosmcp.conf
install -o root -g root -m 0644 packaging/systemd/rust-panosmcp.tmpfiles \
  /usr/lib/tmpfiles.d/rust-panosmcp.conf
systemd-sysusers /usr/lib/sysusers.d/rust-panosmcp.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/rust-panosmcp.conf
```

Install a root-owned inventory that is not group/other writable. API-key files,
TLS private keys, and the token store must be owned by `rust-panosmcp` (or root
when the service can read them) and mode 0600. CA bundles and certificates may
be root-owned 0644.

```bash
install -o root -g rust-panosmcp -m 0640 devices.json \
  /etc/rust-panosmcp/devices.json
install -o rust-panosmcp -g rust-panosmcp -m 0600 panos-api.key \
  /etc/rust-panosmcp/panos-api.key
```

Generate the audit HMAC key, required for device-name redaction in audit logs.
The packaged unit enables `--audit-redact devices=hmac` unconditionally and will
not start without this file. Never regenerate the key on upgrade — a new key
invalidates verification of every prior audit record.

```bash
# Guarded: never overwrite an existing key — doing so breaks correlation of
# HMAC-redacted device identifiers with all audit history already written.
[ -f /etc/rust-panosmcp/audit-hmac.key ] ||
  head -c 32 /dev/urandom | base64 | install -o rust-panosmcp -g rust-panosmcp -m 0600 /dev/stdin \
    /etc/rust-panosmcp/audit-hmac.key
```

Mint the initial read token as the service account so atomic rotations preserve
ownership. Capture stdout directly into a secret manager:

```bash
sudo -u rust-panosmcp /usr/local/bin/rust-panosmcp \
  -f /etc/rust-panosmcp/devices.json token add \
  --tokens-file /var/lib/rust-panosmcp/tokens.json \
  --name initial-reader --devices panosvm \
  --tools list_devices,gather_device_facts,execute_panos_op,get_panos_config
```

The packaged unit listens only on loopback with bearer authentication and is
intended for a same-host TLS reverse proxy. If native TLS is preferred, create a
systemd drop-in that replaces `ExecStart` with explicit `--tls-cert`,
`--tls-key`, `--allowed-host`, and `--allowed-origin` arguments. Never expose
the packaged loopback/plaintext listener through host networking or a port
forward.

```bash
systemctl daemon-reload
systemctl enable --now rust-panosmcp
systemctl status rust-panosmcp
journalctl -u rust-panosmcp --since today
systemd-analyze security rust-panosmcp.service
```

The unit has no capabilities, a read-only operating-system and configuration
tree, a single writable state directory, private temporary/devices namespaces,
kernel and namespace protections, syscall/address-family restrictions, and
bounded tasks/file descriptors.

### Native TLS renewal for a private-address hostname

When the listener hostname resolves only on private DNS, use ACME DNS-01 rather
than HTTP-01. Keep the DNS provider credential off the application host when
possible. In the lab, certbot and its mode-0600 Cloudflare credential live on
the Proxmox host; the deploy hook `scripts/deploy-lab-certificate.sh` validates the
chain, hostname, and key pair before using `pct push` to atomically replace the
certificate on the lab LXC. A failed service restart restores the previous pair.

Test issuance and deployment separately:

```bash
certbot renew --dry-run
RUST_PANOSMCP_LAB_VMID=<vmid> \
RUST_PANOSMCP_CERT_HOST=rust-panosmcp.example.net \
RENEWED_LINEAGE=/etc/letsencrypt/live/rust-panosmcp.example.net \
  /etc/letsencrypt/renewal-hooks/deploy/rust-panosmcp-lxc
curl --fail-with-body https://rust-panosmcp.example.net:30031/mcp
```

The unauthenticated MCP request is expected to return HTTP 401 after TLS
verification succeeds. Never use `--insecure` as a health check. Rotate a DNS
API token immediately if its plaintext reaches logs, terminal capture, or an
unapproved secret store.

## Audit log rotation

When `--audit-log-file` is set, the server keeps the `AuditFileSink` handle
`init_tracing` returns and reopens it by path — alongside the existing
`devices.json`/`tokens.json` hot reload — whenever it receives `SIGHUP`
(`spawn_reload_handler` in `rust-panosmcp/src/main.rs`). A failed reopen (bad
path, permissions) `warn`-logs and keeps the previous sink; it does not stop
the server or block the inventory/token reload.

Install the shipped fragment for rename-mode rotation, not `copytruncate`:
logrotate renames the file, then signals the process through `postrotate`, and
every write after that lands in a fresh inode at the same path. Nothing
written before the rename is truncated and nothing written after it is lost —
`copytruncate` copies the file and then truncates it in place, dropping
whatever is written in the gap between those two steps.

```bash
install -o root -g root -m 0644 packaging/logrotate/rustpanosmcp-audit \
  /etc/logrotate.d/rustpanosmcp-audit
logrotate -d -f /etc/logrotate.d/rustpanosmcp-audit   # dry run
```

## Container installation

The final image is distroless: it has no shell or package manager and runs as
UID/GID 65532. The provided Compose example enables native TLS, a read-only root
filesystem, all-capability drop, no-new-privileges, a PID limit, and a small
no-exec tmpfs.

Prepare one bind-mounted `runtime` directory. Inventory and certificates can be
root-owned and read-only. Files classified as secrets must be readable only by
container UID 65532; a typical rootful-host setup uses owner 65532 and mode
0600. Mount the directory, not individual files, so an atomic token-store
replacement is visible in the container.

```bash
docker compose -f packaging/container/compose.example.yaml up -d
docker compose -f packaging/container/compose.example.yaml kill -s SIGHUP rust-panosmcp
```

Do not add a shell to the production image for diagnostics. Use the same image
with higher Rust logging, external network capture under change control, or a
separately identified debug image. Keep the production root filesystem
read-only.

## Zero-downtime bearer-token rotation

Prefer overlapping add/deploy/revoke over in-place rotate:

1. Add `client-next` with the minimum exact scopes and reload using
   `--server-pid` or `systemctl reload rust-panosmcp`.
2. Deliver the one-time plaintext to the client secret manager.
3. Confirm successful calls and audit attribution under `client-next`.
4. Revoke the old token and reload.
5. Confirm the old token returns HTTP 401 and retain only non-secret audit
   evidence.

`token rotate` immediately replaces the previous secret and is appropriate only
when the client and server can change as one transaction. Wildcard tool scope
never grants mutation tools.

## PAN-OS API-key lifetime and rotation

An API key's lifetime is governed by the firewall's **API Key Lifetime**
setting (Device > Setup > Management > Authentication Settings): a positive
value expires the key that many minutes after it was generated, and `0` —
the factory default — means the key never expires on its own. Do not rely on
the default; set an explicit lifetime under change control so a leaked or
forgotten key is not valid forever. The CLI/Panorama-template equivalent of
this setting varies by PAN-OS release; confirm the exact command against
your device's PAN-OS documentation rather than assuming one form works
across releases.

Independent of that setting, a key also stops working when: the issuing
administrator account is disabled/deleted; its password changes (the key is
derived from the account credential); an administrator explicitly revokes it
(via the **Expire All API Keys** Web UI/Panorama action, which revokes every
key on the device at once); or the API Key Certificate switch below
invalidates it. In every one
of these cases the firewall rejects the key with an HTTP-level 401/403 (not
an HTTP 200 wrapping an XML error code), which this server's `panos_auth`
`/readyz` check treats as an auth failure (see below) — so an expired or
revoked key is visible operationally even before rotation.

**Prefer a file-based key over an environment-variable key.** Both
`api_key.type` values (`file`, `env`) are supported in inventory (see
`config/devices.example.json`). Only the file source rotates without a
process restart: `spawn_reload_handler` in `rust-panosmcp/src/main.rs`
answers `SIGHUP` by calling `RuntimeState::reload`, which re-reads the
key file from disk and swaps in the new client atomically. An
environment-variable value is fixed at process exec time — a running
process cannot observe a change to its own environment, so rotating an
`env`-sourced key requires a full restart (and the brief availability gap
that implies), while rotating a `file`-sourced key is `write key,
reload, verify` with no restart. Use `env` only where the deployment
platform (e.g. a container orchestrator with its own atomic secret
mount) already gives you restart-free rotation another way.

Rotation procedure: use a dedicated, unshared, least-privilege PAN-OS
administrator. Generate a new key under change control, replace the
protected key file atomically with owner and mode preserved, then reload.
Run `gather_device_facts` before revoking the old credential when PAN-OS
permits overlap; otherwise schedule the brief cutover. Inspect PAN-OS
administrator logs and rust-panosmcp audit events. A reload validates
files and policy but cannot prove a new key to the firewall until a
request is made — watch `GET /readyz`, which fails the check named
`panos_auth` as soon as any device's most recent request comes back an
HTTP 401/403 rejection (an invalid, expired, or revoked key) or a PAN-OS
XML API `session-timed-out` (code 22), and recovers on the next successful
request. PAN-OS XML API code 16 ("unauthorized") does *not* fail this
check on its own: PAN-OS also uses it when a valid key's role lacks rights
for a specific command, which a correctly-scoped least-privilege key (see
"Least-privilege PAN-OS roles" below) can trigger routinely, and treating
it as a key failure would flap `/readyz` for the whole server on ordinary
role-scoped traffic. `/readyz` starts (and stays) healthy for a device
that has made no request yet; it reports proven failure, not silence, and
only reacts to real MCP tool traffic — it does not itself poll the device,
so a key that goes bad while a device is otherwise idle is not detected
until the next tool call reaches it.

### The API Key Certificate switch

PAN-OS added an **API Key Certificate**-backed API key mode
(Device > Setup > Management > Authentication Settings on modern
releases). Two behaviors matter here:

- **Enabling it invalidates every existing API key on the device** — the
  switch is not additive. Rotating in the new mode is a full-cutover
  operation: mint new keys under the new mode for every account this
  server authenticates as, stage them to file-based inventory entries,
  reload, and verify `/readyz` and `gather_device_facts` before removing
  the old keys from the secret store.
- **PAN-OS 13.0 disables legacy (non-certificate-backed) API keys
  outright.** An inventory still pointing at a legacy key stops
  authenticating the moment the device upgrades to 13.0, with no
  gradual deprecation window from this server's point of view — the
  first request after the upgrade returns `unauthorized` and flips
  `/readyz`. Plan the switch to API Key Certificate mode as part of any
  PAN-OS 13.0 upgrade, not after it.

## Backup and restore

Back up, encrypted and access-controlled:

- the exact release archive/checksum and systemd overrides or container digest;
- inventory, CA bundles/pins, TLS certificate/private key, and digest-only
  bearer-token store;
- PAN-OS API keys in the approved secret manager, separately from inventory;
- durable audit logs and the documented PAN-OS administrator/role definition.

Configure `--state-file /var/lib/rust-panosmcp/mutation-state.json` and include
that private mode-0600 file in the encrypted backup. It contains exact planned
XML payloads as well as operation metadata and must be protected like candidate
configuration. Before backup, upgrade, or disaster recovery, stop new writes
and reconcile every active validation/commit job and configuration lock on
PAN-OS. Restore files with their documented ownership/modes, validate the
checksum, start the same binary/image, perform read-only health calls, inspect
candidate changes and locks, and only then re-enable write tokens.

## Upgrade and rollback

1. Read the release notes/security advisory and verify checksum or image digest.
2. Run the mock gates and the applicable real PAN-OS release-family matrix.
3. Drain mutation clients and reconcile jobs, candidate changes, and config
   locks. Record an encrypted backup.
4. For systemd, stop the service, atomically replace the binary/package assets,
   run `systemctl daemon-reload`, and start. For containers, pull by approved
   digest and recreate without changing read-only mounts/security options.
5. Confirm version, read tools, bearer refusal behavior, audit delivery, and
   PAN-OS candidate/lock state before restoring write traffic.

Rollback uses the previous verified binary/image and matching configuration.
Never roll back by retrying an operation whose commit result is unknown. Follow
the indeterminate-commit procedure in `PHASE3_OPERATIONS.md` first.

## Monitoring and incident recovery

Alert on repeated 401/403/429 responses, reload failures, PAN-OS API errors,
validation/commit failures, indeterminate operations, stale config locks,
unexpected token names, loss of audit-log delivery, and `GET /readyz`
reporting the `panos_auth` check failed (see
[PAN-OS API-key lifetime and rotation](#pan-os-api-key-lifetime-and-rotation)).
Request and mutation events intentionally omit credentials and payloads;
preserve them in a durable, access-controlled sink.

For the PAN-OS-side least-privilege administrator accounts and management-
interface source-IP restriction this deployment should already have in
place, see [PANOS_ADMIN_ROLES.md](PANOS_ADMIN_ROLES.md).

For suspected credential exposure, follow `SECURITY.md`. For process loss during
mutation, keep write clients disabled, inspect PAN-OS jobs/change summary/locks,
and reconcile manually before restart or discard. A successful process start is
not proof that the PAN-OS candidate is clean.

If a commit or discard succeeds on PAN-OS but configuration-lock removal
fails, v0.2.1 persists the operation as `indeterminate` with
`config_lock_held: true` and returns an error. Do not retry the mutation. Verify
the job, candidate fingerprint, and live PAN-OS lock, remove the lock if
required, then use the exact offline-resolution confirmation documented in
`PHASE3_OPERATIONS.md`.

## Egress filtering

The packaged unit declares `IPAddressDeny` to block egress to cloud metadata
and link-local ranges. However, **systemd cannot enforce these directives in an
unprivileged LXC** — every guest in this fleet is one. systemd implements them
with cgroup BPF and fails open when it cannot load the program, so the unit can
declare a full egress policy while enforcing none of it. `systemd-analyze
security` reads the declaration and cannot tell the difference.

The installer probes actual enforcement and prints one of four verdicts:

- `egress filter: ENFORCED` — the host attaches the BPF program *and* the
  installed unit declares a policy
- `egress filter: NOT ENFORCED` — the host cannot attach it; guidance follows
- `egress filter: NO POLICY` — the host could enforce, but the installed unit
  declares no `IPAddressDeny` (a preserved customized unit overrides the
  packaged one; re-install with `PANOSMCP_FORCE_UNIT=1` to restore it)
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

Both conditions matter. A host-capability check alone would report success over
a service filtering nothing.

The probe uses IP accounting, which rides the same BPF attachment, so a
populated counter proves the filter attached. Check it any time:

```console
systemctl show rust-panosmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`PANOSMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse anything short
of `ENFORCED` — including `UNKNOWN`, since an unmeasurable host is exactly as
unguaranteed as a non-enforcing one.

### Enforcing it where systemd cannot

Any result other than `ENFORCED` means the unit directives are **unproven**, and
the control should move outward — to whatever layer actually sees this
workload's packets. `NOT ENFORCED` and `NO POLICY` mean they are demonstrably
doing nothing; `UNKNOWN` means nothing was measured and they may well be
working. Do not treat the last as the first.

The policy does not change with the runtime:

1. deny `169.254.0.0/16` and `fd00:ec2::254` — cloud metadata, the route from a
   compromised HTTP client to a stolen credential
2. deny link-local (`fe80::/10`) — not used by any supported target
3. deny the local subnet **except** your DNS resolver — blocks lateral movement
   while keeping name resolution working (not currently declared in this
   server's unit; add via drop-in if needed)

The mechanism does. Configure it with your platform's own documentation rather
than a recipe here — these are the layers, not instructions:

| Runtime | Layer that sees this workload's packets |
|---|---|
| Proxmox LXC / VM | per-guest interface firewall |
| libvirt / KVM | `nwfilter` on the guest interface |
| Kubernetes | `NetworkPolicy` egress, on a CNI that implements it |
| Cloud instance | in-guest packet filter for **both** metadata addresses, plus security groups for everything else |
| Bare metal, VM with working systemd | the unit directives; this section does not apply |

Two properties are worth checking whatever you choose, because both are common
and both produce a control that reads as present and is not:

- **Some layers accept egress policy without enforcing it.** Container network
  attachment and some CNI implementations are the usual cases.
- **Cloud metadata often bypasses the cloud firewall.** On EC2, IMDS traffic is
  handled below the security group and NACL layer, so an egress rule there does
  not block it. This applies to the IPv6 endpoint too — `fd00:ec2::254` is ULA
  rather than link-local, so it is easy to file mentally under "ordinary routed
  traffic the firewall sees", and it is not. The control has to be in-guest, or
  IMDS disabled outright. Consult your provider's current metadata-hardening
  guidance; it changes, and getting it wrong is silent.

Whichever you pick, a rule that has not been exercised from inside the workload
is an assumption. Verify it, and re-verify after a reboot — in-kernel firewall
rules are not persistent unless you made them so.
