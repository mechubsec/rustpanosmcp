# How to set up a rust-panosmcp LXC from scratch

Builds one Proxmox LXC running `rust-panosmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run, and the failures that occurred are in
[Troubleshooting](#troubleshooting) with their exact error text.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

Never point a lab-mode server at production devices. It says so itself at
startup, in a `WARN`.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The credentials the server will use.** A PAN-OS API key, a `devices.json`
  inventory, and a bearer token store. Building the container is the easy part;
  these are the part you cannot regenerate. If you are rebuilding an existing
  rig, back them up first — see [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc:

```bash
docker create --name px ghcr.io/mechubsec/rustpanosmcp:0.15.0
docker cp px:/usr/local/bin/rust-panosmcp ./rust-panosmcp
docker rm px
```

No docker? `skopeo copy docker://ghcr.io/mechubsec/rustpanosmcp:0.15.0 dir:/tmp/img`
then find the layer containing `usr/local/bin/rust-panosmcp` and untar it.

## 2. Assemble the install package

**This repository has no package-building script.** The package must be
hand-assembled. `packaging/lxc/install.sh` validates this exact payload,
computed as **two levels up from itself**:

```
bin/rust-panosmcp                         (must be executable)
packaging/systemd/rust-panosmcp.service
packaging/systemd/rust-panosmcp.sysusers
packaging/systemd/rust-panosmcp.tmpfiles
config/devices.example.json
```

Assemble it:

```bash
cd /path/to/rust-panosmcp
mkdir -p bin
install -m 0755 ./rust-panosmcp bin/rust-panosmcp
tar czf rust-panosmcp_0.15.0.tar.gz \
    bin/rust-panosmcp \
    packaging/systemd/rust-panosmcp.service \
    packaging/systemd/rust-panosmcp.sysusers \
    packaging/systemd/rust-panosmcp.tmpfiles \
    config/devices.example.json
```

> **Note.** Unlike `rust-junosmcp`, which ships `scripts/package-lxc.sh` with
> `JMCP_PACKAGE_SKIP_BUILD=1`, this repo has no packager. The tarball is
> hand-assembled as above.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 612 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-panos \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 612
```

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

For the lab-mode rig, use VMID 613, hostname `test-labmode-panos`,
IP `192.0.2.11`, and tag `labmode` instead of `twoperson`.

## 4. Install

**`install.sh` is committed mode 0644, not executable.** Running
`./packaging/lxc/install.sh` fails with `Permission denied`. Invoke it as
`bash ./packaging/lxc/install.sh`.

```bash
pct push 612 rust-panosmcp_0.15.0.tar.gz /tmp/pkg.tar.gz
pct exec 612 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && bash ./packaging/lxc/install.sh'
```

`install.sh` creates the `rust-panosmcp` service user, installs the binary and
the unit, and stops there. **The service will not start yet** — it has no
inventory, and it says so.

## 5. Configuration and credentials

Place the inventory, the API key, and the tokens:

```bash
pct push 612 devices.json   /etc/rust-panosmcp/devices.json
pct push 612 api-key        /etc/rust-panosmcp/api-key
pct push 612 tokens.json    /var/lib/rust-panosmcp/tokens.json
```

Then fix ownership and modes. **Do this for every credential file at once.** The
server refuses to start on any file that is group- or world-readable, and it
checks them one at a time — so getting this wrong costs you one restart per file:

```bash
pct exec 612 -- bash -lc '
    chown -R rust-panosmcp:rust-panosmcp /etc/rust-panosmcp
    chown -R rust-panosmcp:rust-panosmcp /var/lib/rust-panosmcp
    chmod 0600 /etc/rust-panosmcp/devices.json
    chmod 0600 /etc/rust-panosmcp/api-key
    chmod 0600 /var/lib/rust-panosmcp/tokens.json
'
```

## 6. The site drop-in

**`install.sh` does not create `/etc/systemd/system/rust-panosmcp.service.d/`.**
You must `mkdir -p` it. Site configuration goes in a drop-in, which keeps the
shipped unit replaceable — the shipped unit carries the seccomp posture
(`SystemCallErrorNumber=EPERM`), and replacing it wholesale silently loses that.

```bash
pct exec 612 -- mkdir -p /etc/systemd/system/rust-panosmcp.service.d
```

`/etc/systemd/system/rust-panosmcp.service.d/override.conf` for the
**two-person** rig:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rust-panosmcp \
    --device-mapping /etc/rust-panosmcp/devices.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30031 \
    --tokens-file /var/lib/rust-panosmcp/tokens.json \
    --state-file /var/lib/rust-panosmcp/mutation-state.json \
    --allow-insecure-bind \
    --allowed-host 192.0.2.10 \
    --allowed-host test-twoperson-panos:30031 \
    --allowed-origin http://console.example.org
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one.

**Lab mode is the same file with `--lab-mode` appended and the two `--allowed-host`
values changed to the lab rig's own authority** (e.g., `192.0.2.11` and
`test-labmode-panos:30031`).

`--allowed-host` lists the server authorities clients dial (the HTTP Host header);
`--allowed-origin` lists the trusted browser application origins that call this
server (the Origin header). They are configured independently and are usually
different values. For example, a browser console at `http://console.example.org`
calling this server at `192.0.2.10:30031` sends `Origin: http://console.example.org`,
so the allowlist must contain that origin. An off-loopback listener requires at
least one `--allowed-origin` or the service refuses to start — replace the example
value with your actual client origin. The origin scheme must match the server's
TLS configuration: this plaintext lab drop-in (`--allow-insecure-bind`) takes
`http://` origins; an HTTPS console origin requires `--tls-cert` and `--tls-key`
on the listener. Clients which send no Origin header (curl, non-browser MCP
clients) are unaffected by the origin allowlist.

Then:

```bash
pct exec 612 -- systemctl daemon-reload
pct exec 612 -- systemctl enable --now rust-panosmcp.service
```

## 7. Mint a token

```bash
pct exec 612 -- runuser -u rust-panosmcp -- /usr/local/bin/rust-panosmcp token add \
    --tokens-file /var/lib/rust-panosmcp/tokens.json \
    --name my-client --devices '*' --tools '*' \
    -f /etc/rust-panosmcp/devices.json
```

The secret is printed **once** and stored hashed. Two things worth knowing:

- A running server holds its token store in memory. A newly minted or revoked
  token does nothing until the server is signalled:
  `systemctl kill -s HUP rust-panosmcp.service`. The CLI warns you about this.
- `--tools '*'` is a wildcard that resolves to *read-only tools only*. Write
  tools must be named explicitly, so a wildcard token calling
  `create_panos_change_set` gets `insufficient_scope`. That is deliberate.

## 8. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 612 -- /usr/local/bin/rust-panosmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 612 -- systemctl show rust-panosmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 612 -- grep -l SystemCallErrorNumber /etc/systemd/system/rust-panosmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 612 -- systemctl show -p MainPID --value rust-panosmcp.service)
pct exec 612 -- grep -E '^Seccomp' /proc/$pid/status                                    # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.10:30031/mcp \
     -H 'content-type: application/json' -d '{}'                                        # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

Checking `SystemCallErrorNumber` matters. Without it a denied syscall raises
SIGSYS and kills the process mid-request instead of returning `EPERM`; that
seccomp posture fix is critical, and reading it back from the unit is how you
know it is present.

## 9. Stop the rig

Test rigs on this fleet are stopped by default — started only when needed,
stopped again at completion:

```bash
pct shutdown 612
```

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 612
cp -a /var/lib/lxc/612/rootfs/etc/rust-panosmcp           /root/backup-612/
cp -a /var/lib/lxc/612/rootfs/var/lib/rust-panosmcp       /root/backup-612/
cp -a /var/lib/lxc/612/rootfs/etc/systemd/system/rust-panosmcp.service.d /root/backup-612/
pct config 612 > /root/backup-612/pct-config.txt
pct unmount 612
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

## Troubleshooting

These were hit during the rebuild this document is written from.

**`mode 0644 is group- or world-accessible (owner uid 999, this process uid 999); run: chmod 600 /etc/rust-panosmcp/devices.json`**
A credential file is too permissive. The message names the file and the exact
fix. It is checked per file, so fix them all at once (step 5) or you will meet
this again for the next one.

**`/bin/bash: line 1: ./packaging/lxc/install.sh: Permission denied`**
`install.sh` is committed mode 0644, not executable. Invoke it as
`bash ./packaging/lxc/install.sh` instead of `./packaging/lxc/install.sh`.

**`failed to create file: /etc/systemd/system/rust-panosmcp.service.d/override.conf: No such file or directory`**
The drop-in directory does not exist yet. `install.sh` does not create it,
because a drop-in is a site decision. `mkdir -p` it first.

**Service fails immediately with `Error: non-loopback bind '<host>' requires
at least one --allowed-origin`** —
The drop-in has no origin allowlist. An off-loopback listener must supply at
least one `--allowed-origin` value. This is the trusted browser application
origin (the Origin header), including the scheme (`http://` or `https://`) and
port (e.g., `--allowed-origin http://console.example.org`).

**Service active but every call returns 421 `Host '<host>' is not allowed`** —
`--allowed-host` does not match the address clients dial (the HTTP Host header).
Add the exact host and port they use.

**Service active but every call returns 403 `Origin '<origin>' is not allowed`** —
`--allowed-origin` does not match the browser application origin sending the
request (the Origin header). Add the origin of the calling page, including scheme
and port. Non-browser clients (curl, CLI MCP clients) send no Origin header and
are unaffected by this allowlist.
