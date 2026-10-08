# How to run rust-panosmcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and the three failures that occurred are in [Troubleshooting](#troubleshooting)
with their exact error text.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

If you see that line and did not intend it, stop and fix the flag.

## The headline gotcha for this image

The Dockerfile is

```
ENTRYPOINT ["/usr/local/bin/rust-panosmcp", \
    "--device-mapping", "/etc/rust-panosmcp/devices.json", \
    "--tokens-file", "/var/lib/rust-panosmcp/tokens.json", \
    "--state-file", "/var/lib/rust-panosmcp/mutation-state.json", \
    "--audit-hmac-key-file", "/var/lib/rust-panosmcp/audit-hmac.key", \
    "--audit-redact", "devices=hmac"]
CMD ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "30031"]
```

All five of `--device-mapping`, `--tokens-file`, `--state-file`,
`--audit-hmac-key-file`, and `--audit-redact` are baked into ENTRYPOINT
precisely so they survive when you pass other arguments — Docker **appends**
caller arguments to ENTRYPOINT but **replaces CMD entirely**, so a flag
reachable only through CMD used to vanish the moment you set the bind address
or anything else.

**Do not pass `--device-mapping`, `--tokens-file`, `--state-file`,
`--audit-hmac-key-file`, or `--audit-redact` yourself on `docker run` /
`command:`.** Doing so duplicates the flag (once from ENTRYPOINT, once from
your argument), and the server refuses to start:

```
error: the argument '--device-mapping <DEVICE_MAPPING>' cannot be used multiple times
```

(the same error, naming the repeated flag, for any of the other four). If you
need different paths than the ones baked in, mount your files at those paths
rather than passing the flags — the paths are fixed in the image, only the
files backing them change. `--tokens-file`, `--state-file`, and
`--audit-hmac-key-file` share one directory, `/var/lib/rust-panosmcp`, so
mount that directory once and place `tokens.json` inside it;
`mutation-state.json` and `audit-hmac.key` are both created there by the
server on first run — the key is generated once, from OS entropy, and never
rotated in place, so the volume must persist across restarts or every audit
record's HMAC becomes unverifiable against the previous key.

## 1. Prepare host paths

```bash
mkdir -p panos-docker/state
cd panos-docker
```

`devices.json` follows `config/devices.example.json`. The API key can come from
the environment:

```json
{
  "version": 1,
  "devices": [
    {
      "name": "panos-demo",
      "endpoint": "https://192.0.2.20",
      "vsys": "vsys1",
      "api_key": {
        "type": "env",
        "name": "PANOS_DEMO_API_KEY"
      },
      "tags": ["lab", "read-only"]
    }
  ]
}
```

Mint a bearer token. The binary can do this on the host — no container needed.
`tokens.json` goes inside `state/`, because the image's ENTRYPOINT reads it
from `/var/lib/rust-panosmcp/tokens.json`, the same directory as the mutation
state:

```bash
rust-panosmcp token add --tokens-file ./state/tokens.json --name my-client \
    --devices '*' --tools '*' -f ./devices.json
```

The secret prints **once** and is stored hashed. `--tools '*'` resolves to
read-only tools only; write tools must be named explicitly, so a wildcard token
calling `create_panos_change_set` gets `insufficient_scope`. That is deliberate.

Then lock the modes down:

```bash
chmod 0600 devices.json state/tokens.json
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory.

**For a real deployment**, give it ownership:

```bash
sudo chown -R 65532:65532 devices.json state
sudo chmod 0700 state
```

**For local testing without root**, run the container as yourself instead. The
files stay owned by you and nothing needs `sudo`:

```bash
--user "$(id -u):$(id -g)"
```

Both are shown below. The second is what the examples here were verified with.

## 3. Pin to an immutable digest

`RepoDigests` is empty if the image has not been pulled, so `docker pull` comes
first:

```bash
docker pull ghcr.io/mechubsec/rustpanosmcp:0.16.0
image=$(docker inspect ghcr.io/mechubsec/rustpanosmcp:0.16.0 \
    --format '{{index .RepoDigests 0}}')
```

The resolved digest identifies the exact bytes — record it wherever the
deployment is tracked.

## 4. Run it — two-person mode

```bash
docker run -d --name panos-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30031:30031 \
  -e PANOS_DEMO_API_KEY=... \
  -v "$PWD/devices.json:/etc/rust-panosmcp/devices.json:ro" \
  -v "$PWD/state:/var/lib/rust-panosmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30031 --allowed-host localhost:30031 \
  --allowed-origin http://127.0.0.1:30031 --allowed-origin http://localhost:30031
```

`--tokens-file` and `--state-file` are already baked into ENTRYPOINT (see [The
headline gotcha](#the-headline-gotcha-for-this-image)) — do not pass them here.
The inventory is mounted read-only; the state directory (which holds both
`tokens.json` and the change-set lifecycle state in `mutation-state.json`) is
writable. Do not delete `mutation-state.json` while a server is running.

The `--allowed-origin http://127.0.0.1:30031` values are a working local default
for non-browser clients. A browser-based MCP client served from a different port
needs its own origin added (e.g., `--allowed-origin http://localhost:6274`).

## 5. Run it — lab mode

Identical but for `--lab-mode`, and a different published port so both can run
side by side:

```bash
docker run -d --name panos-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30041:30031 \
  -e PANOS_DEMO_API_KEY=... \
  -v "$PWD/devices.json:/etc/rust-panosmcp/devices.json:ro" \
  -v "$PWD/state:/var/lib/rust-panosmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30041 --allowed-host localhost:30041 \
  --allowed-origin http://127.0.0.1:30041 --allowed-origin http://localhost:30041 \
  --lab-mode
```

**Note the port asymmetry, because it catches people.** The server always
listens on `30031` *inside* the container; `-p 127.0.0.1:30041:30031` publishes
it as 30041 on the host, bound to loopback only. But `--allowed-host` and
`--allowed-origin` are matched against the `Host` and `Origin` headers the
**client** sends, and the client is talking to 30041. So those flags carry the
*published* port, not the internal one. Get this wrong and the server starts
cleanly and then refuses every request with `421`. The loopback bind restricts
access to localhost; reaching the server from another host requires TLS rather
than a wider publish.

Give each mode its own state directory if you run them against the same devices;
the change-set lifecycle state is shared, and two servers pointed at one state
file are two servers that can disagree about what a change set's status is.

## 6. Verify

```bash
docker ps --filter name=panos- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30031/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30041/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs panos-labmode 2>&1 | grep -i 'lab mode'
```

The server logs its rate limits at startup:

```
rate limits: max_requests_per_second_per_ip=120, per_token=240
```

These ship enabled by default. rust-junosmcp ships them disabled (`0`) for the
same shared transport, so operators comparing the two logs should expect this
difference.

## 7. Stop

```bash
docker stop panos-twoperson panos-labmode
docker rm panos-twoperson panos-labmode
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal, and the next
caller finds the device blocked.

## Troubleshooting

All three of these were hit while writing this document.

**`error: the argument '--device-mapping <DEVICE_MAPPING>' cannot be used multiple times`**
(or the same error naming `--tokens-file`, `--state-file`,
`--audit-hmac-key-file`, or `--audit-redact`)
You passed one of the ENTRYPOINT-baked flags explicitly. Drop it from
your `docker run` arguments or compose `command:` — mount your inventory file
at `/etc/rust-panosmcp/devices.json`, and put `tokens.json` inside the
directory mounted at `/var/lib/rust-panosmcp`, instead of passing the flags.
See [The headline gotcha for this image](#the-headline-gotcha-for-this-image).

**Service returns 421 `Host '<host>' is not allowed`**
`--allowed-host` does not match the address the client dials (the HTTP Host
header). The list must carry the **published** port (the one in `-p`), not the
internal one. If you published the server on 30041 but allowed only 30031,
every request fails with `421`. The server logs the rejected request with the
mismatched header value — check `docker logs`.

**Service returns 403 `Origin '<origin>' is not allowed`**
`--allowed-origin` does not match the browser application origin sending the
request (the Origin header). Add the origin of the calling page, including
scheme and port (e.g., `--allowed-origin http://localhost:6274` for a
browser-based MCP client served on that port). Clients which send no Origin
header (curl, non-browser MCP clients) are unaffected by this allowlist.

**Permission denied reading the inventory or writing state**
The container process is UID 65532 and does not own your files. Either
`chown -R 65532:65532` them, or run with `--user "$(id -u):$(id -g)"` as shown
above.
