#!/usr/bin/env bash
# Installer for the extracted rust-panosmcp LXC package.
set -euo pipefail

# The script ships at <package>/packaging/lxc/install.sh, so the package root is
# two levels up — not the script's own directory. Getting this wrong makes the
# installer refuse a perfectly good archive with "package payload is missing
# bin/rust-panosmcp".
PACKAGE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
INSTALL_ROOT="${PANOSMCP_INSTALL_ROOT:-/}"
SERVICE_USER="${PANOSMCP_SERVICE_USER:-rust-panosmcp}"
SERVICE_GROUP="${PANOSMCP_SERVICE_GROUP:-rust-panosmcp}"
SKIP_USER_SETUP="${PANOSMCP_INSTALL_SKIP_USER:-0}"
SKIP_SYSTEMD_RELOAD="${PANOSMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}"
SKIP_RUNTIME_DEPS="${PANOSMCP_INSTALL_SKIP_RUNTIME_DEPS:-0}"
FORCE_UNIT="${PANOSMCP_FORCE_UNIT:-0}"

fail() {
    echo ">> Installation refused: $*" >&2
    exit 1
}

# Remove any generated-content temp file left behind by a failed run.
cleanup_tmp_files() {
    rm -f "${tokens_tmp:-}" "${audit_key_tmp:-}"
}
trap cleanup_tmp_files EXIT

# Refuse to operate on a path that is not a plain file, so a caller never
# chmod/chown/writes through whatever unexpected entry happens to sit at a
# destination this installer does not fully control.
require_regular_file() {
    local path="$1"
    if [[ -L "$path" ]] || { [[ -e "$path" ]] && [[ ! -f "$path" ]]; }; then
        fail "$path is not a regular file; refusing"
    fi
}

# chmod a file that may already be owned by the service account, running the
# chmod as that account rather than as root so the operation never has more
# reach than the account already has. Fresh-install paths are still
# root-owned at this point and fall back to a root-run chmod.
secure_chmod() {
    local mode="$1" path="$2"
    local owner=""
    owner="$(stat -c '%U' "$path" 2>/dev/null || true)"
    if [[ "$SKIP_USER_SETUP" != "1" && "$owner" == "$SERVICE_USER" ]]; then
        runuser -u "$SERVICE_USER" -- chmod "$mode" "$path"
    else
        chmod "$mode" "$path"
    fi
}

target_path() {
    local relative="${1#/}"
    if [[ "$INSTALL_ROOT" == "/" ]]; then
        printf '/%s\n' "$relative"
    else
        printf '%s/%s\n' "${INSTALL_ROOT%/}" "$relative"
    fi
}

# Prove whether systemd's IPAddress* filters actually attach here, rather than
# assuming the unit's declaration means anything. systemd implements them with
# cgroup eBPF and FAILS OPEN when it cannot load the program -- typical in an
# unprivileged LXC without host delegation -- so the unit can declare a full
# egress policy while enforcing none of it. `systemd-analyze security` reads the
# declaration and cannot tell the difference.
#
# Informational by default: a runtime that withholds BPF is a legitimate
# deployment, and the operator needs to know rather than be blocked. Set
# PANOSMCP_REQUIRE_EGRESS_FILTER=1 to make a non-enforcing host fatal.
egress_probe_unknown() {
    local require=$1 reason=$2
    printf '%s\n' "egress filter: UNKNOWN ($reason)" >&2
    # Strict mode must not accept what it could not measure. An unmeasurable
    # host is exactly as unguaranteed as a non-enforcing one.
    [[ "$require" == 1 ]] \
        && fail 'PANOSMCP_REQUIRE_EGRESS_FILTER=1 and egress enforcement could not be determined'
    return 0
}

report_egress_enforcement() {
    local require=${PANOSMCP_REQUIRE_EGRESS_FILTER:-0}
    local probe_unit="rust-panosmcp-egress-probe-$$"
    local unit_path="$UNIT_DIR/rust-panosmcp.service"

    if ! command -v systemd-run >/dev/null; then
        egress_probe_unknown "$require" 'systemd-run unavailable; cannot probe'
        return $?
    fi

    # Two independent conditions have to hold, and conflating them is how the
    # previous version overstated its result:
    #   1. the host can attach the cgroup BPF program at all, and
    #   2. the *installed* unit actually declares an egress policy.
    # A transient probe only establishes (1). If the installer preserved a
    # customized unit with no IPAddressDeny, (1) alone would still have printed
    # ENFORCED and satisfied the strict flag over a service filtering nothing.
    local counters=''
    if systemd-run --quiet --collect --unit="$probe_unit" \
        --property=IPAccounting=yes --property=RemainAfterExit=yes \
        /bin/true >/dev/null 2>&1
    then
        counters=$(systemctl show "$probe_unit.service" -p IPEgressBytes --value 2>/dev/null || printf '')
        systemctl stop "$probe_unit.service" >/dev/null 2>&1 || true
        systemctl reset-failed "$probe_unit.service" >/dev/null 2>&1 || true
    else
        egress_probe_unknown "$require" 'probe unit would not start; run as root to determine'
        return $?
    fi

    if [[ -z "$counters" || "$counters" == '[no data]' ]]; then
        printf '%s\n' \
            'egress filter: NOT ENFORCED' \
            '  systemd cannot attach its cgroup BPF program here, so the IPAddressAllow/' \
            '  IPAddressDeny lines in rust-panosmcp.service have no effect. This is normal in' \
            '  an unprivileged LXC. The unit still applies every other sandbox directive.' \
            '  Move the control outward to whatever layer sees this workload'"'"'s packets --' \
            '  guest firewall, host nftables, NetworkPolicy, or cloud security group -- and' \
            '  deny 169.254.0.0/16 plus the local subnet except your resolver, allow 443 out.' \
            '  docs/OPERATIONS.md, "Enforcing it where systemd cannot", has the per-runtime' \
            '  mechanism and a verification command.' >&2
        [[ "$require" == 1 ]] \
            && fail 'PANOSMCP_REQUIRE_EGRESS_FILTER=1 and systemd IP filtering is not enforced here'
        return 0
    fi

    # (1) holds. Now (2): does the unit that was actually installed carry a
    # policy for the kernel to enforce?
    if ! grep -Eq '^[[:space:]]*IPAddressDeny[[:space:]]*=[[:space:]]*[^[:space:]]' "$unit_path"; then
        printf '%s\n' \
            'egress filter: NO POLICY' \
            "  This host can enforce systemd IP filtering, but $unit_path declares no" \
            '  IPAddressDeny. A preserved customized unit overrides the packaged policy;' \
            '  re-install with PANOSMCP_FORCE_UNIT=1 or add the directives by hand.' >&2
        [[ "$require" == 1 ]] \
            && fail 'PANOSMCP_REQUIRE_EGRESS_FILTER=1 and the installed unit declares no egress policy'
        return 0
    fi

    printf '%s\n' 'egress filter: ENFORCED'
    return 0
}

required_files=(
    bin/rust-panosmcp
    packaging/systemd/rust-panosmcp.service
    packaging/systemd/rust-panosmcp.sysusers
    packaging/systemd/rust-panosmcp.tmpfiles
    config/devices.example.json
)

# Validate the complete payload before creating users, directories, or files.
for relative in "${required_files[@]}"; do
    [[ -s "$PACKAGE_ROOT/$relative" ]] || fail "package payload is missing $relative"
done
[[ -x "$PACKAGE_ROOT/bin/rust-panosmcp" ]] \
    || fail "package binary is not executable: bin/rust-panosmcp"

[[ "$INSTALL_ROOT" == /* ]] || fail "PANOSMCP_INSTALL_ROOT must be an absolute path"
if [[ "$INSTALL_ROOT" != "/" && "$SKIP_USER_SETUP" != "1" ]]; then
    fail "a staged install requires PANOSMCP_INSTALL_SKIP_USER=1"
fi
if [[ "$SKIP_USER_SETUP" != "1" && "$EUID" -ne 0 ]]; then
    fail "run as root, or use PANOSMCP_INSTALL_SKIP_USER=1 for a staged smoke test"
fi

BIN_DIR="$(target_path /usr/local/bin)"
CONFIG_DIR="$(target_path /etc/rust-panosmcp)"
UNIT_DIR="$(target_path /etc/systemd/system)"
STATE_DIR="$(target_path /var/lib/rust-panosmcp)"
SYSUSERS_DIR="$(target_path /usr/lib/sysusers.d)"
TMPFILES_DIR="$(target_path /usr/lib/tmpfiles.d)"

# Create service user and directories via systemd-sysusers and systemd-tmpfiles.
if [[ "$SKIP_USER_SETUP" != "1" ]]; then
    command -v systemd-sysusers >/dev/null 2>&1 \
        || fail "systemd-sysusers is required for user/group creation"
    command -v systemd-tmpfiles >/dev/null 2>&1 \
        || fail "systemd-tmpfiles is required for directory creation"

    install -d -m 0755 "$SYSUSERS_DIR" "$TMPFILES_DIR"
    install -m 0644 "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.sysusers" \
        "$SYSUSERS_DIR/rust-panosmcp.conf"
    install -m 0644 "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.tmpfiles" \
        "$TMPFILES_DIR/rust-panosmcp.conf"

    systemd-sysusers rust-panosmcp.conf
    systemd-tmpfiles --create rust-panosmcp.conf
fi

install -d -m 0755 "$BIN_DIR" "$UNIT_DIR"

# Install the binary.
install -m 0755 "$PACKAGE_ROOT/bin/rust-panosmcp" "$BIN_DIR/rust-panosmcp"

# Check for site-customized unit and refuse to overwrite unless FORCE_UNIT=1.
SHIPPED_UNIT="$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service"
INSTALLED_UNIT="$UNIT_DIR/rust-panosmcp.service"
UNIT_CHANGED=0

if [[ -e "$INSTALLED_UNIT" ]]; then
    if ! cmp -s "$SHIPPED_UNIT" "$INSTALLED_UNIT"; then
        UNIT_CHANGED=1
    fi
fi

if [[ "$UNIT_CHANGED" -eq 1 && "$FORCE_UNIT" != "1" ]]; then
    echo ">> WARNING: Installed unit differs from shipped unit."
    echo ">> The installed unit at $INSTALLED_UNIT appears to be site-customized."
    echo ">> Skipping unit installation to preserve TLS paths, bind address, or --allowed-* flags."
    echo ">> The binary has been updated, but the service unit was NOT replaced."
    echo ">> To force unit replacement, re-run with PANOSMCP_FORCE_UNIT=1."
    echo ">> Otherwise, manually reconcile the shipped unit at:"
    echo ">>   $SHIPPED_UNIT"
    SKIP_UNIT_INSTALL=1
else
    install -m 0644 "$SHIPPED_UNIT" "$INSTALLED_UNIT"
    SKIP_UNIT_INSTALL=0
fi

# Install config example (not to the live filename).
install -d -m 0750 "$CONFIG_DIR"
if [[ -e "$PACKAGE_ROOT/config/devices.example.json" ]]; then
    install -m 0644 "$PACKAGE_ROOT/config/devices.example.json" \
        "$CONFIG_DIR/devices.json.example"
fi

# Create tokens.json only if absent, with strict 0600 permissions.
# The unit reads from /var/lib (ProtectSystem=strict makes /etc read-only).
# tokens.json moved from /etc/rust-panosmcp to /var/lib/rust-panosmcp (#125).
#
# Create an empty store ONLY when no legacy store exists. The runtime prefers an
# existing primary, so writing an empty file here while the live tokens are still
# at "$CONFIG_DIR/tokens.json" would shadow them: the service starts and rejects every
# existing bearer token. A silent auth wipe on upgrade is worse than a refusal.
#
# The file is never copied automatically — that would leave a duplicate secret
# behind, which is exactly what the stale-secret scan exists to flag.
#
# For staged installs (SKIP_USER_SETUP=1), systemd-tmpfiles is skipped, so ensure
# the state directory exists before writing to it.
install -d -m 0700 "$STATE_DIR"

require_regular_file "$STATE_DIR/tokens.json"
if [[ ! -e "$STATE_DIR/tokens.json" ]]; then
    if [[ -e "$CONFIG_DIR/tokens.json" ]]; then
        printf '%s\n' ">> Not creating $STATE_DIR/tokens.json: a token store already exists at"
        printf '%s\n' ">> $CONFIG_DIR/tokens.json. The server reads it via the legacy fallback and warns."
        printf '%s\n' ">> Migrate it deliberately, then remove the old copy:"
        printf '%s\n' ">>   install -m 0600 -o $SERVICE_USER -g $SERVICE_GROUP $CONFIG_DIR/tokens.json $STATE_DIR/tokens.json"
        printf '%s\n' ">>   rm $CONFIG_DIR/tokens.json"
    else
        tokens_tmp="$(mktemp "$STATE_DIR/.tokens.json.XXXXXX")"
        printf '%s\n' '{"version":1,"tokens":[]}' >"$tokens_tmp"
        mv -fT "$tokens_tmp" "$STATE_DIR/tokens.json"
    fi
fi

# Ensure tokens.json has 0600 even on upgrade.
if [[ -e "$STATE_DIR/tokens.json" ]]; then
    require_regular_file "$STATE_DIR/tokens.json"
    secure_chmod 0600 "$STATE_DIR/tokens.json"
fi

# Warn if the old /etc location still exists — it may be a live file from
# before the /var/lib migration, or it may be a leftover decoy. Do not delete:
# if it holds live credentials, deletion is not the installer's call.
if [[ -e "$CONFIG_DIR/tokens.json" ]]; then
    echo ">> WARNING: Found tokens.json at $CONFIG_DIR/tokens.json"
    echo ">> WARNING: The service reads from $STATE_DIR/tokens.json."
    echo ">> WARNING: The /etc file may be stale. Review and remove manually if unused."
fi

# Create audit HMAC key if absent. Never regenerate on upgrade — a new key
# breaks verification of every prior record.
require_regular_file "$CONFIG_DIR/audit-hmac.key"
if [[ ! -e "$CONFIG_DIR/audit-hmac.key" ]]; then
    audit_key_tmp="$(mktemp "$CONFIG_DIR/.audit-hmac.key.XXXXXX")"
    head -c 32 /dev/urandom | base64 >"$audit_key_tmp"
    mv -fT "$audit_key_tmp" "$CONFIG_DIR/audit-hmac.key"
fi

# If devices.json exists, ensure it has 0600.
if [[ -e "$CONFIG_DIR/devices.json" ]]; then
    require_regular_file "$CONFIG_DIR/devices.json"
    secure_chmod 0600 "$CONFIG_DIR/devices.json"
fi

# Never clobber mutation-state.json — it holds change-set audit trail.
# Leave it exactly alone if it exists.

if [[ "$SKIP_USER_SETUP" != "1" ]]; then
    chown -h "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    if [[ -e "$CONFIG_DIR/devices.json" ]]; then
        require_regular_file "$CONFIG_DIR/devices.json"
        chown -h "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/devices.json"
    fi
    if [[ -e "$CONFIG_DIR/devices.json.example" ]]; then
        require_regular_file "$CONFIG_DIR/devices.json.example"
        chown -h "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/devices.json.example"
    fi
    if [[ -e "$CONFIG_DIR/audit-hmac.key" ]]; then
        require_regular_file "$CONFIG_DIR/audit-hmac.key"
        chown -h "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/audit-hmac.key"
    fi
    # Recursive ownership for everything under the state dir. GNU chown -R
    # operates on each entry it finds rather than what that entry resolves
    # to, so this does not widen ownership beyond the state dir's contents.
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR" 2>/dev/null || true
fi

if [[ "$INSTALL_ROOT" == "/" && "$SKIP_SYSTEMD_RELOAD" != "1" && "$SKIP_UNIT_INSTALL" != "1" ]]; then
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for a live install"
    systemctl daemon-reload
fi

# Runtime dependencies.
#
# Only `curl` and CA certificates: this server talks HTTPS to PAN-OS and spawns
# no processes, so it needs none of the ssh/scp/tar set that the Junos server
# does. `curl` is for the README's verification step, and the Debian 13
# standard template does not ship it (mecmcp#33).
#
# For LXC only. The container image is distroless and must not gain an HTTP
# client — that is the pivot tool distroless exists to deny an attacker after
# an RCE. Verify the image from the host instead, against the published port.
if [[ "$INSTALL_ROOT" == "/" && "$SKIP_RUNTIME_DEPS" != "1" ]]; then
    if ! command -v curl >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            echo ">> Installing runtime dependencies: curl ca-certificates"
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                curl ca-certificates
            apt-get clean
            rm -rf /var/lib/apt/lists/*
        else
            # Not fatal: the server itself runs fine without curl. Only the
            # documented verification step needs it.
            echo ">> WARNING: curl is missing and no apt-get to install it." >&2
            echo ">> WARNING: the README's endpoint check will not work until it is." >&2
        fi
    fi
fi

if [[ "$INSTALL_ROOT" == "/" && "$SKIP_SYSTEMD_RELOAD" != "1" && "$SKIP_UNIT_INSTALL" != "1" ]]; then
    report_egress_enforcement
fi

echo ">> rust-panosmcp package installed."
if [[ "$SKIP_UNIT_INSTALL" == "1" ]]; then
    echo ">> Binary updated; unit file was NOT replaced (site-customized)."
else
    echo ">> Binary and unit installed."
fi
echo ">> Next steps:"
echo ">>   1. Edit $CONFIG_DIR/devices.json (or copy from devices.json.example)"
echo ">>   2. Mint a bearer token: rust-panosmcp token add <name>"
echo ">>   3. systemctl enable --now rust-panosmcp.service"
echo ">> Endpoint: http://127.0.0.1:30031/mcp"
