#!/usr/bin/env bash
# Regression test: the installer must refuse to operate on tokens.json,
# audit-hmac.key, or devices.json when the existing path is not a regular
# file, and must leave whatever that path points to untouched.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

FAKE_PACKAGE="$STAGING/rust-panosmcp-test"
install -d "$FAKE_PACKAGE/bin" "$FAKE_PACKAGE/packaging/systemd" "$FAKE_PACKAGE/packaging/lxc" \
    "$FAKE_PACKAGE/config"

cp "$PACKAGE_ROOT/packaging/lxc/install.sh" "$FAKE_PACKAGE/packaging/lxc/install.sh"
cp "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.service" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.sysusers" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/packaging/systemd/rust-panosmcp.tmpfiles" "$FAKE_PACKAGE/packaging/systemd/"
cp "$PACKAGE_ROOT/config/devices.example.json" "$FAKE_PACKAGE/config/"

echo '#!/bin/sh' > "$FAKE_PACKAGE/bin/rust-panosmcp"
echo 'echo "fake binary"' >> "$FAKE_PACKAGE/bin/rust-panosmcp"
chmod +x "$FAKE_PACKAGE/bin/rust-panosmcp"
chmod +x "$FAKE_PACKAGE/packaging/lxc/install.sh"

INSTALL_ROOT="$STAGING/staged"
export PANOSMCP_INSTALL_ROOT="$INSTALL_ROOT"
export PANOSMCP_INSTALL_SKIP_USER=1
export PANOSMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1
export PANOSMCP_INSTALL_SKIP_RUNTIME_DEPS=1

cd "$FAKE_PACKAGE"

STATE_DIR="$INSTALL_ROOT/var/lib/rust-panosmcp"
CONFIG_DIR="$INSTALL_ROOT/etc/rust-panosmcp"
CANARY="$STAGING/canary"
printf 'canary-untouched\n' >"$CANARY"
chmod 0644 "$CANARY"

assert_refused_and_canary_untouched() {
    local label="$1"
    local canary_perms_before="$2"
    local canary_perms_after
    canary_perms_after="$(stat -c '%a' "$CANARY")"
    if [[ "$canary_perms_after" != "$canary_perms_before" ]]; then
        echo "FAIL: $label: canary perms changed ($canary_perms_before -> $canary_perms_after)" >&2
        exit 1
    fi
    if [[ "$(cat "$CANARY")" != "canary-untouched" ]]; then
        echo "FAIL: $label: canary content was overwritten" >&2
        exit 1
    fi
}

# --- First install: establishes the baseline state dir/tokens.json. ---
./packaging/lxc/install.sh >/dev/null

if [[ ! -f "$STATE_DIR/tokens.json" ]]; then
    echo "FAIL: baseline install did not create $STATE_DIR/tokens.json" >&2
    exit 1
fi

# --- tokens.json: replace the real file with a non-regular entry. ---
rm -f "$STATE_DIR/tokens.json"
ln -s "$CANARY" "$STATE_DIR/tokens.json"
canary_before="$(stat -c '%a' "$CANARY")"

if ./packaging/lxc/install.sh >/dev/null 2>"$STAGING/tokens-refusal.log"; then
    echo "FAIL: installer did not refuse a symlinked tokens.json" >&2
    exit 1
fi
grep -q "not a regular file; refusing" "$STAGING/tokens-refusal.log" \
    || { echo "FAIL: unexpected refusal message for tokens.json" >&2; cat "$STAGING/tokens-refusal.log" >&2; exit 1; }
assert_refused_and_canary_untouched "tokens.json" "$canary_before"
rm -f "$STATE_DIR/tokens.json"

# --- audit-hmac.key: replace the file left by the baseline install. ---
rm -f "$CONFIG_DIR/audit-hmac.key"
ln -s "$CANARY" "$CONFIG_DIR/audit-hmac.key"
canary_before="$(stat -c '%a' "$CANARY")"

if ./packaging/lxc/install.sh >/dev/null 2>"$STAGING/audit-key-refusal.log"; then
    echo "FAIL: installer did not refuse a symlinked audit-hmac.key" >&2
    exit 1
fi
grep -q "not a regular file; refusing" "$STAGING/audit-key-refusal.log" \
    || { echo "FAIL: unexpected refusal message for audit-hmac.key" >&2; cat "$STAGING/audit-key-refusal.log" >&2; exit 1; }
assert_refused_and_canary_untouched "audit-hmac.key" "$canary_before"
rm -f "$CONFIG_DIR/audit-hmac.key" "$STATE_DIR/tokens.json"

# --- devices.json: operator-managed file, present as a non-regular entry. ---
ln -s "$CANARY" "$CONFIG_DIR/devices.json"
canary_before="$(stat -c '%a' "$CANARY")"

if ./packaging/lxc/install.sh >/dev/null 2>"$STAGING/devices-refusal.log"; then
    echo "FAIL: installer did not refuse a symlinked devices.json" >&2
    exit 1
fi
grep -q "not a regular file; refusing" "$STAGING/devices-refusal.log" \
    || { echo "FAIL: unexpected refusal message for devices.json" >&2; cat "$STAGING/devices-refusal.log" >&2; exit 1; }
assert_refused_and_canary_untouched "devices.json" "$canary_before"
rm -f "$CONFIG_DIR/devices.json"

echo "PASS: installer refuses symlinked tokens.json, audit-hmac.key, and devices.json"
