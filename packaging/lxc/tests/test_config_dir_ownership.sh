#!/usr/bin/env bash
# The config directory stays root-owned, and that correction precedes any
# write into the directory.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
INSTALL_SH="$PACKAGE_ROOT/packaging/lxc/install.sh"

line_of() {
    local pattern="$1"
    local found=""
    found="$(grep -nF -- "$pattern" "$INSTALL_SH" | head -n 1 | cut -d: -f1 || true)"
    printf '%s\n' "$found"
}

# shellcheck disable=SC2016  # Patterns match installer source text, not this script.
own="$(line_of 'chown -h "root:$SERVICE_GROUP" "$CONFIG_DIR"')"
# shellcheck disable=SC2016
example="$(line_of '"$CONFIG_DIR/devices.json.example"')"
# shellcheck disable=SC2016
key="$(line_of 'mktemp "$CONFIG_DIR/.audit-hmac.key.XXXXXX"')"

if [[ -z "$own" || -z "$example" || -z "$key" ]]; then
    echo "FAIL: expected config-dir ownership correction or write site is missing" >&2
    exit 1
fi

if (( own > example || own > key )); then
    echo "FAIL: config dir ownership correction is after a write into it (own=$own example=$example key=$key)" >&2
    exit 1
fi

# shellcheck disable=SC2016  # Pattern matches installer source text, not this script.
if grep -Eq 'chown[[:space:]].*"\$SERVICE_USER:\$SERVICE_GROUP"[[:space:]]+"\$CONFIG_DIR"[[:space:]]*$' "$INSTALL_SH"; then
    echo "FAIL: config dir is assigned to the service account" >&2
    exit 1
fi

echo "PASS: config dir stays root-owned and is corrected before writes"
