#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

failures=0

require_contains() {
    local file=$1
    local pattern=$2
    if ! grep -Fq -- "$pattern" "$file"; then
        printf 'missing required text in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_absent() {
    local file=$1
    local pattern=$2
    if grep -Eq -- "$pattern" "$file"; then
        printf 'forbidden text in %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_absent_in_cmd() {
    local file=$1
    local pattern=$2
    # Check if pattern appears in CMD block (handles multi-line CMD with backslashes).
    # Matches from 'CMD [' through the end of the JSON array.
    if awk '/^CMD \[/ {in_cmd=1} in_cmd && /'"$pattern"'/ {found=1; exit} in_cmd && /^[^[:space:]]/ && !/^CMD/ {in_cmd=0} END {exit !found}' "$file"; then
        printf 'forbidden flag in CMD block of %s: %s\n' "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

diagnostics="$(mktemp)"
trap 'rm -f "$diagnostics"' EXIT
if ! systemd-analyze verify packaging/systemd/rust-panosmcp.service 2>"$diagnostics"; then
    if grep -Ev '^rust-panosmcp\.service: Command /usr/local/bin/rust-panosmcp is not executable: No such file or directory$' \
        "$diagnostics" | grep -q .; then
        cat "$diagnostics" >&2
        exit 1
    fi
fi
cat "$diagnostics" >&2

grep -Eq '^USER 65532:65532$' Dockerfile

# ENTRYPOINT must contain security-relevant flags and config paths (mecmcp#357).
# The ENTRYPOINT is multi-line so check each flag appears in the file (they are
# all within the ENTRYPOINT block per the visual inspection of the Dockerfile).
require_contains "Dockerfile" '"/usr/local/bin/rust-panosmcp",'
require_contains "Dockerfile" '"--device-mapping", "/etc/rust-panosmcp/devices.json",'
require_contains "Dockerfile" '"--tokens-file", "/var/lib/rust-panosmcp/tokens.json",'
require_contains "Dockerfile" '"--state-file", "/var/lib/rust-panosmcp/mutation-state.json"'

# CMD must contain transport, host, and port.
require_contains "Dockerfile" 'CMD ["--transport", "streamable-http", \'
require_contains "Dockerfile" '"--host", "127.0.0.1", \'
require_contains "Dockerfile" '"--port", "30031"]'

# Regression guard for mecmcp#357: CMD must NOT contain config paths or
# security-relevant flags. Docker replaces CMD when the caller supplies args,
# so these must live in ENTRYPOINT to survive operator overrides.
require_absent_in_cmd "Dockerfile" '--device-mapping'
require_absent_in_cmd "Dockerfile" '--tokens-file'
require_absent_in_cmd "Dockerfile" '--state-file'
require_absent_in_cmd "Dockerfile" '--audit-format'
require_absent_in_cmd "Dockerfile" '--audit-redact'
require_absent_in_cmd "Dockerfile" '--audit-hmac-key-file'

grep -Eq '^FROM rust:.*@sha256:[0-9a-f]{64} AS builder$' Dockerfile
# Pins the approved runtime base. This must move whenever the Dockerfile's base
# moves — it is the check that stops the base drifting silently, so it is
# deliberately exact rather than a wildcard over distroless variants.
grep -Eq '^FROM gcr.io/distroless/cc-debian13:nonroot@sha256:[0-9a-f]{64}$' Dockerfile
if grep -En '(^|[[:space:]])(curl|wget|apt-get|apk|dnf)([[:space:]]|$)' Dockerfile; then
    echo "runtime/container build contains an unapproved package-fetch command" >&2
    exit 1
fi

# Run the installer/unit consistency test to catch path mismatches.
if [[ -x "$ROOT/packaging/lxc/tests/test_install_unit_consistency.sh" ]]; then
    "$ROOT/packaging/lxc/tests/test_install_unit_consistency.sh"
else
    echo "WARN: install/unit consistency test not found or not executable" >&2
fi

# Run the installer symlink-hardening regression test.
if [[ -x "$ROOT/packaging/lxc/tests/test_symlink_hardening.sh" ]]; then
    "$ROOT/packaging/lxc/tests/test_symlink_hardening.sh"
else
    echo "WARN: installer symlink-hardening test not found or not executable" >&2
fi

if (( failures > 0 )); then
    printf 'packaging policy: FAIL (%d violation(s))\n' "$failures" >&2
    exit 1
fi
printf 'packaging policy: PASS\n'
