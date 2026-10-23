#!/usr/bin/env bash
# Regression guard for mecmcp#355: BUILD-INFO from the skip-build path must not
# name a toolchain that never compiled the binary. Needs target/release/rust-panosmcp.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
[[ -x target/release/rust-panosmcp ]] || {
    echo 'target/release/rust-panosmcp must already be built before this test runs' >&2
    exit 1
}

expected_sha=$(sha256sum target/release/rust-panosmcp | cut -d' ' -f1)
commit=$(git rev-parse HEAD)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Negative: a missing or malformed source commit must be refused.
for bad in '' 'abc123' "${commit^^}"; do
    if PANOSMCP_ALLOW_DIRTY=1 PANOSMCP_PACKAGE_SKIP_BUILD=1 \
        PANOSMCP_BINARY_SOURCE_COMMIT="$bad" PANOSMCP_OUTPUT_DIR="$work/neg" \
        scripts/build-release.sh >/dev/null 2>&1; then
        echo "skip-build accepted a bad PANOSMCP_BINARY_SOURCE_COMMIT: '$bad'" >&2
        exit 1
    fi
done

PANOSMCP_ALLOW_DIRTY=1 PANOSMCP_PACKAGE_SKIP_BUILD=1 \
PANOSMCP_BINARY_SOURCE_COMMIT="$commit" PANOSMCP_OUTPUT_DIR="$work/out" \
    scripts/build-release.sh >/dev/null

mapfile -t archives < <(find "$work/out" -maxdepth 1 -name 'rust-panosmcp-v*.tar.gz')
[[ ${#archives[@]} -eq 1 ]] || { echo "expected one archive, found ${#archives[@]}" >&2; exit 1; }
mkdir "$work/x"
tar -xzf "${archives[0]}" -C "$work/x"
build_info=$(find "$work/x" -maxdepth 2 -name BUILD-INFO)

recorded_rustc=$(sed -n 's/^rustc=//p' "$build_info")
case "$recorded_rustc" in
    unknown\ \(*) ;;
    *) echo "skip-build rustc= must start with 'unknown ('; got: $recorded_rustc" >&2; exit 1 ;;
esac
if grep -Eq 'rustc [0-9]+\.[0-9]+\.[0-9]+' <<<"$recorded_rustc"; then
    echo "skip-build BUILD-INFO names a compiler version: $recorded_rustc" >&2
    exit 1
fi
recorded_sha=$(sed -n 's/^binary_sha256=//p' "$build_info")
[[ "$recorded_sha" == "$expected_sha" ]] || {
    echo "binary_sha256 ($recorded_sha) != packaged binary ($expected_sha)" >&2
    exit 1
}
recorded_commit=$(sed -n 's/^git_commit=//p' "$build_info")
[[ "$recorded_commit" == "$commit" ]] || {
    echo "git_commit ($recorded_commit) != supplied commit ($commit)" >&2
    exit 1
}
echo 'skip-build provenance is honest'
