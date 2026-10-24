#!/usr/bin/env bash
# Build a deterministic release archive and SHA-256 checksum.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "${PANOSMCP_ALLOW_DIRTY:-0}" != "1" ]] \
    && [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "refusing a release archive from a dirty worktree" >&2
    exit 1
fi

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
if [[ -z "$VERSION" ]]; then
    echo "workspace version not found" >&2
    exit 1
fi
PACKAGING_COMMIT="$(git rev-parse --verify HEAD)"
SKIP_BUILD="${PANOSMCP_PACKAGE_SKIP_BUILD:-0}"
TARGET_DIR="${PANOSMCP_TARGET_DIR:-$ROOT/target}"
OUTPUT_DIR="${PANOSMCP_OUTPUT_DIR:-$ROOT/dist}"
if [[ "$SKIP_BUILD" == "1" ]]; then
    # Packaging a CI-built binary: the binary is not ours to compile, so the
    # local rustc host says nothing about it, and the release image is x86_64.
    TARGET_TRIPLE="${PANOSMCP_TARGET_TRIPLE:-x86_64-unknown-linux-gnu}"
    # Workstation glibc is newer than the LXCs', so a rebuilt binary will not
    # start there; package the release image's binary instead.
    if [[ ! -x "$TARGET_DIR/release/rust-panosmcp" ]]; then
        echo "PANOSMCP_PACKAGE_SKIP_BUILD=1 but $TARGET_DIR/release/rust-panosmcp is missing or not executable." >&2
        echo "Extract it from the release image, e.g.:" >&2
        echo "  docker create --name pm ghcr.io/mechubsec/rust-panosmcp:<version>" >&2
        echo "  docker cp pm:/usr/local/bin/rust-panosmcp $TARGET_DIR/release/rust-panosmcp; docker rm pm" >&2
        exit 1
    fi
    if [[ ! "${PANOSMCP_BINARY_SOURCE_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "PANOSMCP_PACKAGE_SKIP_BUILD=1 requires PANOSMCP_BINARY_SOURCE_COMMIT: the full lowercase 40-hex commit that built the binary" >&2
        exit 1
    fi
    if ! COMMIT="$(git rev-parse "${PANOSMCP_BINARY_SOURCE_COMMIT}^{commit}" 2>/dev/null)"; then
        echo "commit $PANOSMCP_BINARY_SOURCE_COMMIT is not in this clone; run: git fetch origin $PANOSMCP_BINARY_SOURCE_COMMIT" >&2
        exit 1
    fi
    # Version and toolchain pin describe the binary, so read them at its source
    # commit, not from this checkout, and refuse a binary that disagrees.
    VERSION="$(git show "$COMMIT:Cargo.toml" | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -n 1)"
    # shortcut: executes the binary, so packaging must run on a host that can run it
    # (the fleet and packaging hosts are x86_64 Linux); fails closed otherwise.
    BINARY_VERSION="$("$TARGET_DIR/release/rust-panosmcp" --version | awk '{print $2}')" || {
        echo "cannot run $TARGET_DIR/release/rust-panosmcp to verify its version; package on a host that can execute it" >&2
        exit 1
    }
    if [[ -z "$VERSION" || "$BINARY_VERSION" != "$VERSION" ]]; then
        echo "binary reports version '$BINARY_VERSION' but ${COMMIT:0:12} declares '$VERSION'; wrong binary or wrong PANOSMCP_BINARY_SOURCE_COMMIT" >&2
        exit 1
    fi
    TOOLCHAIN_CHANNEL="$(git show "$COMMIT:rust-toolchain.toml" 2>/dev/null | sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' | head -n 1)"
    if [[ -z "$TOOLCHAIN_CHANNEL" ]]; then
        echo "no toolchain channel in rust-toolchain.toml at ${COMMIT:0:12}" >&2
        exit 1
    fi
    RUSTC_LINE="unknown (binary supplied prebuilt via PANOSMCP_PACKAGE_SKIP_BUILD; pinned toolchain $TOOLCHAIN_CHANNEL at ${COMMIT:0:12}; not compiled by this script)"
else
    COMMIT="$PACKAGING_COMMIT"
    TARGET_TRIPLE="${PANOSMCP_TARGET_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"
    RUSTC_LINE="$(rustc -vV | tr '\n' ' ' | sed 's/ *$//')"
fi
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$COMMIT")}"
ARCHIVE="rust-panosmcp-v${VERSION}-${TARGET_TRIPLE}.tar.gz"
BUILD_ARGS=(--release --locked --bin rust-panosmcp)
if [[ "${PANOSMCP_OFFLINE:-0}" == "1" ]]; then
    BUILD_ARGS+=(--offline)
fi

export SOURCE_DATE_EPOCH CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$TARGET_DIR"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$ROOT=/usr/src/rust-panosmcp"
if [[ "$SKIP_BUILD" != "1" ]]; then
    cargo build "${BUILD_ARGS[@]}"
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
PKG="$STAGING/rust-panosmcp-v${VERSION}"
install -d "$PKG/bin" "$PKG/packaging/systemd" "$PKG/packaging/lxc" "$PKG/docs" "$PKG/config"
install -m 0755 "$TARGET_DIR/release/rust-panosmcp" "$PKG/bin/rust-panosmcp"
install -m 0644 LICENSE README.md SECURITY.md "$PKG/"
install -m 0644 docs/OPERATIONS.md docs/COMPATIBILITY.md docs/BENCHMARKS.md \
    docs/V0.2_CHANGE_SETS.md "$PKG/docs/"
install -m 0644 packaging/systemd/rust-panosmcp.service \
    packaging/systemd/rust-panosmcp.sysusers \
    packaging/systemd/rust-panosmcp.tmpfiles \
    packaging/systemd/ssdf-audit.conf.example "$PKG/packaging/systemd/"
install -m 0755 packaging/lxc/install.sh "$PKG/packaging/lxc/install.sh"
install -m 0644 config/devices.example.json \
    config/devices.mutation.example.json \
    config/tokens.example.json "$PKG/config/"
{
    printf 'version=%s\n' "$VERSION"
    printf 'git_commit=%s\n' "$COMMIT"
    printf 'packaging_commit=%s\n' "$PACKAGING_COMMIT"
    printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
    printf 'target=%s\n' "$TARGET_TRIPLE"
    printf 'binary_sha256=%s\n' "$(sha256sum "$PKG/bin/rust-panosmcp" | cut -d' ' -f1)"
    printf 'rustc=%s\n' "$RUSTC_LINE"
} >"$PKG/BUILD-INFO"

mkdir -p "$OUTPUT_DIR"
tar --sort=name --format=ustar --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -C "$STAGING" -cf - "$(basename "$PKG")" \
    | gzip -n -9 >"$OUTPUT_DIR/$ARCHIVE"
(
    cd "$OUTPUT_DIR"
    sha256sum "$ARCHIVE" >"$ARCHIVE.sha256"
)
echo "$OUTPUT_DIR/$ARCHIVE"
