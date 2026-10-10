# syntax=docker/dockerfile:1.7

# Builder version is taken from rust-toolchain.toml (currently 1.99.0). The two
# must stay in sync. Both image indexes are pinned and Dependabot proposes
# digest refreshes; the explicit Debian generation prevents an unplanned ABI jump.
# Full patch version, deliberately. `rust:1.98-slim-bookworm` is a floating
# tag: it already points at 1.98.2 while rust-toolchain.toml declares 1.98.1,
# so a digest-only Dependabot refresh moves the compiler across a point
# release while the CI sync check still reports a match. Digest resolved from
# the registry 2026-08-24.
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS builder

WORKDIR /src
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/src=/usr/src/rust-panosmcp"

COPY Cargo.toml Cargo.lock ./
COPY rust-panosmcp/Cargo.toml rust-panosmcp/Cargo.toml
COPY rust-panosmcp-auth/Cargo.toml rust-panosmcp-auth/Cargo.toml
COPY rust-panosmcp-core/Cargo.toml rust-panosmcp-core/Cargo.toml
COPY rust-panosmcp/src rust-panosmcp/src
COPY rust-panosmcp-auth/src rust-panosmcp-auth/src
COPY rust-panosmcp-core/src rust-panosmcp-core/src

RUN cargo build --release --locked --bin rust-panosmcp

# Runtime base digest verified against registry on 2026-08-24.
# Digests have no version ordering and must be validated by resolving the tag
# against the registry (docker pull gcr.io/distroless/cc-debian13:nonroot),
# never by comparing hashes or by matching sibling repos.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

ARG VERSION=0.2.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="rust-panosmcp" \
      org.opencontainers.image.description="Secure async MCP server for PAN-OS firewalls" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/mechubsec/rustpanosmcp" \
      org.opencontainers.image.licenses="MIT"
# Official MCP Registry ownership check: must equal server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustpanosmcp"

COPY --from=builder --chown=nonroot:nonroot /src/target/release/rust-panosmcp /usr/local/bin/rust-panosmcp

ENV RUST_LOG=info
EXPOSE 30031
USER 65532:65532
STOPSIGNAL SIGTERM

# ENTRYPOINT carries what must always hold: config paths and anything security-
# relevant. CMD carries only what an operator is expected to replace: bind
# address, port, and mode flags. Docker replaces CMD when the caller supplies
# arguments, so security-relevant defaults must stay in ENTRYPOINT.
#
# --audit-hmac-key-file: the binary itself generates
# /var/lib/rust-panosmcp/audit-hmac.key on first run if it is absent (see
# ensure_audit_hmac_key in src/main.rs) -- the container-image equivalent of
# packaging/lxc/install.sh's own key-generation step, closing the "5 of 6
# server images run unkeyed audit" gap (mecmcp#376 / MEC-978). The path is
# under the writable /var/lib/rust-panosmcp volume, not /etc/rust-panosmcp,
# because compose.example.yaml mounts /etc/rust-panosmcp read-only, so a key
# path there could never be generated on a fresh container.
# --audit-redact devices=hmac is the same default packaging/systemd ships, so
# the container and LXC/systemd paths converge on the same keyed, redacted
# posture instead of only the device-direct paths doing it.
ENTRYPOINT ["/usr/local/bin/rust-panosmcp", \
    "--device-mapping", "/etc/rust-panosmcp/devices.json", \
    "--tokens-file", "/var/lib/rust-panosmcp/tokens.json", \
    "--state-file", "/var/lib/rust-panosmcp/mutation-state.json", \
    "--audit-hmac-key-file", "/var/lib/rust-panosmcp/audit-hmac.key", \
    "--audit-redact", "devices=hmac"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30031"]
