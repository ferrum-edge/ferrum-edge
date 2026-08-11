# syntax=docker/dockerfile:1
# Multi-stage build for Ferrum Edge

# Build features for the main binary. The final `runtime` target is the ordinary
# gateway image and contains neither the eBPF ELF nor `ip`. Build the explicit
# `runtime-ebpf` target with `FEATURES=cloud-secrets,ebpf` for node-agent /
# ambient capture; hosted CI exercises both contracts.
ARG FEATURES=cloud-secrets
ARG RUNTIME_BASE=gcr.io/distroless/cc-debian13:nonroot
ARG IPROUTE2_BASE=debian:13-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2
ARG IPROUTE2_VERSION=6.15.0-1

# --- eBPF build stage (nightly, Linux only) ---
# Compiles the no_std `ferrum-ebpf` crate to a BPF ELF using nightly +
# `-Z build-std` against the bpfel-unknown-none target. The resulting ELF is
# COPY'd into the runtime image and loaded by node_agent / node-waypoint mesh
# mode at startup via aya. Linking requires `bpf-linker` (installed below).
#
# The ebpf/ workspace pins a nightly via ebpf/rust-toolchain.toml, but the
# `cargo +nightly` invocations below explicitly select the latest installed
# nightly — the `+nightly` override takes precedence over the toolchain file,
# so the pin is NOT what is used here. Both resolve to a nightly toolchain so
# the build works today; if the eBPF crate ever requires a *specific* pinned
# nightly, drop `+nightly` from the build below so the rust-toolchain.toml pin
# is honored (and install rust-src on that pinned toolchain). core-only
# build-std matches the crate's `#![no_std]` + `panic = "abort"`.
FROM rust:latest AS ebpf-builder
RUN rustup toolchain install nightly --component rust-src \
    && cargo +nightly install bpf-linker --locked
COPY ebpf/ /build/ebpf/
WORKDIR /build/ebpf
RUN cargo +nightly build \
        --release \
        -p ferrum-ebpf \
        --target bpfel-unknown-none \
        -Z build-std=core \
    && test -f target/bpfel-unknown-none/release/ferrum-ebpf

# Runtime tool closure for the distroless eBPF image. Inventory the actual base
# filesystem and stage only loader-resolved libraries it does not already own.
FROM ${RUNTIME_BASE} AS runtime-base
FROM ${IPROUTE2_BASE} AS iproute2-runtime
ARG IPROUTE2_VERSION
COPY .github/scripts/stage_iproute2_runtime.sh /usr/local/bin/stage-iproute2-runtime
RUN --mount=from=runtime-base,source=/,target=/distroless-root,ro \
    /bin/sh /usr/local/bin/stage-iproute2-runtime \
        /iproute2-root /distroless-root "${IPROUTE2_VERSION}"

# Stage 1: Builder — rust:latest uses trixie (Debian 13), matching distroless/cc-debian13 glibc
FROM rust:latest AS builder
ARG FEATURES

# Install build dependencies
# clang/libclang-dev: required by bindgen (used by zstd-sys)
# cmake: required by some native C dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Dependency caching layer ─────────────────────────────────────────────
# Copy only manifests and build script first, so Docker can cache the
# expensive dependency download + compile step across source changes.
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY custom_plugins ./custom_plugins
# Vendored crates referenced by [patch.crates-io] in Cargo.toml. Must be
# present before any `cargo build` (including the dummy-main dep-cache step
# below) — Cargo resolves patch paths during manifest load, not just at
# compile time.
COPY vendor ./vendor
# The main crate depends on shared no_std eBPF ABI types via a path dependency,
# so the Docker build context must include ebpf/ before any Cargo metadata load.
COPY ebpf ./ebpf

# Create a dummy main.rs to build dependencies only
RUN mkdir src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    cargo build --features "${FEATURES}" --release 2>/dev/null || true && \
    rm -rf src

# ── Build the real binary ───────────────────────────────────────────────
COPY src ./src
# Touch main.rs so cargo knows it changed (not the dummy)
RUN touch src/main.rs && cargo build --features "${FEATURES}" --release

# Stage 2: common distroless runtime. It intentionally has no shell, package
# manager, eBPF ELF, or `ip` executable.
FROM runtime-base AS runtime-common

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=65532:65532 /build/target/release/ferrum-edge /app/ferrum-edge
COPY --from=builder --chown=65532:65532 /build/target/release/ferrum-cni /app/ferrum-cni

# Set environment variables
ENV PATH="/app:${PATH}" \
    FERRUM_MODE=database \
    FERRUM_LOG_LEVEL=error \
    FERRUM_PROXY_HTTP_PORT=8000 \
    FERRUM_PROXY_HTTPS_PORT=8443 \
    FERRUM_ADMIN_HTTP_PORT=9000 \
    FERRUM_ADMIN_HTTPS_PORT=9443

# Expose ports
EXPOSE 8000 8443 9000 9443 50051

# Health check using the built-in CLI subcommand (no curl needed)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/ferrum-edge", "health"]

# Add labels
LABEL org.opencontainers.image.title="Ferrum Edge" \
      org.opencontainers.image.description="High-performance edge proxy built in Rust" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge"

# Run the gateway (already running as nonroot via the distroless tag). The
# mesh/node-agent charts explicitly select UID 0 for kernel capture operations.
ENTRYPOINT ["/app/ferrum-edge"]
CMD ["run"]

# Privileged capture runtime. NodeWaypoint ingress redirect owns an exact policy
# rule/route and therefore needs this staged `ip` closure at startup/teardown.
# No shell or package manager crosses into the image.
FROM runtime-common AS runtime-ebpf
COPY --from=iproute2-runtime /iproute2-root/usr/sbin/ip /usr/sbin/ip
COPY --from=iproute2-runtime /iproute2-root/usr/lib/ /usr/lib/
COPY --from=iproute2-runtime /iproute2-root/usr/lib64/ /usr/lib64/
COPY --from=ebpf-builder --chown=65532:65532 \
    /build/ebpf/target/bpfel-unknown-none/release/ferrum-ebpf /app/bpf/ferrum-ebpf
ENV FERRUM_NODE_AGENT_BPF_ELF_PATH=/app/bpf/ferrum-ebpf

# Keep the ordinary runtime as the default final target.
FROM runtime-common AS runtime
