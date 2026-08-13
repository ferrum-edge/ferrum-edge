# syntax=docker/dockerfile:1
# Multi-stage build for Ferrum Edge

# Build features for the main binary. There are three published runtime targets:
#
#   * `runtime`            — the ordinary gateway image. Distroless, and contains
#                            neither the eBPF ELF nor `ip`.
#   * `runtime-ebpf`       — node-agent / NodeWaypoint capture. Still distroless:
#                            it adds the eBPF ELF and a staged `ip` closure and
#                            deliberately has NO `/bin/sh` and NO iptables.
#   * `runtime-ebpf-tools` — a strict superset of `runtime-ebpf` for the Ambient
#                            host/pod-netns UDP lifecycle, which drives generated
#                            `sh -c` iptables/ip6tables scripts and therefore
#                            cannot run on a distroless image. Debian-based, so
#                            it is NOT distroless by construction.
#
# Build the eBPF targets with `FEATURES=cloud-secrets,ebpf`; hosted CI exercises
# all three contracts.
ARG FEATURES=cloud-secrets
ARG RUNTIME_BASE=gcr.io/distroless/cc-debian13:nonroot
ARG IPROUTE2_BASE=debian:13-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2
ARG IPROUTE2_VERSION=6.15.0-1
ARG BPF_LINKER_VERSION=0.11.0
ARG BPF_LINKER_AMD64_SHA256=10f62ba9ab7e544d538370552660efcb4f1a19153d5752bbf0f6b51f3bada450
ARG BPF_LINKER_ARM64_SHA256=d09ddd83303e9ab1443f51e0e284680154009646a3ce141c63d838ee61b73eb9

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
ARG TARGETARCH
ARG BPF_LINKER_VERSION
ARG BPF_LINKER_AMD64_SHA256
ARG BPF_LINKER_ARM64_SHA256
# Use the upstream static release instead of compiling bpf-linker against the
# mutable LLVM installation in rust:latest. Both architecture-specific assets
# and their SHA-256 digests are pinned above.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) asset_arch=x86_64; asset_sha="${BPF_LINKER_AMD64_SHA256}" ;; \
        arm64) asset_arch=aarch64; asset_sha="${BPF_LINKER_ARM64_SHA256}" ;; \
        *) echo "unsupported bpf-linker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl zstd; \
    rm -rf /var/lib/apt/lists/*; \
    archive=/tmp/bpf-linker.tar.zst; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
        --connect-timeout 30 --max-time 300 \
        -o "${archive}" \
        "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-${asset_arch}-unknown-linux-musl.tar.zst"; \
    printf '%s  %s\n' "${asset_sha}" "${archive}" | sha256sum --check --strict; \
    tar --zstd -xf "${archive}" -C /usr/local/bin bpf-linker; \
    chmod 0755 /usr/local/bin/bpf-linker; \
    rm -f "${archive}"; \
    bpf-linker --version
RUN rustup toolchain install nightly --component rust-src \
    && rustup run nightly rustc --version
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

# --- Ambient UDP lifecycle tool base ------------------------------------------
# The Ambient UDP capture lifecycle (host-netns and per-pod-netns producers, plus
# the disabled stale-rule cleanup manager) executes GENERATED `sh -c` scripts that
# call `ip`, `iptables`, `ip6tables`, and the `*-save` readback helpers. A
# distroless image ships none of them, so `preflight_capture_tools` refuses
# startup there by design. That lifecycle therefore needs its own tools-capable
# runtime rather than a silent weakening of the published `-ebpf` contract.
#
# This stage is deliberately a FULL Debian userland, not a staged closure:
# `iptables` resolves through the `xtables-nft-multi` alternatives links and
# needs its own `/usr/lib/x86_64-linux-gnu/xtables` extension directory plus
# `/etc/ethertypes`, so hand-staging it into distroless would reproduce a Debian
# root with none of Debian's security-update path. `iproute2` shares the exact
# pinned version used by the distroless staging closure; `iptables` tracks the
# digest-pinned base suite's security-updated package, because pinning an exact
# package revision here would break every Debian point release without bounding
# anything the release manifest digest does not already bound.
#
# Splitting the tool provisioning into its own stage lets CI smoke the tool
# contract without paying for the Rust + nightly eBPF builds, while the final
# runtime below still inherits exactly these bytes.
FROM ${IPROUTE2_BASE} AS capture-tools-base
ARG IPROUTE2_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        "iproute2=${IPROUTE2_VERSION}" \
        iptables \
    && rm -rf /var/lib/apt/lists/*
# Fail the BUILD, not a node at 3am, if the tool contract the Ambient UDP
# lifecycle depends on is ever absent. Keep this list in lock-step with
# `preflight_capture_tools` and the `ambient-host-udp-live` image smoke.
RUN set -eu; \
    test -x /bin/sh; \
    for tool in ip iptables ip6tables iptables-save ip6tables-save; do \
        command -v "$tool" >/dev/null 2>&1 || { \
            echo "capture-tools-base is missing required tool: $tool" >&2; \
            exit 1; \
        }; \
    done; \
    iptables --version >/dev/null; \
    ip6tables --version >/dev/null

# Ambient UDP lifecycle runtime, published as the `-ebpf-tools` tag. A strict
# superset of `runtime-ebpf`: same binaries, same BPF ELF, plus the shell and
# netfilter/iproute2 tools above. It runs as root because every consumer of this
# image needs root + NET_ADMIN (and, for the per-pod producer, `setns`) to
# install capture rules; the mesh/node-agent charts already select UID 0. The
# ENV/EXPOSE/HEALTHCHECK/ENTRYPOINT block mirrors `runtime-common`, which cannot
# be inherited here because this target does not descend from the distroless base.
FROM capture-tools-base AS runtime-ebpf-tools

WORKDIR /app

COPY --from=builder /build/target/release/ferrum-edge /app/ferrum-edge
COPY --from=builder /build/target/release/ferrum-cni /app/ferrum-cni
COPY --from=ebpf-builder \
    /build/ebpf/target/bpfel-unknown-none/release/ferrum-ebpf /app/bpf/ferrum-ebpf

ENV PATH="/app:${PATH}" \
    FERRUM_MODE=database \
    FERRUM_LOG_LEVEL=error \
    FERRUM_PROXY_HTTP_PORT=8000 \
    FERRUM_PROXY_HTTPS_PORT=8443 \
    FERRUM_ADMIN_HTTP_PORT=9000 \
    FERRUM_ADMIN_HTTPS_PORT=9443 \
    FERRUM_NODE_AGENT_BPF_ELF_PATH=/app/bpf/ferrum-ebpf

EXPOSE 8000 8443 9000 9443 50051

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/ferrum-edge", "health"]

LABEL org.opencontainers.image.title="Ferrum Edge (Ambient UDP lifecycle)" \
      org.opencontainers.image.description="Ferrum Edge eBPF runtime plus the shell, iproute2, and iptables tools the Ambient UDP capture lifecycle executes" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge"

USER 0
ENTRYPOINT ["/app/ferrum-edge"]
CMD ["run"]

# Keep the ordinary runtime as the default final target.
FROM runtime-common AS runtime
