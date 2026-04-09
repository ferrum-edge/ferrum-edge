# Multi-stage build for Ferrum Edge
# Stage 1: Builder — rust:latest uses trixie (Debian 13), matching distroless/cc-debian13 glibc
FROM rust:latest AS builder

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

# Create a dummy main.rs to build dependencies only
RUN mkdir src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# ── Build the real binary ───────────────────────────────────────────────
COPY src ./src
# Touch main.rs so cargo knows it changed (not the dummy)
RUN touch src/main.rs && cargo build --release

# Stage 2: Distroless runtime — no OS packages, no shell, no CVEs
# Uses nonroot tag (UID 65532) for least-privilege execution.
# OpenSSL is vendored (statically linked) so libssl is not needed.
# ca-certificates are included in distroless/cc.
FROM gcr.io/distroless/cc-debian13:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=nonroot:nonroot /build/target/release/ferrum-edge /app/ferrum-edge

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

# Health check using built-in CLI subcommand (no curl needed in distroless)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/ferrum-edge", "health"]

# Add labels
LABEL org.opencontainers.image.title="Ferrum Edge" \
      org.opencontainers.image.description="High-performance edge proxy built in Rust" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge"

# Run the gateway (already running as nonroot via distroless tag)
ENTRYPOINT ["/app/ferrum-edge"]
