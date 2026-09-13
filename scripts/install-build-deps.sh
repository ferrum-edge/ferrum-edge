#!/usr/bin/env bash
# Bootstrap the optional toolchain extras that .cargo/config.toml expects,
# plus the native packages rdkafka-sys needs to compile librdkafka from source
# (`cmake-build` + vendored TLS for kafka_logging; see docs/dependency-policy.md):
# - sccache (rustc-wrapper for cross-branch compile cache)
# - mold (Linux) / lld (macOS) for faster link times
# - cmake (configures librdkafka)
# - curl development headers (librdkafka still requires curl/curl.h even
#   when cmake is passed -DWITH_CURL=0)
#
# Run this once per workstation. CI installs the same tools via the
# `setup-sccache` and `setup-fast-linker` composite actions in .github/actions/
# (cmake is already on GitHub-hosted Ubuntu and in the Docker/Cross builders;
# libcurl4-openssl-dev is installed by setup-rust-ci and the Linux build jobs).
#
# If a tool is already installed, the relevant package manager call is a
# no-op. Re-running is safe.

set -euo pipefail

os="$(uname -s)"
case "${os}" in
  Darwin)
    if ! command -v brew &> /dev/null; then
      echo "Homebrew not found. Install from https://brew.sh and re-run." >&2
      exit 1
    fi
    echo "Installing sccache + lld + cmake + curl via Homebrew..."
    # sccache: rustc-wrapper required by .cargo/config.toml
    # lld: fast linker (`ld64.lld`) required by .cargo/config.toml on macOS
    # cmake: rdkafka-sys cmake-build configures librdkafka from source
    # curl: Homebrew formula ships curl/curl.h (headers are not on the
    #   default Apple curl PATH that cmake searches)
    brew install sccache lld cmake curl
    ;;
  Linux)
    if command -v apt-get &> /dev/null; then
      echo "Installing mold + clang + cmake + libcurl headers via apt..."
      sudo apt-get update
      # mold/clang: fast linker expected by .cargo/config.toml
      # cmake: rdkafka-sys cmake-build configures librdkafka from source
      # libcurl4-openssl-dev: curl/curl.h; required even with -DWITH_CURL=0
      sudo apt-get install -y mold clang cmake libcurl4-openssl-dev
    elif command -v dnf &> /dev/null; then
      echo "Installing mold + clang + cmake + libcurl headers via dnf..."
      # Same roles as the apt packages above; Fedora/RHEL names differ only
      # for the curl headers package (`libcurl-devel`).
      sudo dnf install -y mold clang cmake libcurl-devel
    else
      echo "This script targets apt- or dnf-based Linux. Install sccache, mold, clang, cmake, and curl development headers (libcurl-devel) manually for your distro." >&2
      exit 1
    fi
    if ! command -v sccache &> /dev/null; then
      if command -v cargo &> /dev/null; then
        echo "Installing sccache via cargo..."
        cargo install sccache --locked
      else
        echo "cargo not on PATH; install Rust first (https://rustup.rs) then re-run." >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "Unsupported OS: ${os}" >&2
    exit 1
    ;;
esac

echo ""
echo "Done. Verify:"
command -v sccache > /dev/null && sccache --version
command -v cmake > /dev/null && cmake --version | head -n 1 || true
case "${os}" in
  Darwin) command -v ld64.lld > /dev/null && ld64.lld --version || true ;;
  Linux)  command -v mold > /dev/null && mold --version || true ;;
esac
echo ""
echo "Optional: set SCCACHE_DIR in your shell profile to relocate the cache,"
echo "  e.g. export SCCACHE_DIR=\"\$HOME/.cache/sccache\"  in ~/.zshrc or ~/.bashrc."
