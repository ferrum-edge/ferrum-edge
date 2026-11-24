#!/usr/bin/env bash
# Bootstrap the optional toolchain extras that .cargo/config.toml expects,
# plus the native packages rdkafka-sys needs to compile librdkafka from source
# (`cmake-build` + vendored TLS for kafka_logging; see docs/dependency-policy.md):
# - sccache (rustc-wrapper for cross-branch compile cache). The repository
#   config does not select it (Dependabot's cargo updater has no sccache), so
#   this script also enables it in your user-level $CARGO_HOME/config.toml.
#   Set FERRUM_SKIP_CARGO_WRAPPER_CONFIG=1 to leave that file alone.
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
    # sccache: compiler cache, enabled as the user-level rustc-wrapper below
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

# Enable sccache as the user-level rustc wrapper. The checked-in
# .cargo/config.toml must not name it (see the sccache note there), and cargo
# merges $CARGO_HOME/config.toml under the repository config, so a wrapper set
# here applies to this checkout. It is a per-user setting: it also applies to
# other cargo projects on this machine.
configure_rustc_wrapper() {
  if [ "${FERRUM_SKIP_CARGO_WRAPPER_CONFIG:-}" = "1" ]; then
    echo "FERRUM_SKIP_CARGO_WRAPPER_CONFIG=1: not configuring a rustc wrapper."
    return
  fi
  if ! command -v sccache > /dev/null; then
    echo "sccache is not on PATH; not configuring a rustc wrapper." >&2
    return
  fi
  if [ -n "${RUSTC_WRAPPER:-}" ] || [ -n "${CARGO_BUILD_RUSTC_WRAPPER:-}" ]; then
    echo "RUSTC_WRAPPER / CARGO_BUILD_RUSTC_WRAPPER is already set in this shell; leaving cargo config unchanged."
    return
  fi

  local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  local config="${cargo_home}/config.toml"
  if [ ! -f "$config" ] && [ -f "${cargo_home}/config" ]; then
    config="${cargo_home}/config"
  fi

  if [ -f "$config" ] && grep -Eq '^[[:space:]]*(build\.)?rustc-wrapper[[:space:]]*=' "$config"; then
    echo "${config} already sets a rustc-wrapper; leaving it unchanged."
    return
  fi
  # Appending a second [build] table (or a [build] table after dotted
  # `build.*` keys) would make the file invalid TOML and break every cargo
  # command, so only append to a file that has neither.
  if [ -f "$config" ] && grep -Eq '^[[:space:]]*(\[build\]|build\.)' "$config"; then
    echo "${config} already has build settings. Add this to its [build] table to enable sccache:" >&2
    echo '  rustc-wrapper = "sccache"' >&2
    return
  fi

  mkdir -p "$cargo_home"
  printf '\n[build]\nrustc-wrapper = "sccache"\n' >> "$config"
  echo "Enabled sccache: added build.rustc-wrapper = \"sccache\" to ${config}"
}
configure_rustc_wrapper

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
