#!/usr/bin/env bash
# Build ferrum-edge and ferrum-cni inside the digest-pinned GNU sysroot so
# linked GLIBC symbols cannot track the GitHub-hosted runner image.
#
# Cargo output is isolated under /src/target/linux-gnu-sysroot so a restored
# native ubuntu-26.04 `target/<triple>/release` tree cannot contaminate the
# pinned sysroot link. After a successful container build, only the two
# regular, non-symlink binaries are copied to the canonical paths consumed
# by ABI scans and artifact uploads.
set -euo pipefail

contract="${GITHUB_WORKSPACE:-.}/.github/linux-gnu-abi.toml"
if [[ ! -f "$contract" ]]; then
  echo "::error::missing GNU ABI contract $contract" >&2
  exit 1
fi

sysroot_image="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["image"])' "$contract")"
sysroot_platform="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["platform"])' "$contract")"
protoc_url="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["protoc_url"])' "$contract")"
protoc_sha256="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["protoc_sha256"])' "$contract")"

if [[ -n "${LINUX_GNU_SYSROOT_IMAGE:-}" && "$LINUX_GNU_SYSROOT_IMAGE" != "$sysroot_image" ]]; then
  echo "::error::LINUX_GNU_SYSROOT_IMAGE does not match .github/linux-gnu-abi.toml" >&2
  exit 1
fi
if [[ -n "${LINUX_GNU_PROTOC_SHA256:-}" && "$LINUX_GNU_PROTOC_SHA256" != "$protoc_sha256" ]]; then
  echo "::error::LINUX_GNU_PROTOC_SHA256 does not match .github/linux-gnu-abi.toml" >&2
  exit 1
fi

target="${LINUX_GNU_TARGET:?LINUX_GNU_TARGET is required}"
features="${LINUX_GNU_FEATURES:?LINUX_GNU_FEATURES is required}"
profile="${LINUX_GNU_PROFILE:-release}"

if [[ "$target" != "x86_64-unknown-linux-gnu" ]]; then
  echo "::error::GNU sysroot builder only produces the x86_64 GNU target" >&2
  exit 1
fi

docker pull --platform "$sysroot_platform" "$sysroot_image"

work_root="$(pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
mkdir -p "$cargo_home" "$rustup_home"

# Create the bind-mounted parent as the host user before the rootful container
# creates the isolated build subtree. The container repairs ownership only on
# that dedicated subtree; keeping the parent host-owned lets the controlled
# post-build copy create the canonical target triple without broad chown.
target_root="$work_root/target"
if [[ -L "$target_root" ]]; then
  echo "::error::host target root $target_root is a symlink" >&2
  exit 1
fi
mkdir -p -- "$target_root"
if [[ ! -d "$target_root" || ! -w "$target_root" ]]; then
  echo "::error::host target root $target_root must be a writable directory" >&2
  exit 1
fi

host_uid="$(id -u)"
host_gid="$(id -g)"

# `.cargo/config.toml` sets linker=clang and -fuse-ld=mold. The sysroot has
# neither mold nor a rustflags-safe clang as the GNU target linker.
# RUSTFLAGS= (empty) is the override that replaces target rustflags; cargo
# skips `[target.<triple>] rustflags` once RUSTFLAGS is set.
# CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS= is cleared at the same
# precedence as the linker override so the x86_64 intent is explicit. It is
# not a substitute: CARGO_TARGET_*_RUSTFLAGS merges with config when
# RUSTFLAGS is unset. mold is not installed in the sysroot, so a regression
# fails the link instead of silently changing the floor.
docker run --rm \
  --platform "$sysroot_platform" \
  --volume "$work_root:/src:rw" \
  --volume "$cargo_home:/opt/cargo:rw" \
  --volume "$rustup_home:/opt/rustup:rw" \
  --workdir /src \
  --env CARGO_HOME=/opt/cargo \
  --env RUSTUP_HOME=/opt/rustup \
  --env PATH="/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  --env CARGO_TERM_COLOR=always \
  --env LIBZ_SYS_STATIC=1 \
  --env RUSTC_WRAPPER= \
  --env CARGO_BUILD_RUSTC_WRAPPER= \
  --env RUSTFLAGS= \
  --env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  --env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS= \
  --env CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot \
  --env PROTOC_URL="$protoc_url" \
  --env PROTOC_SHA256="$protoc_sha256" \
  --env LINUX_GNU_TARGET="$target" \
  --env LINUX_GNU_FEATURES="$features" \
  --env LINUX_GNU_PROFILE="$profile" \
  --env HOST_UID="$host_uid" \
  --env HOST_GID="$host_gid" \
  "$sysroot_image" \
  bash -lc '
    set -euo pipefail
    if [[ "${CARGO_TARGET_DIR:-}" != "/src/target/linux-gnu-sysroot" ]]; then
      echo "::error::CARGO_TARGET_DIR must be /src/target/linux-gnu-sysroot" >&2
      exit 1
    fi
    mkdir -p /src/target/linux-gnu-sysroot
    # Compiler/linker packages are deliberately unpinned. The base image is
    # digest-pinned and AlmaLinux repos are GPG-signed, but dnf still resolves
    # gcc/binutils/clang against the live 8.10 repo, so NVRs can move between
    # runs. Pinning exact NVRs would break the builder when security updates
    # retire the old package. The ABI scanner is the fail-closed bound on the
    # published DT_NEEDED / GLIBC version-need set.
    dnf -y install gcc gcc-c++ make cmake zlib-devel perl unzip curl ca-certificates libcurl-devel openssl-devel clang clang-devel
    export LIBCLANG_PATH=/usr/lib64
    if ! compgen -G "$LIBCLANG_PATH/libclang.so*" > /dev/null; then
      echo "::error::pinned sysroot is missing libclang under $LIBCLANG_PATH; bindgen build scripts cannot run" >&2
      exit 1
    fi
    curl -fsSL "$PROTOC_URL" -o /tmp/protoc.zip
    echo "$PROTOC_SHA256  /tmp/protoc.zip" | sha256sum -c -
    unzip -o /tmp/protoc.zip -d /usr/local bin/protoc
    chmod +x /usr/local/bin/protoc
    rm /tmp/protoc.zip
    export PROTOC=/usr/local/bin/protoc
    cargo build --features "$LINUX_GNU_FEATURES" --profile "$LINUX_GNU_PROFILE" --target "$LINUX_GNU_TARGET" --target-dir /src/target/linux-gnu-sysroot
    chown -R "${HOST_UID}:${HOST_GID}" \
      /src/target/linux-gnu-sysroot \
      /opt/cargo \
      /opt/rustup
  '

copy_sysroot_binary() {
  local name="$1"
  local src="$work_root/target/linux-gnu-sysroot/${target}/${profile}/${name}"
  local dest="$work_root/target/${target}/${profile}/${name}"
  if [[ ! -e "$src" ]]; then
    echo "::error::pinned sysroot build did not produce ${name} at ${src}" >&2
    exit 1
  fi
  if [[ -L "$src" ]]; then
    echo "::error::pinned sysroot output ${src} is a symlink" >&2
    exit 1
  fi
  if [[ ! -f "$src" ]]; then
    echo "::error::pinned sysroot output ${src} is not a regular file" >&2
    exit 1
  fi
  mkdir -p "$work_root/target/${target}/${profile}"
  if [[ -L "$dest" ]]; then
    echo "::error::canonical output path ${dest} is a symlink" >&2
    exit 1
  fi
  cp -f -- "$src" "$dest"
  if [[ -L "$dest" || ! -f "$dest" ]]; then
    echo "::error::canonical copy of ${name} is not a regular file" >&2
    exit 1
  fi
}

copy_sysroot_binary ferrum-edge
copy_sysroot_binary ferrum-cni
