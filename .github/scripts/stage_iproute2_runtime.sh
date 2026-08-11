#!/bin/sh
# Stage only the iproute2 executable and non-base shared libraries needed by
# distroless/cc-debian13. The final image already owns glibc, its dynamic loader,
# libgcc, and libstdc++; overlaying any of those from debian:13-slim would make
# the base ABI internally inconsistent.
set -eu

stage_root="${1:-/iproute2-root}"
base_root="${2:-}"
iproute2_version="${3:?exact iproute2 package version is required}"
apt-get update
apt-get install -y --no-install-recommends "iproute2=${iproute2_version}"
mkdir -p "${stage_root}/usr/sbin" "${stage_root}/usr/lib" "${stage_root}/usr/lib64"
cp /usr/sbin/ip "${stage_root}/usr/sbin/ip"

ldd /usr/sbin/ip > /tmp/iproute2-ldd
awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' \
    /tmp/iproute2-ldd > /tmp/iproute2-libraries
test -s /tmp/iproute2-libraries

while IFS= read -r library; do
    soname="$(basename "$library")"
    case "$soname" in
        ld-linux-*.so.*|libc.so.*|libdl.so.*|libm.so.*|libpthread.so.*|\
        libresolv.so.*|librt.so.*|libutil.so.*|libanl.so.*|libnss_*.so.*|\
        libgcc_s.so.*|libstdc++.so.*)
            continue
            ;;
    esac
    case "$library" in
        /lib/*|/lib64/*) destination="/usr$library" ;;
        /usr/lib/*|/usr/lib64/*) destination="$library" ;;
        *)
            echo "unexpected iproute2 library path" >&2
            exit 1
            ;;
    esac
    if [ -n "$base_root" ] && [ -e "${base_root}${destination}" ]; then
        continue
    fi
    mkdir -p "${stage_root}$(dirname "$destination")"
    cp -L "$library" "${stage_root}${destination}"
done < /tmp/iproute2-libraries

if find "$stage_root" -type f \
    \( -name 'ld-linux-*.so.*' -o -name 'libc.so.*' -o -name 'libgcc_s.so.*' \
       -o -name 'libstdc++.so.*' \) | grep -q .; then
    echo "iproute2 closure attempted to overlay the distroless base ABI" >&2
    exit 1
fi

rm -rf /var/lib/apt/lists/* /tmp/iproute2-ldd /tmp/iproute2-libraries
