#!/usr/bin/env bash
# Install Ubuntu packages for the H1 Internal Profile hosted jobs, bounded.
#
# Usage: h1_apt_install.sh PACKAGE...
#
# Mirrors .github/actions/setup-rust-ci: only Ubuntu's own source definition
# is refreshed and installed from (an outage in an unrelated third-party
# repository on the image must not block canonical packages), and the same
# Dir::Etc options reach `apt-get update`, download, and local install.
#
# The runner's regional mirror (for example us-east-2.ec2.archive.ubuntu.com)
# has throttled downloads to ~50 KB/s, turning a ~30 s install into a job
# timeout. Only the network phases (`update` with Error-Mode=any and
# `install --download-only`) run under the short mirror deadline, so a timeout
# never interrupts dpkg mid-unpack or leaves database locks behind. If the
# primary mirror fails or stalls, the fetch is retried once from a temporary
# copy of the Ubuntu source pointing at http://archive.ubuntu.com/ubuntu/
# (keeping Types/Suites/Components/Signed-By unchanged via h1_apt_sources.py).
# Once all packages are downloaded, `install --no-download` unpacks and
# configures them offline with DEBIAN_FRONTEND=noninteractive.
#
# Test seams: H1_APT_ETC_DIR (default /etc/apt), H1_APT_SUDO (default sudo;
# empty runs apt directly), H1_APT_PRIMARY_TIMEOUT / H1_APT_FALLBACK_TIMEOUT
# (seconds, defaults 300 / 600).
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: h1_apt_install.sh PACKAGE..." >&2
  exit 2
fi
packages=("$@")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
etc_dir=${H1_APT_ETC_DIR:-/etc/apt}
primary_timeout=${H1_APT_PRIMARY_TIMEOUT:-300}
fallback_timeout=${H1_APT_FALLBACK_TIMEOUT:-600}
sudo_cmd=${H1_APT_SUDO-sudo}
for budget in "$primary_timeout" "$fallback_timeout"; do
  if ! [[ $budget =~ ^[1-9][0-9]{0,4}$ ]]; then
    echo "::error::apt budgets must be positive whole seconds" >&2
    exit 2
  fi
done
privileged=()
if [ -n "$sudo_cmd" ]; then privileged=("$sudo_cmd"); fi

if [ -f "$etc_dir/sources.list.d/ubuntu.sources" ]; then
  ubuntu_sources=$etc_dir/sources.list.d/ubuntu.sources
elif [ -f "$etc_dir/sources.list" ]; then
  ubuntu_sources=$etc_dir/sources.list
else
  echo "::error::canonical Ubuntu apt sources are unavailable under $etc_dir" >&2
  exit 1
fi

apt_options() {
  local sources=$1
  APT_OPTS=(
    -o "Dir::Etc::sourcelist=$sources"
    -o "Dir::Etc::sourceparts=-"
    -o "Acquire::Retries=3"
    -o "Acquire::http::Timeout=30"
  )
}

# Run one network apt command as root, killed (whole process group, including
# download methods) once the fetch deadline passes.
bounded() {
  local deadline=$1
  shift
  local remaining=$((deadline - SECONDS))
  if [ "$remaining" -le 0 ]; then
    echo "apt budget exhausted before: $*" >&2
    return 124
  fi
  "${privileged[@]}" env DEBIAN_FRONTEND=noninteractive \
    timeout --kill-after=30 "$remaining" "$@"
}

fetch_attempt() {
  local label=$1 sources=$2 budget=$3
  local deadline=$((SECONDS + budget)) status=0
  apt_options "$sources"
  echo "::group::apt-get fetch ($label, ${budget}s budget) from $sources"
  bounded "$deadline" apt-get "${APT_OPTS[@]}" \
    -o "APT::Get::List-Cleanup=0" \
    -o "APT::Update::Error-Mode=any" \
    update || status=$?
  if [ "$status" -eq 0 ]; then
    bounded "$deadline" apt-get "${APT_OPTS[@]}" \
      install -y --no-install-recommends --download-only -- "${packages[@]}" \
      || status=$?
  fi
  echo "::endgroup::"
  return "$status"
}

install_downloaded() {
  local label=$1 sources=$2
  apt_options "$sources"
  echo "::group::apt-get local install ($label) from $sources"
  "${privileged[@]}" env DEBIAN_FRONTEND=noninteractive \
    apt-get "${APT_OPTS[@]}" \
    install -y --no-install-recommends --no-download -- "${packages[@]}"
  echo "::endgroup::"
}

status=0
fetch_attempt primary "$ubuntu_sources" "$primary_timeout" || status=$?
if [ "$status" -eq 0 ]; then
  install_downloaded primary "$ubuntu_sources"
  exit 0
fi
echo "::warning::Ubuntu apt fetch from the runner mirror failed or timed out (status $status); retrying from http://archive.ubuntu.com/ubuntu/"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
case "$ubuntu_sources" in
  *.sources) fallback=$workdir/ubuntu-canonical.sources ;;
  *) fallback=$workdir/ubuntu-canonical.list ;;
esac
chmod 755 "$workdir"
rewrite=0
python3 "$here/h1_apt_sources.py" "$ubuntu_sources" "$fallback" || rewrite=$?
case "$rewrite" in
  0) chmod 644 "$fallback" ;;
  3)
    echo "::warning::$ubuntu_sources names no regional Ubuntu mirror; retrying it unchanged"
    fallback=$ubuntu_sources
    ;;
  *)
    echo "::error::could not derive a canonical Ubuntu apt source from $ubuntu_sources" >&2
    exit 1
    ;;
esac

fetch_attempt fallback "$fallback" "$fallback_timeout"
install_downloaded fallback "$fallback"
