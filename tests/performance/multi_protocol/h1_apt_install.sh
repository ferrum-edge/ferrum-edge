#!/usr/bin/env bash
# Install Ubuntu packages for the H1 Internal Profile hosted jobs, bounded.
#
# Usage: h1_apt_install.sh PACKAGE...
#
# Mirrors .github/actions/setup-rust-ci: only Ubuntu's own source definition
# is refreshed and installed from (an outage in an unrelated third-party
# repository on the image must not block canonical packages), and the same
# Dir::Etc options reach both `apt-get update` and `apt-get install`.
#
# The runner's regional mirror (for example us-east-2.ec2.archive.ubuntu.com)
# has throttled downloads to ~50 KB/s, turning a ~30 s install into a job
# timeout. The primary attempt therefore runs under a hard budget; if it fails
# or stalls, the same packages are retried once from a temporary copy of the
# Ubuntu source pointing at http://archive.ubuntu.com/ubuntu/. That copy keeps
# the runner's Types/Suites/Components/Signed-By unchanged (h1_apt_sources.py),
# so signature verification is never weakened.
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

# Run one apt command as root, killed (whole process group, including the
# download methods) once the attempt's deadline passes.
bounded() {
  local deadline=$1
  shift
  local remaining=$((deadline - SECONDS))
  if [ "$remaining" -le 0 ]; then
    echo "apt budget exhausted before: $*" >&2
    return 124
  fi
  "${privileged[@]}" timeout --kill-after=30 "$remaining" "$@"
}

attempt() {
  local label=$1 sources=$2 budget=$3
  local deadline=$((SECONDS + budget)) status=0
  local options=(
    -o "Dir::Etc::sourcelist=$sources"
    -o "Dir::Etc::sourceparts=-"
    -o "Acquire::Retries=3"
    -o "Acquire::http::Timeout=30"
  )
  echo "::group::apt-get ($label, ${budget}s budget) from $sources"
  bounded "$deadline" apt-get "${options[@]}" -o "APT::Get::List-Cleanup=0" update || status=$?
  if [ "$status" -eq 0 ]; then
    bounded "$deadline" apt-get "${options[@]}" install -y --no-install-recommends "${packages[@]}" \
      || status=$?
  fi
  echo "::endgroup::"
  return "$status"
}

status=0
attempt primary "$ubuntu_sources" "$primary_timeout" || status=$?
if [ "$status" -eq 0 ]; then
  exit 0
fi
echo "::warning::Ubuntu apt install from the runner mirror failed or timed out (status $status); retrying from http://archive.ubuntu.com/ubuntu/"

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

# A primary attempt killed while dpkg was unpacking leaves packages half
# configured; finish that before installing again.
"${privileged[@]}" timeout --kill-after=30 120 dpkg --configure -a
attempt fallback "$fallback" "$fallback_timeout"
