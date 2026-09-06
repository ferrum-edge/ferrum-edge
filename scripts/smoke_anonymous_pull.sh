#!/usr/bin/env bash
# Prove that a published image can be consumed by a first-time user with NO
# registry credentials: anonymous token acquisition, manifest resolution, an
# image pull, and `ferrum-edge version --json` from the pulled image.
#
# The publishing jobs log in before they push, so their own success never
# demonstrates anonymous access (issue #4637). This script runs with an empty,
# throwaway DOCKER_CONFIG so no credential helper or cached login can leak in.
#
# Usage: bash scripts/smoke_anonymous_pull.sh [--warn-only] IMAGE_REF
#   IMAGE_REF   docker.io/<ns>/<repo>:<tag> or ghcr.io/<owner>/<repo>:<tag>
#   --warn-only emit a GitHub Actions warning instead of failing, for a
#               registry whose visibility is still being enabled
set -euo pipefail

warn_only=false
if [[ "${1:-}" == "--warn-only" ]]; then
  warn_only=true
  shift
fi
if [[ $# -ne 1 || -z "$1" || "$1" == -* ]]; then
  echo "Usage: bash scripts/smoke_anonymous_pull.sh [--warn-only] IMAGE_REF" >&2
  exit 2
fi
image="$1"

# docker.io/<ns>/<repo>:<tag>  |  ghcr.io/<owner>/<repo>:<tag>
registry="${image%%/*}"
remainder="${image#*/}"
repository="${remainder%%[:@]*}"
reference="${remainder#"$repository"}"
reference="${reference#:}"
reference="${reference#@}"
if [[ -z "$reference" ]]; then
  reference="latest"
fi

fail() {
  if [[ "$warn_only" == true ]]; then
    echo "::warning::anonymous pull smoke (${image}): $*"
    exit 0
  fi
  echo "::error::anonymous pull smoke (${image}): $*" >&2
  exit 1
}

case "$registry" in
  docker.io)
    token_url="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repository}:pull"
    registry_host="registry-1.docker.io"
    ;;
  ghcr.io)
    token_url="https://ghcr.io/token?scope=repository%3A${repository//\//%2F}%3Apull&service=ghcr.io"
    registry_host="ghcr.io"
    ;;
  *)
    echo "unsupported registry: ${registry}" >&2
    exit 2
    ;;
esac

# 1. Anonymous token: no Authorization header, no credential helper.
token_response="$(curl -fsS --max-time 30 "$token_url" 2>/dev/null)" \
  || fail "anonymous token request to ${registry} was refused (package private or missing?)"
token="$(printf '%s' "$token_response" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("token") or d.get("access_token") or "")')"
[[ -n "$token" ]] || fail "anonymous token response from ${registry} carried no token"

# 2. Manifest resolution with that token only.
manifest_code="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${token}" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  "https://${registry_host}/v2/${repository}/manifests/${reference}")"
[[ "$manifest_code" == "200" ]] || fail "manifest ${reference} resolved with HTTP ${manifest_code}"

# 3. Pull and run with an empty Docker config: no stored login can be used.
docker_config="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-anon-docker.XXXXXX")"
trap 'rm -rf "$docker_config"' EXIT
export DOCKER_CONFIG="$docker_config"
docker pull --quiet "$image" >/dev/null \
  || fail "docker pull without credentials failed"
version_json="$(docker run --rm --network none "$image" version --json 2>/dev/null)" \
  || fail "the pulled image did not run 'ferrum-edge version --json'"
printf '%s' "$version_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("version"), d' \
  || fail "'version --json' did not report a version"

echo "anonymous pull smoke passed for ${image}: $(printf '%s' "$version_json" | tr -d '\n' | cut -c1-200)"
