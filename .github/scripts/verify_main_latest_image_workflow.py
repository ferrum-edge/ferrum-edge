#!/usr/bin/env python3
"""Static contract for the main `latest` image publisher.

Owner decision 2026-09-28: the Docker `latest` tag tracks the newest `main`
commit whose push CI succeeded. This verifier pins the fail-closed shape of
`.github/workflows/main-latest-image.yml`:

* it is triggered only by completed CI runs on `main`, and its first job
  proceeds only for a successful `push` run of ci.yml in this repository;
* nothing is published unless the CI-validated commit is on main's history,
  and `latest` moves only while that still holds and only forward: when the
  commit `latest` names now is on main's history, it must be an ancestor of
  this one. Both checks run again, through pinned helpers that are actually
  invoked, immediately before each registry's move. A compare 404 counts as
  "not on main's history" only when GitHub reports no common ancestor or the
  commits API does not know one of the commits; otherwise the run fails;
* every run that can publish shares one workflow-level concurrency group with
  cancel-in-progress disabled, so publishers and moves of `latest` never
  overlap;
* an already signed `main-<sha>` is reused rather than rebuilt, and only after
  its signature verifies under the pinned signing identity, in a job that
  never checks out the repository and reads Docker Hub anonymously;
* credential isolation: only the credential-free `contract` and `smoke` jobs
  check out or execute repository code, `contract` runs Python only as
  `python3 -I`, and no job holding a secret or a registry token checks out the
  repository, runs a repository script, or runs the built image. Syft, which
  parses the built image, runs with no credential: it scans the public Docker
  Hub image anonymously, and the GHCR attestations reuse those SBOMs;
* anonymous Docker Hub reads in `resolve`, the Syft scan, and `smoke` retry
  throttled, failed, or dropped requests with exponential backoff, at most
  three attempts in all;
* every job holds exactly its least-privilege permissions, the downstream jobs
  require every needed job to have succeeded, and only the release registry
  secrets are referenced;
* every remote action is pinned by full commit SHA to the same pin release.yml
  uses, and no workflow expression is interpolated into a shell body;
* only the `main-<sha>` tags and `latest` are pushed, never a version tag or an
  eBPF variant. The build runs from the public Git URL of the CI-validated
  commit, each platform image is smoke-run by digest before the manifest, and
  the digest is attested and then signed, verified under the pinned identity
  and issuer, and `latest` is created only from the digest reference that the
  verify step exported, then checked to resolve to it.

It reads files only; it does not contact a registry or execute the workflow.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "main-latest-image.yml"
RELEASE_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"

EXPECTED_ON = (
    "on:\n"
    "  workflow_run:\n"
    "    workflows:\n"
    "      - CI\n"
    "    types:\n"
    "      - completed\n"
    "    branches:\n"
    "      - main\n"
)
# One group for every run that can publish; runs for other events or
# conclusions land in other groups and cannot displace a waiting publisher.
EXPECTED_CONCURRENCY = (
    "concurrency:\n"
    "  group: main-latest-image-${{ github.repository }}-"
    "${{ github.event.workflow_run.path }}-${{ github.event.workflow_run.event }}-"
    "${{ github.event.workflow_run.conclusion }}\n"
    "  cancel-in-progress: false\n"
)
EXPECTED_TOP_PERMISSIONS = "permissions:\n  contents: read\n"
EXPECTED_JOB_PERMISSIONS = {
    "resolve": {"contents": "read", "packages": "read"},
    "contract": {"contents": "read"},
    "build": {"contents": "read", "packages": "write"},
    "smoke": {"contents": "read"},
    "manifest": {"contents": "read", "packages": "write"},
    "attest": {"id-token": "write", "packages": "write"},
    "promote": {"contents": "read", "packages": "write"},
}
EXPECTED_NEEDS = {
    "resolve": None,
    "contract": "resolve",
    "build": "[resolve, contract]",
    "smoke": "[resolve, build]",
    "manifest": "[resolve, build, smoke]",
    "attest": "[resolve, contract, manifest]",
    "promote": "[resolve, contract, attest]",
}
# The only jobs that may check out or execute repository code. They hold no
# secret, no registry login, and no token beyond `contents: read`.
CREDENTIAL_FREE_JOBS = frozenset({"contract", "smoke"})
RESOLVE_CONDITIONS = (
    "github.repository == 'ferrum-edge/ferrum-edge'",
    "github.event.workflow_run.conclusion == 'success'",
    "github.event.workflow_run.event == 'push'",
    "github.event.workflow_run.head_branch == 'main'",
    "github.event.workflow_run.path == '.github/workflows/ci.yml'",
    "github.event.workflow_run.head_repository.full_name == github.repository",
)
BUILD_GATE = "needs.resolve.outputs.publish == 'true' && needs.resolve.outputs.build == 'true'"
# `manifest` is skipped when `resolve` reuses a signed `main-<sha>`, so the two
# downstream jobs replace the implicit success() with explicit result checks
# that name every needed job.
EXPECTED_JOB_IFS = {
    "contract": "needs.resolve.outputs.publish == 'true'",
    "build": BUILD_GATE,
    "smoke": BUILD_GATE,
    "manifest": BUILD_GATE,
    "attest": (
        "${{ !cancelled() && needs.resolve.result == 'success' && "
        "needs.contract.result == 'success' && needs.resolve.outputs.publish == 'true' && "
        "(needs.manifest.result == 'success' || "
        "(needs.manifest.result == 'skipped' && needs.resolve.outputs.build == 'false')) }}"
    ),
    "promote": (
        "${{ !cancelled() && needs.resolve.result == 'success' && "
        "needs.contract.result == 'success' && needs.attest.result == 'success' && "
        "needs.resolve.outputs.publish == 'true' }}"
    ),
}
RESOLVE_OUTPUTS = (
    "    outputs:\n"
    "      publish: ${{ steps.head.outputs.publish }}\n"
    "      sha: ${{ steps.head.outputs.sha }}\n"
    "      build: ${{ steps.existing.outputs.build }}\n"
)
ATTEST_OUTPUTS = (
    "    outputs:\n"
    "      docker_ref: ${{ steps.verify.outputs.docker_ref }}\n"
    "      ghcr_ref: ${{ steps.verify.outputs.ghcr_ref }}\n"
)
PROMOTE_ENV = (
    "          DOCKER_REF: ${{ needs.attest.outputs.docker_ref }}\n",
    "          GHCR_REF: ${{ needs.attest.outputs.ghcr_ref }}\n",
)
HEAD_LOOKUP = 'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"'
WORKFLOW_SHA_COMPARE = 'if ! is_ancestor "$SOURCE_SHA" "$GITHUB_SHA"; then'
HEAD_COMPARE = 'if ! is_ancestor "$SOURCE_SHA" "$main_head"; then'
LATEST_FORWARD = 'if is_ancestor "$revision" "$SOURCE_SHA"; then'
# A revision that is not on main's history cannot be newer: warn and move.
LATEST_ORPHAN = 'if ! is_ancestor "$revision" "$main_head"; then'
DIGEST_COMPARE = 'if [ "$actual" != "${expected_ref#*@}" ]; then'
# GitHub's compare reports `ahead` or `identical` exactly when base is an
# ancestor of, or equal to, head. A compare 404 means "not an ancestor" only
# when it is corroborated: no common ancestor, or the commits API does not know
# one of the two commits. An uncorroborated 404, like any other answer, must
# stop the run, so a spurious 404 can never move `latest` backwards.
UNCORROBORATED_404 = 'if [ "$corroborated" != true ]; then'
IS_ANCESTOR = (
    "          is_ancestor() {\n"
    '            local base="$1"\n'
    '            local head="$2"\n'
    "            local status\n"
    "            local compare_err\n"
    "            local commit_err\n"
    "            local commit\n"
    "            local corroborated\n"
    '            compare_err="$(mktemp)"\n'
    '            commit_err="$(mktemp)"\n'
    '            status="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${base}...${head}'
    "?per_page=1\" --jq '.status' 2>\"$compare_err\" || true)\"\n"
    "            if grep -q 'HTTP 404' \"$compare_err\"; then\n"
    "              corroborated=false\n"
    "              if grep -qi 'no common ancestor' \"$compare_err\"; then\n"
    "                corroborated=true\n"
    "              fi\n"
    '              for commit in "$base" "$head"; do\n'
    '                if ! gh api "repos/${GITHUB_REPOSITORY}/commits/${commit}" '
    "--jq '.sha' >/dev/null 2>\"$commit_err\" &&\n"
    "                  grep -Eq 'HTTP 404|No commit found for SHA' \"$commit_err\"; then\n"
    "                  corroborated=true\n"
    "                fi\n"
    "              done\n"
    f"              {UNCORROBORATED_404}\n"
    '                echo "::error::compare ${base}...${head} returned 404, but both commits '
    "exist and GitHub reported no missing common ancestor; refusing to treat ${base} as "
    'off main\'s history" >&2\n'
    '                cat "$compare_err" >&2\n'
    "                exit 1\n"
    "              fi\n"
    '              status="missing"\n'
    "            fi\n"
    '            case "$status" in\n'
    "              ahead | identical) return 0 ;;\n"
    "              behind | diverged | missing) return 1 ;;\n"
    "              *)\n"
    '                echo "::error::could not compare ${base} with ${head}" >&2\n'
    '                cat "$compare_err" >&2\n'
    "                exit 1\n"
    "                ;;\n"
    "            esac\n"
    "          }\n"
)
# The one identity and issuer a `main-<sha>` signature may carry, used both to
# reuse an existing image and to verify before `latest` moves.
VERIFY_IDENTITY = (
    '          certificate_identity="https://github.com/ferrum-edge/ferrum-edge/'
    '.github/workflows/main-latest-image.yml@refs/heads/main"\n'
    '          oidc_issuer="https://token.actions.githubusercontent.com"\n'
    "          verify_common_args=(\n"
    '            --certificate-identity "$certificate_identity"\n'
    '            --certificate-oidc-issuer "$oidc_issuer"\n'
    "            --certificate-github-workflow-repository ferrum-edge/ferrum-edge\n"
    "            --certificate-github-workflow-ref refs/heads/main\n"
    "            --certificate-github-workflow-trigger workflow_run\n"
    "          )\n"
)
REUSE_SIGNED_CHECK = (
    'registry_read "$work/verify.err" cosign verify "${verify_common_args[@]}" '
    '"$image_ref" > "$work/signature.json" &&'
)
REUSE_INSPECT = (
    'manifest="$(registry_read "$work/inspect.err" docker buildx imagetools inspect '
    '"$tag_ref" --format \'{{json .Manifest}}\')"'
)
# Docker Hub is read anonymously, so `resolve`, the Syft scan, and `smoke` retry
# a throttled, failed, or dropped registry read with exponential backoff, at
# most three attempts in all, and stop the run once the retries are exhausted.
REGISTRY_READ = (
    "          transient_registry_error='toomanyrequests|too many requests|"
    "internal server error|bad gateway|service unavailable|timeout|connection reset|"
    "connection refused|no such host|temporary failure|\\beof\\b|deadline exceeded'\n"
    "          registry_read() {\n"
    '            local err_file="$1"\n'
    "            shift\n"
    "            local attempt\n"
    "            for attempt in 1 2 3; do\n"
    '              if "$@" >"${err_file}.out" 2>"$err_file"; then\n'
    '                cat "${err_file}.out"\n'
    "                return 0\n"
    "              fi\n"
    '              if ! grep -Eqi "$transient_registry_error" "$err_file"; then\n'
    "                return 1\n"
    "              fi\n"
    '              if [ "$attempt" -lt 3 ]; then\n'
    '                echo "::warning::transient registry error (attempt ${attempt} of 3); '
    'retrying" >&2\n'
    '                sleep $((10 * 2 ** (attempt - 1)))\n'
    "              fi\n"
    "            done\n"
    '            echo "::error::registry read still failing after 3 attempts" >&2\n'
    '            cat "$err_file" >&2\n'
    "            exit 1\n"
    "          }\n"
)
REUSE_SIGNED_CALLS = (
    'signed "ferrumedge/ferrum-edge@${docker_digest}"',
    'signed "ghcr.io/${GITHUB_REPOSITORY}@${ghcr_digest}"',
)
SIGN_IF = "\n        if: needs.resolve.outputs.build == 'true'\n"
SIGN_CALLS = (
    '          sign_and_attest docker "$DOCKER_REF"',
    '          sign_and_attest ghcr "$GHCR_REF"',
)
VERIFY_SNIPPETS = (
    'cosign verify \\\n              "${verify_common_args[@]}" \\\n              "$image_ref"',
    "cosign verify-attestation \\\n"
    '              "${verify_common_args[@]}" \\\n'
    "              --type slsaprovenance1",
    "cosign verify-attestation \\\n"
    '              "${verify_common_args[@]}" \\\n'
    "              --type spdxjson",
    '-f "$work/require_signature.jq"',
    '-f "$work/require_provenance.jq"',
    '-f "$work/require_sbom_attest.jq"',
)
VERIFY_IMAGE_CALLS = (
    '          verify_image docker "$DOCKER_REF"',
    '          verify_image ghcr "$GHCR_REF"',
)
VERIFY_OUTPUT_LINES = (
    'echo "docker_ref=${DOCKER_REF}" >> "$GITHUB_OUTPUT"',
    'echo "ghcr_ref=${GHCR_REF}" >> "$GITHUB_OUTPUT"',
)
SMOKE_PULL = (
    'if ! registry_read "$pull_err" docker pull "ferrumedge/ferrum-edge@${DIGEST}"; then'
)
SMOKE_RUN = (
    'version_json="$(docker run --rm --network none --pull never '
    '"ferrumedge/ferrum-edge@${DIGEST}" version --json)"'
)
SMOKE_CHECK = (
    "jq -e '.version | type == \"string\" and length > 0' <<<\"$version_json\" >/dev/null"
)
PROMOTE_FUNCTIONS = (
    "require_verified_ref",
    "is_ancestor",
    "require_on_main",
    "require_latest_not_newer",
    "require_latest",
    "summarize",
)
# The top-level statements of the promote step, in order: every gate is
# invoked, and each registry's move is bracketed by its own checks.
PROMOTE_SEQUENCE = (
    "set -euo pipefail",
    'require_verified_ref "ferrumedge/ferrum-edge" "$DOCKER_REF"',
    'require_verified_ref "ghcr.io/${GITHUB_REPOSITORY}" "$GHCR_REF"',
    "require_on_main",
    'require_latest_not_newer "ferrumedge/ferrum-edge"',
    'docker buildx imagetools create -t "ferrumedge/ferrum-edge:latest" "$DOCKER_REF"',
    'require_latest "ferrumedge/ferrum-edge:latest" "$DOCKER_REF"',
    "require_on_main",
    'require_latest_not_newer "ghcr.io/${GITHUB_REPOSITORY}"',
    'docker buildx imagetools create -t "ghcr.io/${GITHUB_REPOSITORY}:latest" "$GHCR_REF"',
    'require_latest "ghcr.io/${GITHUB_REPOSITORY}:latest" "$GHCR_REF"',
    "summarize",
)
PROMOTE_SOURCES = {
    '"ferrumedge/ferrum-edge:latest"': '"$DOCKER_REF"',
    '"ghcr.io/${GITHUB_REPOSITORY}:latest"': '"$GHCR_REF"',
}
# Only `contract` checks out the repository: the running workflow's own commit.
CHECKOUT_REFS = {
    "contract": "ref: ${{ github.sha }}",
}
# The whole `contract` script: both verifier modes, isolated from the checkout.
CONTRACT_RUN = (
    "          set -euo pipefail\n"
    "          python3 -I .github/scripts/verify_main_latest_image_workflow.py --self-test\n"
    "          python3 -I .github/scripts/verify_main_latest_image_workflow.py"
)
# BuildKit fetches the CI-validated commit from the public repository, so the
# credentialed build never checks out the repository, and the empty token keeps
# the job token out of the build (no GIT_AUTH_TOKEN secret to mount).
BUILD_CONTEXT = (
    "          context: https://github.com/ferrum-edge/ferrum-edge.git"
    "#${{ needs.resolve.outputs.sha }}\n"
)
BUILD_GIT_TOKEN = '          github-token: ""\n'
IMMUTABLE_TAGS = [
    '"ferrumedge/ferrum-edge:main-${SOURCE_SHA}"',
    '"ghcr.io/${GITHUB_REPOSITORY}:main-${SOURCE_SHA}"',
]
LATEST_TAGS = list(PROMOTE_SOURCES)
TAGS_BY_JOB = {
    "manifest": IMMUTABLE_TAGS,
    "promote": LATEST_TAGS,
}
ALLOWED_SECRETS = frozenset({"DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GITHUB_TOKEN"})
SYFT_IMAGE = (
    "anchore/syft@sha256:"
    "9a9f85314017f1ea798fb012edfa7fe9259923910f82c8d4bc983ab5c765e60b"
)
# Syft parses the image the repository built, so its step references no secret
# or token and its container gets no registry auth: it scans the public Docker
# Hub image anonymously (through the bounded retry) into its own new output
# directory, and the GHCR attestations reuse those SBOMs (the `images` step
# proved both registries hold identical platform descriptors). This is the whole
# Syft command, joined.
SYFT_RUN = (
    'if ! registry_read "$work/syft.err" docker run --rm -e SYFT_CHECK_FOR_APP_UPDATE=false '
    '-v "$sbom_dir:/out" '
    + SYFT_IMAGE
    + ' scan "registry:${DOCKER_REF}" --platform "$platform" '
    '-o "spdx-json=/out/${arch}.spdx.json"; then'
)
SYFT_OUTPUT_DIR = ('sbom_dir="$RUNNER_TEMP/syft-output"', 'mkdir "$sbom_dir"')
SYFT_CREDENTIAL_MARKERS = (
    "SYFT_REGISTRY",
    "DOCKERHUB",
    "TOKEN",
    "PASSWORD",
    "github.token",
    "--env-file",
    "docker.sock",
    "$work:",
    "/.docker",
    "config.json",
    "DOCKER_CONFIG",
)
BUILD_PARITY_LINES = (
    "          target: runtime\n",
    "            FEATURES=cloud-secrets\n",
    "          provenance: false\n",
    "            platform: linux/amd64\n",
    "            platform: linux/arm64\n",
    "          - os: ubuntu-latest\n",
    "          - os: ubuntu-24.04-arm\n",
)
FORBIDDEN_ACTIVE_TEXT = (
    ("-ebpf", "eBPF image variants are published only by release.yml"),
    ("refs/tags", "version tags are published only by release.yml"),
    ("github.ref_name", "version tags are published only by release.yml"),
    ("TAG_NAME", "version tags are published only by release.yml"),
    ("MAJOR_MINOR", "version tags are published only by release.yml"),
    ("pull_request", "the publisher must never run for a pull request"),
    ("workflow_dispatch", "the publisher must only follow successful main CI"),
    ("continue-on-error", "publisher steps must fail closed"),
    ("always()", "publisher jobs must not run after a failed dependency"),
    ("failure()", "publisher jobs must not run after a failed dependency"),
    ("write-all", "permissions must be granted per job, never write-all"),
    ("read-all", "permissions must be granted per job, never read-all"),
    ("docker push", "images are pushed only by digest and imagetools"),
    ("docker tag", "images are tagged only by imagetools create"),
)
PROMOTE_FORBIDDEN = ("unset ", "alias ", "set +e")
# Commands that would run repository code on a credentialed host: an
# interpreter, a build tool, git, or a repository-relative path.
REPOSITORY_EXECUTION = re.compile(
    r"(?<![\w./$-])(?:python[0-9.]*|bash|sh|source|make|cargo|npm|npx|node|pip[0-9]*|git)"
    r"(?![\w.+-])|\.github/scripts|(?<![\w.}$-])\./"
)
PYTHON_INVOCATION = re.compile(r"(?<![\w./-])python[0-9.]*(?![\w.-])(?P<flag> -I )?")
REMOTE_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)", re.MULTILINE)
PINNED_REF = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{40})$")
RUN_KEY = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<value>.*)$")
TAG_ARGUMENT = re.compile(r"(?:^|\s)(?:-t|--tag)(?:\s+|=)(?P<tag>\S+)")
FUNCTION_START = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\(\) \{$")
# `cloud-secrets` is a Cargo feature, not the `secrets` context. Expression
# context names are case-insensitive, so `SECRETS.X` is the same reference.
SECRET_REFERENCE = re.compile(
    r"(?<![\w-])secrets\b(?P<field>\.[A-Za-z0-9_]+)?", re.IGNORECASE
)

RESOLVE_WORKFLOW_MESSAGE = (
    "jobs.resolve must skip unless the running workflow contains the validated commit"
)
RESOLVE_HEAD_MESSAGE = "jobs.resolve must skip when the commit is no longer on main's history"
RESOLVE_IDENTITY_MESSAGE = (
    "jobs.resolve may reuse main-<sha> only under the pinned main-latest-image.yml "
    "signing identity and issuer"
)
REUSE_MESSAGE = (
    "jobs.resolve may skip the build only after verifying a signed main-<sha> in both "
    "registries"
)
SMOKE_MESSAGE = (
    "jobs.smoke must run each pushed platform image by its downloaded digest, "
    "unconditionally, before jobs.manifest"
)
SIGN_MESSAGE = (
    "jobs.attest must attest provenance and SBOMs and then sign each registry's digest "
    "whenever it built one"
)
VERIFY_MESSAGE = (
    "jobs.attest must verify signatures, provenance, and SBOMs of both registries in "
    "one unconditional `id: verify` step after signing, and export only those references"
)
ATTEST_IDENTITY_MESSAGE = (
    "jobs.attest must verify under the pinned main-latest-image.yml signing identity "
    "and issuer"
)
ATTEST_OUTPUTS_MESSAGE = (
    "jobs.attest must expose only the digest references its verify step checked"
)
PROMOTE_SOURCE_MESSAGE = (
    "jobs.promote must create latest only from the verified digest reference exported "
    "by jobs.attest's verify step"
)
PROMOTE_ON_MAIN_MESSAGE = (
    "jobs.promote must leave latest unchanged when the commit is no longer on main"
)
PROMOTE_BACKWARDS_MESSAGE = (
    "jobs.promote must leave latest unchanged when it already names a newer commit"
)
PROMOTE_ORPHAN_MESSAGE = (
    "jobs.promote must warn and move latest when the commit it names is not on "
    "main's history, instead of blocking forever"
)
PROMOTE_DIGEST_MESSAGE = (
    "jobs.promote must fail when latest does not resolve to the verified digest"
)
RESOLVE_LAST_STEP_MESSAGE = (
    "jobs.resolve must end with its `id: existing` step, so build=false is its final output"
)
RESOLVE_ANONYMOUS_MESSAGE = (
    "jobs.resolve must read Docker Hub anonymously: no Docker Hub credential and "
    "only the GHCR read login"
)
CONTRACT_MESSAGE = (
    "jobs.contract must check out the running workflow's commit and run exactly both "
    "verifier modes with `python3 -I`"
)
BUILD_CONTEXT_MESSAGE = (
    "jobs.build must build from the public Git URL pinned to the CI-validated commit "
    'with github-token: ""'
)
CHECKOUT_MESSAGE = "must not check out the repository: it holds registry credentials"
CREDENTIAL_FREE_MESSAGE = (
    "runs repository code, so it must hold no secret, registry login, or token "
    "beyond contents: read"
)
REPOSITORY_EXECUTION_MESSAGE = (
    "holds registry credentials, so its shell must not run an interpreter, git, "
    "a build tool, or a repository script"
)
IMAGE_RUN_MESSAGE = (
    "holds registry credentials, so it may run only the pinned Syft image, never the "
    "built image"
)
PYTHON_ISOLATION_MESSAGE = "every Python invocation must be `python3 -I`"
SYFT_MESSAGE = (
    "jobs.attest must run Syft once, anonymously: its step references no secret or "
    "token, and it runs exactly the pinned credential-free scan of the Docker Hub image"
)
REGISTRY_RETRY_MESSAGE = (
    "must read Docker Hub anonymously through the pinned bounded-retry registry_read "
    "helper"
)


def active_text(text: str) -> str:
    """Drop comment-only lines so prose cannot satisfy or trip a check."""

    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def top_level_block(text: str, key: str) -> tuple[str | None, list[str]]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if re.match(rf"^{re.escape(key)}:", line)]
    if len(starts) != 1:
        return None, [f"workflow must contain exactly one top-level {key}: block"]
    block = [lines[starts[0]]]
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            break
        block.append(line)
    return "\n".join(block) + "\n", []


def job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    headers = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == "jobs:"]
    if len(headers) != 1:
        return {}
    blocks: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    for line in lines[headers[0] + 1 :]:
        if re.match(r"^[A-Za-z0-9_-]+:", line):
            break
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            if current is not None:
                blocks[current] = "".join(body)
            current = match.group(1)
            body = []
            continue
        if current is not None:
            body.append(line)
    if current is not None:
        blocks[current] = "".join(body)
    return blocks


def job_field(block: str, field: str) -> str | None:
    matches = re.findall(rf"^    {re.escape(field)}:[ \t]*(.*)$", block, re.MULTILINE)
    if len(matches) != 1:
        return None
    return matches[0].strip()


def job_permissions(block: str) -> dict[str, str] | None:
    lines = block.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "    permissions:"]
    if len(starts) != 1:
        return None
    permissions: dict[str, str] = {}
    for line in lines[starts[0] + 1 :]:
        match = re.match(r"^      ([a-z-]+):\s*([a-z]+)\s*$", line)
        if match is None:
            break
        permissions[match.group(1)] = match.group(2)
    return permissions


def run_bodies(block: str) -> list[str]:
    """Return every `run:` script in a job, block scalars included."""

    lines = block.splitlines()
    bodies: list[str] = []
    index = 0
    while index < len(lines):
        match = RUN_KEY.match(lines[index])
        if match is None:
            index += 1
            continue
        value = match.group("value").strip()
        key_indent = len(match.group("indent"))
        if value[:1] not in {"|", ">"}:
            bodies.append(value)
            index += 1
            continue
        body: list[str] = []
        cursor = index + 1
        while cursor < len(lines):
            line = lines[cursor]
            if line.strip() and len(line) - len(line.lstrip(" ")) <= key_indent:
                break
            body.append(line)
            cursor += 1
        bodies.append("\n".join(body))
        index = cursor
    return bodies


def step_blocks(block: str) -> list[str]:
    steps: list[str] = []
    current: list[str] | None = None
    for line in block.splitlines():
        if re.match(r"^      - ", line):
            if current is not None:
                steps.append("\n".join(current))
            current = [line]
        elif current is not None:
            if line.strip() and not line.startswith("       "):
                steps.append("\n".join(current))
                current = None
            else:
                current.append(line)
    if current is not None:
        steps.append("\n".join(current))
    return steps


def branch_contains(body: str, compare: str, needle: str) -> bool:
    """The branch opened by `compare` must contain `needle` before its `fi`."""

    start = body.find(compare)
    if start < 0:
        return False
    end = re.search(r"^\s*fi\s*$", body[start:], re.MULTILINE)
    if end is None:
        return False
    return needle in body[start : start + end.start()]


def stale_branch_exits_cleanly(body: str, compare: str) -> bool:
    """The stale branch of a history check must skip publication, not fall through."""

    return branch_contains(body, compare, "exit 0")


def shell_structure(body: str) -> tuple[dict[str, list[str]], list[str]]:
    """Split a run body into its top-level function definitions and statements.

    Continuation lines are joined, so a multi-line command is one statement.
    Every definition of a name is kept, so a redefinition stays visible.
    """

    lines = [
        line
        for line in body.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        return {}, []
    base = len(lines[0]) - len(lines[0].lstrip(" "))
    functions: dict[str, list[str]] = {}
    statements: list[str] = []
    current: str | None = None
    function_lines: list[str] = []
    pending: list[str] = []
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        if current is not None:
            if indent == base and text == "}":
                functions.setdefault(current, []).append("\n".join(function_lines))
                current = None
                function_lines = []
            else:
                function_lines.append(line)
            continue
        if pending:
            pending.append(text.rstrip("\\").strip())
            if not text.endswith("\\"):
                statements.append(" ".join(pending))
                pending = []
            continue
        match = FUNCTION_START.match(text)
        if indent == base and match is not None:
            current = match.group("name")
            continue
        if text.endswith("\\"):
            pending = [text.rstrip("\\").strip()]
            continue
        statements.append(text)
    if pending:
        statements.append(" ".join(pending))
    if current is not None:
        functions.setdefault(current, []).append("\n".join(function_lines))
    return functions, statements


def release_action_pins(release_text: str) -> dict[str, set[str]]:
    pins: dict[str, set[str]] = {}
    for match in REMOTE_USES.finditer(active_text(release_text)):
        pinned = PINNED_REF.match(match.group("ref"))
        if pinned is not None:
            pins.setdefault(pinned.group("name"), set()).add(pinned.group("sha"))
    return pins


def credential_isolation_errors(job_name: str, block: str) -> list[str]:
    """Repository code and registry credentials never share a job."""

    job_active = active_text(block)
    permissions = job_permissions(block) or {}
    credentialed = (
        any(scope != "contents" for scope in permissions)
        or any(level != "read" for level in permissions.values())
        or SECRET_REFERENCE.search(job_active) is not None
        or "docker/login-action@" in job_active
    )
    if job_name in CREDENTIAL_FREE_JOBS:
        if credentialed:
            return [f"jobs.{job_name} {CREDENTIAL_FREE_MESSAGE}"]
        return []

    failures: list[str] = []
    for body in run_bodies(block):
        script = re.sub(r"\\\n\s*", " ", active_text(body))
        if REPOSITORY_EXECUTION.search(script):
            failures.append(f"jobs.{job_name} {REPOSITORY_EXECUTION_MESSAGE}")
        for line in script.splitlines():
            if "docker run" in line and SYFT_IMAGE not in line:
                failures.append(f"jobs.{job_name} {IMAGE_RUN_MESSAGE}")
    return failures


def validate_resolve(block: str, active: str) -> list[str]:
    failures: list[str] = []
    if RESOLVE_OUTPUTS not in block:
        failures.append("jobs.resolve outputs must be exactly publish, sha, and build")

    head_bodies = [body for body in run_bodies(block) if HEAD_LOOKUP in body]
    if len(head_bodies) != 1:
        failures.append("jobs.resolve must look up the current main head exactly once")
    else:
        body = head_bodies[0]
        if IS_ANCESTOR not in body:
            failures.append("jobs.resolve must use the pinned is_ancestor helper")
        if not stale_branch_exits_cleanly(body, WORKFLOW_SHA_COMPARE):
            failures.append(RESOLVE_WORKFLOW_MESSAGE)
        if not stale_branch_exits_cleanly(body, HEAD_COMPARE):
            failures.append(RESOLVE_HEAD_MESSAGE)
        workflow_compare = body.find(WORKFLOW_SHA_COMPARE)
        compare = body.find(HEAD_COMPARE)
        publish = body.find('echo "publish=true"')
        if (
            min(workflow_compare, compare) < 0
            or publish < max(workflow_compare, compare)
            or body.count('echo "publish=true"') != 1
        ):
            failures.append("jobs.resolve may set publish=true only after both history checks")
    if active.count('"publish=true"') != 1:
        failures.append("publish=true must be emitted by exactly one guarded statement")

    steps = step_blocks(block)
    logins = [step for step in steps if "docker/login-action@" in step]
    if (
        "DOCKERHUB" in active_text(block)
        or len(logins) != 1
        or "registry: ghcr.io" not in logins[0]
    ):
        failures.append(RESOLVE_ANONYMOUS_MESSAGE)
    if not steps or "\n        id: existing" not in steps[-1]:
        failures.append(RESOLVE_LAST_STEP_MESSAGE)

    job_active = active_text(block)
    if "cosign sign" in job_active or "cosign attest" in job_active:
        failures.append("jobs.resolve may verify an existing signature but must never sign")

    existing = [step for step in steps if "\n        id: existing" in step]
    if len(existing) != 1:
        failures.append(REUSE_MESSAGE)
        return failures
    step = existing[0]
    if VERIFY_IDENTITY not in step:
        failures.append(RESOLVE_IDENTITY_MESSAGE)
    if REGISTRY_READ not in step or REUSE_INSPECT not in step:
        failures.append(f"jobs.resolve {REGISTRY_RETRY_MESSAGE}")
    skip = step.find('echo "build=false"')
    calls = [step.find(call) for call in REUSE_SIGNED_CALLS]
    if (
        active.count('"build=false"') != 1
        or skip < 0
        or min(calls) < 0
        or skip < max(calls)
        or REUSE_SIGNED_CHECK not in step
    ):
        failures.append(REUSE_MESSAGE)
    return failures


def validate_contract(block: str) -> list[str]:
    steps = step_blocks(block)
    if (
        len(steps) != 2
        or "actions/checkout@" not in steps[0]
        or [body.rstrip() for body in run_bodies(block)] != [CONTRACT_RUN]
    ):
        return [CONTRACT_MESSAGE]
    return []


def validate_build(block: str) -> list[str]:
    failures: list[str] = []
    for line in BUILD_PARITY_LINES:
        if line not in block:
            failures.append(f"jobs.build must keep {line.strip()!r} (release build parity)")
    if (
        block.count(BUILD_CONTEXT) != 1
        or block.count(BUILD_GIT_TOKEN) != 1
        or len(re.findall(r"^\s+context:", block, re.MULTILINE)) != 1
        or len(re.findall(r"^\s+github-token:", block, re.MULTILINE)) != 1
    ):
        failures.append(BUILD_CONTEXT_MESSAGE)
    return failures


def validate_smoke(block: str) -> list[str]:
    steps = step_blocks(block)
    downloads = [
        index
        for index, step in enumerate(steps)
        if "actions/download-artifact@" in step
        and "name: main-latest-digest-${{ matrix.arch_dir }}" in step
    ]
    smoke = [
        index
        for index, step in enumerate(steps)
        if SMOKE_RUN in step and SMOKE_CHECK in step and "\n        if:" not in step
    ]
    if len(downloads) != 1 or len(smoke) != 1 or downloads[0] > smoke[0]:
        return [SMOKE_MESSAGE]
    step = steps[smoke[0]]
    pull = step.find(SMOKE_PULL)
    if (
        REGISTRY_READ not in step
        or not 0 <= pull < step.find(SMOKE_RUN)
        or not branch_contains(step, SMOKE_PULL, "exit 1")
    ):
        return [f"jobs.smoke {REGISTRY_RETRY_MESSAGE}"]
    return []


def validate_syft(steps: list[str]) -> list[str]:
    """Syft runs once, with no credential in its step or its container."""

    syft_steps_raw = [step for step in steps if SYFT_IMAGE in step]
    if len(syft_steps_raw) != 1:
        return [SYFT_MESSAGE]
    step = active_text(syft_steps_raw[0])
    script = re.sub(r"\\\n\s*", " ", step)
    runs = [" ".join(line.split()) for line in script.splitlines() if "docker run" in line]
    if (
        runs != [SYFT_RUN]
        or SECRET_REFERENCE.search(step) is not None
        or any(marker in step for marker in SYFT_CREDENTIAL_MARKERS)
        or any(line not in step for line in SYFT_OUTPUT_DIR)
        or REGISTRY_READ not in syft_steps_raw[0]
    ):
        return [SYFT_MESSAGE]
    return []


def validate_attest(block: str) -> list[str]:
    failures: list[str] = []
    if ATTEST_OUTPUTS not in block:
        failures.append(ATTEST_OUTPUTS_MESSAGE)
    steps = step_blocks(block)
    failures.extend(validate_syft(steps))

    sign_steps = [
        (index, step) for index, step in enumerate(steps) if "sign_and_attest() {" in step
    ]
    sign_index = -1
    signed = len(sign_steps) == 1
    if signed:
        sign_index, step = sign_steps[0]
        sign = step.find('cosign sign --yes "$image_ref"')
        last_attest = step.rfind("cosign attest --yes")
        signed = (
            SIGN_IF in step
            and 0 <= last_attest < sign
            and "--type slsaprovenance1" in step
            and "--type spdxjson" in step
            and all(call in step for call in SIGN_CALLS)
        )
    if not signed:
        failures.append(SIGN_MESSAGE)

    verify_steps = [
        (index, step) for index, step in enumerate(steps) if "\n        id: verify" in step
    ]
    if len(verify_steps) != 1:
        failures.append(VERIFY_MESSAGE)
        return failures
    index, step = verify_steps[0]
    if VERIFY_IDENTITY not in step:
        failures.append(ATTEST_IDENTITY_MESSAGE)
    calls = [step.find(call) for call in VERIFY_IMAGE_CALLS]
    outputs = [step.find(line) for line in VERIFY_OUTPUT_LINES]
    if (
        "\n        if:" in step
        or index < sign_index
        or not all(snippet in step for snippet in VERIFY_SNIPPETS)
        or min(calls) < 0
        or min(outputs) < max(calls)
        or any(step.count(line) != 1 for line in VERIFY_OUTPUT_LINES)
    ):
        failures.append(VERIFY_MESSAGE)
    return failures


def validate_promote(block: str) -> list[str]:
    failures: list[str] = []
    if any(line not in block for line in PROMOTE_ENV) or (
        block.count("DOCKER_REF:") != 1 or block.count("GHCR_REF:") != 1
    ):
        failures.append(PROMOTE_SOURCE_MESSAGE)

    bodies = [body for body in run_bodies(block) if "imagetools create" in body]
    if len(bodies) != 1:
        failures.append("jobs.promote must move latest in exactly one step")
        return failures
    body = bodies[0]
    for token in PROMOTE_FORBIDDEN:
        if token in active_text(body):
            failures.append(f"jobs.promote must not use {token.strip()!r}")

    functions, statements = shell_structure(body)
    for name in PROMOTE_FUNCTIONS:
        if len(functions.get(name, [])) != 1 or body.count(f"{name}() {{") != 1:
            failures.append(f"jobs.promote must define {name} exactly once")
    unexpected = sorted(set(functions) - set(PROMOTE_FUNCTIONS))
    if unexpected:
        failures.append(f"jobs.promote defines unexpected shell functions {unexpected}")

    for statement in statements:
        if not statement.startswith("docker buildx imagetools create "):
            continue
        tag = next((tag for tag in PROMOTE_SOURCES if f"-t {tag} " in statement), None)
        if tag is None or statement.split()[-1] != PROMOTE_SOURCES[tag]:
            failures.append(PROMOTE_SOURCE_MESSAGE)
    for statement in dict.fromkeys(PROMOTE_SEQUENCE):
        if statements.count(statement) < PROMOTE_SEQUENCE.count(statement):
            failures.append(f"jobs.promote must run {statement!r}")
    if tuple(statements) != PROMOTE_SEQUENCE:
        failures.append(
            "jobs.promote must run exactly its pinned gate sequence: re-check main and "
            "latest, move one registry, verify it, then the next"
        )

    def function(name: str) -> str:
        definitions = functions.get(name, [])
        return definitions[0] if definitions else ""

    if IS_ANCESTOR not in body:
        failures.append("jobs.promote must use the pinned is_ancestor helper")
    on_main = function("require_on_main")
    if HEAD_LOOKUP not in on_main or not stale_branch_exits_cleanly(on_main, HEAD_COMPARE):
        failures.append(PROMOTE_ON_MAIN_MESSAGE)
    not_newer = function("require_latest_not_newer")
    forward = not_newer.find(LATEST_FORWARD)
    orphan = not_newer.find(LATEST_ORPHAN)
    if (
        "--format '{{json .Image}}'" not in not_newer
        or '"org.opencontainers.image.revision"' not in not_newer
        or not branch_contains(not_newer, LATEST_FORWARD, "return 0")
        or not not_newer.rstrip().endswith("exit 0")
        or not 0 <= forward < orphan
    ):
        failures.append(PROMOTE_BACKWARDS_MESSAGE)
    if (
        orphan < 0
        or HEAD_LOOKUP not in not_newer[forward:orphan]
        or not branch_contains(not_newer, LATEST_ORPHAN, "::warning::")
        or not branch_contains(not_newer, LATEST_ORPHAN, "return 0")
        or branch_contains(not_newer, LATEST_ORPHAN, "exit")
    ):
        failures.append(PROMOTE_ORPHAN_MESSAGE)
    if not branch_contains(function("require_latest"), DIGEST_COMPARE, "exit 1"):
        failures.append(PROMOTE_DIGEST_MESSAGE)
    verified_ref = function("require_verified_ref")
    if (
        '[ "${ref%@*}" != "$repository" ]' not in verified_ref
        or '[[ ! "${ref#*@}" =~ ^sha256:[0-9a-f]{64}$ ]]' not in verified_ref
        or "exit 1" not in verified_ref
    ):
        failures.append(PROMOTE_SOURCE_MESSAGE)
    return failures


def validate_workflow(text: str, release_text: str) -> list[str]:
    failures: list[str] = []
    active = active_text(text)

    for key, expected in (
        ("on", EXPECTED_ON),
        ("concurrency", EXPECTED_CONCURRENCY),
        ("permissions", EXPECTED_TOP_PERMISSIONS),
    ):
        block, errors = top_level_block(text, key)
        failures.extend(errors)
        if block is not None and block != expected:
            failures.append(f"top-level {key}: block differs from the publisher contract")

    for needle, reason in FORBIDDEN_ACTIVE_TEXT:
        if needle in active:
            failures.append(f"workflow must not contain {needle!r}: {reason}")
    if active.count("cancelled()") != 2:
        failures.append("cancelled() may appear only in the pinned attest and promote conditions")
    if len(re.findall(r"^\s*concurrency:", active, re.MULTILINE)) != 1:
        failures.append("only the workflow may declare concurrency")
    for python in PYTHON_INVOCATION.finditer(active):
        if python.group("flag") is None:
            failures.append(PYTHON_ISOLATION_MESSAGE)

    jobs = job_blocks(text)
    if set(jobs) != set(EXPECTED_JOB_PERMISSIONS):
        failures.append(
            f"workflow jobs must be exactly {sorted(EXPECTED_JOB_PERMISSIONS)}, "
            f"found {sorted(jobs)}"
        )
        return failures

    for job_name, block in jobs.items():
        permissions = job_permissions(block)
        if permissions != EXPECTED_JOB_PERMISSIONS[job_name]:
            failures.append(
                f"jobs.{job_name}.permissions must be exactly "
                f"{EXPECTED_JOB_PERMISSIONS[job_name]}, found {permissions}"
            )
        needs = job_field(block, "needs")
        if needs != EXPECTED_NEEDS[job_name]:
            failures.append(
                f"jobs.{job_name}.needs must be {EXPECTED_NEEDS[job_name]!r}, found {needs!r}"
            )
        condition = job_field(block, "if")
        if job_name == "resolve":
            if condition is None:
                failures.append("jobs.resolve must gate on the triggering CI run")
            else:
                if "||" in condition:
                    failures.append("jobs.resolve.if must be a conjunction of required facts")
                for required in RESOLVE_CONDITIONS:
                    if required not in condition:
                        failures.append(f"jobs.resolve.if must require {required}")
        elif condition != EXPECTED_JOB_IFS[job_name]:
            failures.append(f"jobs.{job_name}.if must be exactly {EXPECTED_JOB_IFS[job_name]!r}")

        for body in run_bodies(block):
            if "${{" in body:
                failures.append(
                    f"jobs.{job_name} interpolates a workflow expression into a shell "
                    "body; pass it through env instead"
                )

        failures.extend(credential_isolation_errors(job_name, block))
        for step in step_blocks(block):
            if "actions/checkout@" not in step:
                continue
            if "persist-credentials: false" not in step:
                failures.append(f"jobs.{job_name} checkout must not persist credentials")
            expected_ref = CHECKOUT_REFS.get(job_name)
            if expected_ref is None:
                failures.append(f"jobs.{job_name} {CHECKOUT_MESSAGE}")
            elif expected_ref not in step:
                failures.append(f"jobs.{job_name} checkout must pin {expected_ref}")

        job_active = active_text(block)
        tags = [
            match.group("tag")
            for body in run_bodies(block)
            for match in TAG_ARGUMENT.finditer(re.sub(r"\\\n\s*", " ", body))
        ]
        expected_tags = TAGS_BY_JOB.get(job_name, [])
        if tags != expected_tags:
            failures.append(
                f"jobs.{job_name} must push exactly the tags {expected_tags}, found {tags}"
            )
        creates = job_active.count("imagetools create")
        if creates != len(expected_tags):
            failures.append(
                f"jobs.{job_name} must run imagetools create exactly "
                f"{len(expected_tags)} times, found {creates}"
            )
        if re.search(r"^\s+tags:", job_active, re.MULTILINE):
            failures.append(f"jobs.{job_name} must not tag images through an action input")
        if job_name != "build" and "push-by-digest=true" in job_active:
            failures.append(f"jobs.{job_name} must not push platform images")
        if job_name not in {"attest", "resolve"} and "cosign " in job_active:
            failures.append(f"jobs.{job_name} must not use cosign; only jobs.attest signs")

    failures.extend(validate_resolve(jobs["resolve"], active))
    failures.extend(validate_contract(jobs["contract"]))
    failures.extend(validate_build(jobs["build"]))
    failures.extend(validate_smoke(jobs["smoke"]))
    failures.extend(validate_attest(jobs["attest"]))
    failures.extend(validate_promote(jobs["promote"]))

    if SYFT_IMAGE not in active or SYFT_IMAGE not in release_text:
        failures.append(
            "jobs.attest must scan with the same digest-pinned Syft image as release.yml"
        )

    for secret in SECRET_REFERENCE.finditer(active):
        field = secret.group("field")
        if field is None or field[1:] not in ALLOWED_SECRETS:
            failures.append(
                f"workflow may reference only {sorted(ALLOWED_SECRETS)} secrets, "
                f"found {secret.group(0)}"
            )

    release_pins = release_action_pins(release_text)
    for match in REMOTE_USES.finditer(active):
        ref = match.group("ref")
        pinned = PINNED_REF.match(ref)
        if pinned is None:
            failures.append(f"action {ref!r} must be pinned by a full commit SHA")
            continue
        if pinned.group("sha") not in release_pins.get(pinned.group("name"), set()):
            failures.append(f"action {ref!r} must use the same pin as release.yml")

    return list(dict.fromkeys(failures))


def replace_once(old: str, new: str) -> Callable[[str], str | None]:
    def mutate(text: str) -> str | None:
        if old not in text:
            return None
        return text.replace(old, new, 1)

    return mutate


def replace_in_job(job: str, old: str, new: str) -> Callable[[str], str | None]:
    def mutate(text: str) -> str | None:
        header = f"\n  {job}:\n"
        start = text.find(header)
        if start < 0 or old not in text[start:]:
            return None
        return text[:start] + text[start:].replace(old, new, 1)

    return mutate


def chain(*mutations: Callable[[str], str | None]) -> Callable[[str], str | None]:
    """Apply several mutations in order; None when any of them no longer applies."""

    def mutate(text: str) -> str | None:
        for mutation in mutations:
            mutated = mutation(text)
            if mutated is None:
                return None
            text = mutated
        return text

    return mutate


def cut(start_marker: str, end_marker: str) -> Callable[[str], str | None]:
    """Delete from `start_marker` up to, not including, the next `end_marker`."""

    def mutate(text: str) -> str | None:
        start = text.find(start_marker)
        end = text.find(end_marker, start + 1) if start >= 0 else -1
        if end < 0:
            return None
        return text[:start] + text[end:]

    return mutate


def self_test() -> int:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    release = RELEASE_PATH.read_text(encoding="utf-8")
    failures: list[str] = []

    baseline = validate_workflow(workflow, release)
    if baseline:
        failures.append(
            "the checked-in publisher must satisfy its own contract: " + "; ".join(baseline)
        )

    build_push = "docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc"
    checkout_step = (
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6\n"
        "        with:\n"
        "          ref: ${{ needs.resolve.outputs.sha }}\n"
        "          persist-credentials: false\n\n"
    )
    dockerhub_login = (
        "      - name: Log in to Docker Hub\n"
        "        uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4\n"
        "        with:\n"
        "          username: ${{ secrets.DOCKERHUB_USERNAME }}\n"
        "          password: ${{ secrets.DOCKERHUB_TOKEN }}\n\n"
    )
    contract_step = "      - name: Verify the publisher contract of the running workflow\n"
    ghcr_latest = '            -t "ghcr.io/${GITHUB_REPOSITORY}:latest" \\\n'
    identity_tail = 'main-latest-image.yml@refs/heads/main"'
    syft_env = (
        "          DOCKER_REF: ${{ steps.images.outputs.docker_ref }}\n"
        "          SOURCE_SHA: ${{ needs.resolve.outputs.sha }}\n"
    )
    syft_token_env = "          DOCKERHUB_PASSWORD: ${{ secrets.DOCKERHUB_TOKEN }}\n"
    syft_update_check = "              -e SYFT_CHECK_FOR_APP_UPDATE=false \\\n"
    syft_token_arg = '              -e SYFT_REGISTRY_AUTH_PASSWORD="$DOCKERHUB_PASSWORD" \\\n'
    other_identity = 'main-latest-image.yml@refs/heads/feature"'
    # Each mutation maps to (mutation, a fragment its rejection must contain).
    # None accepts any rejection.
    mutations: dict[str, tuple[Callable[[str], str | None], str | None]] = {
        "pull request trigger": (
            replace_once("on:\n  workflow_run:\n", "on:\n  pull_request:\n  workflow_run:\n"),
            None,
        ),
        "manual trigger": (
            replace_once(
                "      - main\n\npermissions:",
                "      - main\n  workflow_dispatch:\n\npermissions:",
            ),
            None,
        ),
        "any triggering branch": (replace_once("    branches:\n      - main\n", ""), None),
        "failed CI admitted": (
            replace_once(
                "github.event.workflow_run.conclusion == 'success'",
                "github.event.workflow_run.conclusion != 'cancelled'",
            ),
            None,
        ),
        "non-push CI admitted": (
            replace_once("github.event.workflow_run.event == 'push' && ", ""),
            None,
        ),
        "disjunctive CI gate": (
            replace_once(
                "github.event.workflow_run.conclusion == 'success' &&",
                "github.event.workflow_run.conclusion == 'success' ||",
            ),
            None,
        ),
        "other workflow admitted": (
            replace_once(
                "github.event.workflow_run.path == '.github/workflows/ci.yml'",
                "github.event.workflow_run.path == '.github/workflows/other.yml'",
            ),
            None,
        ),
        "fork publication": (
            replace_once("github.repository == 'ferrum-edge/ferrum-edge' && ", ""),
            None,
        ),
        "cancel in progress": (
            replace_once("  cancel-in-progress: false\n", "  cancel-in-progress: true\n"),
            "top-level concurrency: block differs",
        ),
        "concurrency without the CI workflow path": (
            replace_once(
                "-${{ github.event.workflow_run.path }}-${{ github.event.workflow_run.event }}",
                "-${{ github.event.workflow_run.event }}",
            ),
            "top-level concurrency: block differs",
        ),
        "per-commit concurrency": (
            replace_once(
                "-${{ github.event.workflow_run.conclusion }}\n  cancel-in-progress",
                "-${{ github.event.workflow_run.conclusion }}-"
                "${{ github.event.workflow_run.head_sha }}\n  cancel-in-progress",
            ),
            "top-level concurrency: block differs",
        ),
        "second concurrency group": (
            replace_in_job(
                "promote",
                "    timeout-minutes: 10\n",
                "    timeout-minutes: 10\n"
                "    concurrency:\n"
                "      group: main-latest-image-promote\n"
                "      cancel-in-progress: true\n",
            ),
            "only the workflow may declare concurrency",
        ),
        "running workflow need not contain the commit": (
            replace_in_job("resolve", WORKFLOW_SHA_COMPARE, "if false; then"),
            RESOLVE_WORKFLOW_MESSAGE,
        ),
        "no pre-build history check": (
            replace_in_job("resolve", HEAD_COMPARE, "if false; then"),
            RESOLVE_HEAD_MESSAGE,
        ),
        "stale pre-build run falls through": (
            replace_in_job(
                "resolve",
                "no longer on main's history (head ${main_head}); not publishing\"\n"
                '            echo "publish=false" >> "$GITHUB_OUTPUT"\n'
                "            exit 0\n",
                "no longer on main's history (head ${main_head}); not publishing\"\n",
            ),
            RESOLVE_HEAD_MESSAGE,
        ),
        "no promote history check": (
            replace_in_job("promote", HEAD_COMPARE, "if false; then"),
            PROMOTE_ON_MAIN_MESSAGE,
        ),
        "latest may move backwards": (
            replace_in_job("promote", LATEST_FORWARD, "if true; then"),
            PROMOTE_BACKWARDS_MESSAGE,
        ),
        "ancestry helper accepts a newer latest": (
            replace_in_job(
                "promote",
                "behind | diverged | missing) return 1 ;;",
                "behind | diverged | missing) return 0 ;;",
            ),
            "jobs.promote must use the pinned is_ancestor helper",
        ),
        "resolve history checks use a changed helper": (
            replace_in_job(
                "resolve",
                "behind | diverged | missing) return 1 ;;",
                "behind | diverged | missing) return 0 ;;",
            ),
            "jobs.resolve must use the pinned is_ancestor helper",
        ),
        "newer latest falls through to the move": (
            replace_in_job(
                "promote",
                'it names the newer \\`${revision}\\`." >> "$GITHUB_STEP_SUMMARY"\n'
                "            exit 0\n",
                'it names the newer \\`${revision}\\`." >> "$GITHUB_STEP_SUMMARY"\n',
            ),
            PROMOTE_BACKWARDS_MESSAGE,
        ),
        "uncorroborated compare 404 moves latest": (
            replace_in_job("promote", UNCORROBORATED_404, "if false; then"),
            "jobs.promote must use the pinned is_ancestor helper",
        ),
        "resolve accepts an uncorroborated compare 404": (
            replace_in_job("resolve", UNCORROBORATED_404, "if false; then"),
            "jobs.resolve must use the pinned is_ancestor helper",
        ),
        "orphaned latest blocks forever": (
            replace_in_job(
                "promote",
                'treating latest as absent"\n              return 0\n',
                'treating latest as absent"\n              exit 0\n',
            ),
            PROMOTE_ORPHAN_MESSAGE,
        ),
        "promote omits the second on-main check": (
            replace_in_job(
                "promote",
                '          require_on_main\n          require_latest_not_newer "ghcr.io/',
                '          require_latest_not_newer "ghcr.io/',
            ),
            "jobs.promote must run 'require_on_main'",
        ),
        "ancestry gate defined but not called": (
            replace_in_job(
                "promote", '          require_latest_not_newer "ferrumedge/ferrum-edge"\n', ""
            ),
            f"jobs.promote must run {PROMOTE_SEQUENCE[4]!r}",
        ),
        "digest gate defined but not called": (
            replace_in_job(
                "promote",
                '          require_latest "ferrumedge/ferrum-edge:latest" "$DOCKER_REF"\n',
                "",
            ),
            f"jobs.promote must run {PROMOTE_SEQUENCE[6]!r}",
        ),
        "latest created from a tag": (
            replace_in_job(
                "promote",
                '-t "ferrumedge/ferrum-edge:latest" \\\n            "$DOCKER_REF"',
                '-t "ferrumedge/ferrum-edge:latest" \\\n'
                '            "ferrumedge/ferrum-edge:main-${SOURCE_SHA}"',
            ),
            PROMOTE_SOURCE_MESSAGE,
        ),
        "latest from an unverified reference": (
            replace_once(
                "docker_ref: ${{ steps.verify.outputs.docker_ref }}",
                "docker_ref: ${{ steps.images.outputs.docker_ref }}",
            ),
            ATTEST_OUTPUTS_MESSAGE,
        ),
        "verify step deleted": (
            cut(
                "      - name: Verify signatures, provenance, subjects, and SBOMs\n",
                "\n  promote:\n",
            ),
            VERIFY_MESSAGE,
        ),
        "sign deleted": (
            replace_in_job("attest", '            cosign sign --yes "$image_ref"\n', ""),
            SIGN_MESSAGE,
        ),
        "signing skipped on a fresh build": (
            replace_in_job(
                "attest",
                "      - name: Attest and sign main-sha image digests\n"
                "        if: needs.resolve.outputs.build == 'true'\n",
                "      - name: Attest and sign main-sha image digests\n"
                "        if: needs.resolve.outputs.build == 'false'\n",
            ),
            SIGN_MESSAGE,
        ),
        "signing identity changed": (
            replace_in_job("attest", identity_tail, other_identity),
            ATTEST_IDENTITY_MESSAGE,
        ),
        "reuse identity changed": (
            replace_in_job("resolve", identity_tail, other_identity),
            RESOLVE_IDENTITY_MESSAGE,
        ),
        "reuse without a signature check": (
            replace_in_job(
                "resolve",
                '            signed "ghcr.io/${GITHUB_REPOSITORY}@${ghcr_digest}"; then\n',
                "            true; then\n",
            ),
            REUSE_MESSAGE,
        ),
        "attest after a failed manifest": (
            replace_once(
                "(needs.manifest.result == 'success' || ",
                "(needs.manifest.result != 'cancelled' || ",
            ),
            "jobs.attest.if must be exactly",
        ),
        "attest without resolve success": (
            replace_in_job("attest", "needs.resolve.result == 'success' && ", ""),
            "jobs.attest.if must be exactly",
        ),
        "promote without resolve success": (
            replace_in_job("promote", "needs.resolve.result == 'success' && ", ""),
            "jobs.promote.if must be exactly",
        ),
        "promote without contract success": (
            replace_in_job("promote", "needs.contract.result == 'success' && ", ""),
            "jobs.promote.if must be exactly",
        ),
        "reuse step no longer last in resolve": (
            replace_in_job(
                "resolve",
                '            echo "build=true" >> "$GITHUB_OUTPUT"\n          fi\n',
                '            echo "build=true" >> "$GITHUB_OUTPUT"\n          fi\n\n'
                "      - name: Late step\n"
                "        run: echo done\n",
            ),
            RESOLVE_LAST_STEP_MESSAGE,
        ),
        "Docker Hub credential in resolve": (
            replace_in_job(
                "resolve",
                "      # `main-<sha>` is built once.",
                dockerhub_login + "      # `main-<sha>` is built once.",
            ),
            RESOLVE_ANONYMOUS_MESSAGE,
        ),
        "checkout in a credentialed job": (
            replace_in_job(
                "promote",
                "    steps:\n      - name: Set up Docker Buildx\n",
                "    steps:\n" + checkout_step + "      - name: Set up Docker Buildx\n",
            ),
            CHECKOUT_MESSAGE,
        ),
        "build checks out the repository": (
            replace_in_job(
                "build",
                "    steps:\n      - name: Set up Docker Buildx\n",
                "    steps:\n" + checkout_step + "      - name: Set up Docker Buildx\n",
            ),
            CHECKOUT_MESSAGE,
        ),
        "build from a moving branch": (
            replace_in_job(
                "build",
                "ferrum-edge.git#${{ needs.resolve.outputs.sha }}",
                "ferrum-edge.git#main",
            ),
            BUILD_CONTEXT_MESSAGE,
        ),
        "build receives the job token": (
            replace_in_job("build", BUILD_GIT_TOKEN, ""),
            BUILD_CONTEXT_MESSAGE,
        ),
        "repository script in a credentialed job": (
            replace_in_job(
                "manifest",
                "          set -euo pipefail\n          docker buildx imagetools create",
                "          set -euo pipefail\n"
                "          bash .github/scripts/stage_iproute2_runtime.sh\n"
                "          docker buildx imagetools create",
            ),
            REPOSITORY_EXECUTION_MESSAGE,
        ),
        "interpreter in a credentialed job": (
            replace_in_job(
                "promote",
                "          set -euo pipefail\n\n          require_verified_ref() {",
                "          set -euo pipefail\n"
                "          python3 -I -c 'print(1)'\n\n"
                "          require_verified_ref() {",
            ),
            REPOSITORY_EXECUTION_MESSAGE,
        ),
        "built image run in a credentialed job": (
            replace_in_job(
                "build",
                '          mkdir -p "$RUNNER_TEMP/digests"\n',
                '          docker run --rm "ferrumedge/ferrum-edge@${DIGEST}" version\n'
                '          mkdir -p "$RUNNER_TEMP/digests"\n',
            ),
            IMAGE_RUN_MESSAGE,
        ),
        "python without isolation": (
            replace_once(
                "python3 -I .github/scripts/verify_main_latest_image_workflow.py --self-test",
                "python3 .github/scripts/verify_main_latest_image_workflow.py --self-test",
            ),
            PYTHON_ISOLATION_MESSAGE,
        ),
        "contract skips its self-test": (
            replace_in_job(
                "contract",
                "          python3 -I .github/scripts/verify_main_latest_image_workflow.py"
                " --self-test\n",
                "",
            ),
            CONTRACT_MESSAGE,
        ),
        "contract holds a registry credential": (
            replace_in_job("contract", contract_step, dockerhub_login + contract_step),
            CREDENTIAL_FREE_MESSAGE,
        ),
        "smoke holds a write token": (
            replace_in_job(
                "smoke",
                "    permissions:\n      contents: read\n",
                "    permissions:\n      contents: read\n      packages: write\n",
            ),
            CREDENTIAL_FREE_MESSAGE,
        ),
        "smoke pull without retry": (
            replace_in_job(
                "smoke", 'if ! registry_read "$pull_err" docker pull', "if ! docker pull"
            ),
            f"jobs.smoke {REGISTRY_RETRY_MESSAGE}",
        ),
        "unbounded registry retry": (
            replace_in_job("resolve", "for attempt in 1 2 3; do", "while true; do"),
            f"jobs.resolve {REGISTRY_RETRY_MESSAGE}",
        ),
        "Syft receives the Docker Hub token": (
            chain(
                replace_in_job("attest", syft_env, syft_token_env + syft_env),
                replace_in_job("attest", syft_update_check, syft_update_check + syft_token_arg),
            ),
            SYFT_MESSAGE,
        ),
        "Syft step holds the Docker Hub token": (
            replace_in_job("attest", syft_env, syft_token_env + syft_env),
            SYFT_MESSAGE,
        ),
        "Syft writes into the attestation work directory": (
            replace_in_job("attest", '-v "$sbom_dir:/out"', '-v "$work:/out"'),
            SYFT_MESSAGE,
        ),
        "no image smoke": (
            cut("      - name: Smoke the pushed platform image\n", "\n  manifest:\n"),
            SMOKE_MESSAGE,
        ),
        "unpinned action": (replace_once(build_push, "docker/build-push-action@v7"), None),
        "action pin drifts from release": (
            replace_once(build_push, "docker/build-push-action@" + "0" * 40),
            None,
        ),
        "version tag": (
            replace_once(
                '-t "ferrumedge/ferrum-edge:latest"', '-t "ferrumedge/ferrum-edge:1.2.3"'
            ),
            None,
        ),
        "extra series tag": (
            replace_once(
                ghcr_latest,
                ghcr_latest + '            -t "ghcr.io/${GITHUB_REPOSITORY}:1.2" \\\n',
            ),
            None,
        ),
        "latest before signing": (
            replace_once(
                '-t "ferrumedge/ferrum-edge:main-${SOURCE_SHA}"',
                '-t "ferrumedge/ferrum-edge:latest"',
            ),
            None,
        ),
        "eBPF variant": (replace_once("target: runtime\n", "target: runtime-ebpf\n"), None),
        "different build features": (
            replace_once("FEATURES=cloud-secrets\n", "FEATURES=cloud-secrets,ebpf\n"),
            None,
        ),
        "expression in shell": (
            replace_once(
                '          set -euo pipefail\n          if [[ ! "$DIGEST"',
                "          set -euo pipefail\n"
                '          echo "${{ github.event.workflow_run.head_branch }}"\n'
                '          if [[ ! "$DIGEST"',
            ),
            None,
        ),
        "permission escalation": (
            replace_in_job(
                "resolve",
                "    permissions:\n      contents: read\n",
                "    permissions:\n      contents: write\n",
            ),
            None,
        ),
        "non-blocking build": (
            replace_once(
                "    timeout-minutes: 240\n",
                "    timeout-minutes: 240\n    continue-on-error: true\n",
            ),
            None,
        ),
        "persisted checkout credentials": (
            replace_once("persist-credentials: false", "persist-credentials: true"),
            None,
        ),
        "unexpected secret": (
            replace_once("${{ secrets.DOCKERHUB_TOKEN }}", "${{ secrets.RELEASE_TAG_TOKEN }}"),
            "found secrets.RELEASE_TAG_TOKEN",
        ),
        "uppercase secrets context": (
            replace_once("${{ secrets.DOCKERHUB_TOKEN }}", "${{ SECRETS.RELEASE_TAG_TOKEN }}"),
            "found SECRETS.RELEASE_TAG_TOKEN",
        ),
        "promote without attestation": (
            replace_once(
                "    needs: [resolve, contract, attest]\n",
                "    needs: [resolve, contract, manifest]\n",
            ),
            None,
        ),
        "direct docker push": (
            replace_in_job(
                "promote",
                "          set -euo pipefail\n",
                '          set -euo pipefail\n          docker push "ferrumedge/ferrum-edge:latest"\n',
            ),
            None,
        ),
    }
    for label, (mutate, reason) in mutations.items():
        mutated = mutate(workflow)
        if mutated is None:
            failures.append(f"self-test mutation {label!r} no longer applies to the workflow")
            continue
        rejected = validate_workflow(mutated, release)
        if not rejected:
            failures.append(f"self-test mutation {label!r} was not rejected")
        elif reason is not None and not any(reason in failure for failure in rejected):
            failures.append(
                f"self-test mutation {label!r} was rejected, but not for its own reason "
                f"{reason!r}: {rejected}"
            )

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"Main latest image publisher self-test OK ({len(mutations)} mutations rejected)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()

    failures = validate_workflow(
        WORKFLOW_PATH.read_text(encoding="utf-8"),
        RELEASE_PATH.read_text(encoding="utf-8"),
    )
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1
    print("Main latest image publisher contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
