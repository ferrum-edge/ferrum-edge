#!/usr/bin/env python3
"""Static contract for the main `latest` image publisher.

Owner decision 2026-09-28: the Docker `latest` tag tracks the newest `main`
commit whose push CI succeeded. This verifier pins the fail-closed shape of
`.github/workflows/main-latest-image.yml`:

* it is triggered only by completed CI runs on `main`, and its first job
  proceeds only for a successful `push` run of ci.yml in this repository;
* the CI-validated SHA must still be the head of `main` before anything is
  built, and again in the same step that moves `latest`;
* publishers are serialized with cancel-in-progress disabled;
* every job holds exactly its least-privilege permissions, and only the
  release registry secrets are referenced;
* every remote action is pinned by full commit SHA to the same pin release.yml
  uses, and no workflow expression is interpolated into a shell body;
* only the immutable `main-<sha>` tags and `latest` are pushed, never a version
  tag or an eBPF variant, and `latest` moves only after the `main-<sha>` digest
  is signed, attested, and verified.

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
EXPECTED_CONCURRENCY = (
    "concurrency:\n"
    "  group: main-latest-image-${{ github.event.workflow_run.event }}-"
    "${{ github.event.workflow_run.conclusion }}\n"
    "  cancel-in-progress: false\n"
)
EXPECTED_TOP_PERMISSIONS = "permissions:\n  contents: read\n"
EXPECTED_JOB_PERMISSIONS = {
    "resolve": {"contents": "read"},
    "build": {"contents": "read", "packages": "write"},
    "manifest": {"contents": "read", "packages": "write"},
    "attest": {"id-token": "write", "packages": "write"},
    "promote": {"contents": "read", "packages": "write"},
}
EXPECTED_NEEDS = {
    "resolve": None,
    "build": "resolve",
    "manifest": "[resolve, build]",
    "attest": "[resolve, manifest]",
    "promote": "[resolve, attest]",
}
RESOLVE_CONDITIONS = (
    "github.repository == 'ferrum-edge/ferrum-edge'",
    "github.event.workflow_run.conclusion == 'success'",
    "github.event.workflow_run.event == 'push'",
    "github.event.workflow_run.head_branch == 'main'",
    "github.event.workflow_run.path == '.github/workflows/ci.yml'",
    "github.event.workflow_run.head_repository.full_name == github.repository",
)
PUBLISH_GATE = "needs.resolve.outputs.publish == 'true'"
HEAD_LOOKUP = 'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"'
HEAD_COMPARE = 'if [ "$main_head" != "$SOURCE_SHA" ]; then'
WORKFLOW_SHA_COMPARE = 'if [ "$GITHUB_SHA" != "$SOURCE_SHA" ]; then'
CHECKOUT_REFS = (
    "ref: ${{ steps.head.outputs.sha }}",
    "ref: ${{ needs.resolve.outputs.sha }}",
)
IMMUTABLE_TAGS = [
    '"ferrumedge/ferrum-edge:main-${SOURCE_SHA}"',
    '"ghcr.io/${GITHUB_REPOSITORY}:main-${SOURCE_SHA}"',
]
LATEST_TAGS = [
    '"ferrumedge/ferrum-edge:latest"',
    '"ghcr.io/${GITHUB_REPOSITORY}:latest"',
]
TAGS_BY_JOB = {
    "manifest": IMMUTABLE_TAGS,
    "promote": LATEST_TAGS,
}
ALLOWED_SECRETS = frozenset({"DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GITHUB_TOKEN"})
SYFT_IMAGE = (
    "anchore/syft@sha256:"
    "9a9f85314017f1ea798fb012edfa7fe9259923910f82c8d4bc983ab5c765e60b"
)
BUILD_PARITY_LINES = (
    "          context: .\n",
    "          file: Dockerfile\n",
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
    ("cancelled()", "publisher jobs must not run after a cancelled dependency"),
    ("write-all", "permissions must be granted per job, never write-all"),
    ("read-all", "permissions must be granted per job, never read-all"),
    ("docker push", "images are pushed only by digest and imagetools"),
    ("docker tag", "images are tagged only by imagetools create"),
)
REMOTE_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)", re.MULTILINE)
PINNED_REF = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{40})$")
RUN_KEY = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<value>.*)$")
TAG_ARGUMENT = re.compile(r"(?:^|\s)(?:-t|--tag)(?:\s+|=)(?P<tag>\S+)")
# `cloud-secrets` is a Cargo feature, not the `secrets` context.
SECRET_REFERENCE = re.compile(r"(?<![\w-])secrets\b(?P<field>\.[A-Za-z0-9_]+)?")


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


def stale_branch_exits_cleanly(body: str, compare: str) -> bool:
    """The stale branch of a head comparison must skip publication, not fall through."""

    start = body.find(compare)
    if start < 0:
        return False
    end = re.search(r"^\s*fi\s*$", body[start:], re.MULTILINE)
    if end is None:
        return False
    return "exit 0" in body[start : start + end.start()]


def release_action_pins(release_text: str) -> dict[str, set[str]]:
    pins: dict[str, set[str]] = {}
    for match in REMOTE_USES.finditer(active_text(release_text)):
        pinned = PINNED_REF.match(match.group("ref"))
        if pinned is not None:
            pins.setdefault(pinned.group("name"), set()).add(pinned.group("sha"))
    return pins


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
        elif condition != PUBLISH_GATE:
            failures.append(f"jobs.{job_name}.if must be exactly {PUBLISH_GATE!r}")

        for body in run_bodies(block):
            if "${{" in body:
                failures.append(
                    f"jobs.{job_name} interpolates a workflow expression into a shell "
                    "body; pass it through env instead"
                )

        for step in step_blocks(block):
            if "actions/checkout@" not in step:
                continue
            if "persist-credentials: false" not in step:
                failures.append(f"jobs.{job_name} checkout must not persist credentials")
            if not any(ref in step for ref in CHECKOUT_REFS):
                failures.append(f"jobs.{job_name} checkout must pin the CI-validated SHA")

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
        if job_name != "attest" and "cosign " in job_active:
            failures.append(f"jobs.{job_name} must not sign; only jobs.attest signs")

    resolve_bodies = run_bodies(jobs["resolve"])
    head_bodies = [body for body in resolve_bodies if HEAD_LOOKUP in body]
    if len(head_bodies) != 1:
        failures.append("jobs.resolve must look up the current main head exactly once")
    else:
        body = head_bodies[0]
        if not stale_branch_exits_cleanly(body, WORKFLOW_SHA_COMPARE):
            failures.append(
                "jobs.resolve must skip when the running workflow is not the validated commit"
            )
        if not stale_branch_exits_cleanly(body, HEAD_COMPARE):
            failures.append("jobs.resolve must skip when main has moved past the validated SHA")
        compare = body.find(HEAD_COMPARE)
        publish = body.find('echo "publish=true"')
        if compare < 0 or publish < compare or body.count('echo "publish=true"') != 1:
            failures.append("jobs.resolve may set publish=true only after the head check")
    if active.count('"publish=true"') != 1:
        failures.append("publish=true must be emitted by exactly one guarded statement")

    promote_bodies = [
        body for body in run_bodies(jobs["promote"]) if "imagetools create" in body
    ]
    if len(promote_bodies) != 1:
        failures.append("jobs.promote must move latest in exactly one step")
    else:
        body = promote_bodies[0]
        lookup = body.find(HEAD_LOOKUP)
        compare = body.find(HEAD_COMPARE)
        create = body.find("imagetools create")
        if not (0 <= lookup < compare < create):
            failures.append(
                "jobs.promote must re-check the main head in the same step, before latest moves"
            )
        if not stale_branch_exits_cleanly(body, HEAD_COMPARE):
            failures.append("jobs.promote must leave latest unchanged when main has moved")
        if "require_latest" not in body:
            failures.append("jobs.promote must prove latest resolves to the verified digest")

    build = jobs["build"]
    for line in BUILD_PARITY_LINES:
        if line not in build:
            failures.append(f"jobs.build must keep {line.strip()!r} (release build parity)")
    if SYFT_IMAGE not in active or SYFT_IMAGE not in release_text:
        failures.append(
            "jobs.attest must scan with the same digest-pinned Syft image as release.yml"
        )

    for secret in SECRET_REFERENCE.finditer(active):
        field = secret.group("field")
        if field is None or field[1:] not in ALLOWED_SECRETS:
            failures.append(
                f"workflow may reference only {sorted(ALLOWED_SECRETS)} secrets, "
                f"found secrets{field or ''}"
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
    ghcr_latest = '            -t "ghcr.io/${GITHUB_REPOSITORY}:latest" \\\n'
    mutations: dict[str, Callable[[str], str | None]] = {
        "pull request trigger": replace_once(
            "on:\n  workflow_run:\n", "on:\n  pull_request:\n  workflow_run:\n"
        ),
        "manual trigger": replace_once(
            "      - main\n\npermissions:", "      - main\n  workflow_dispatch:\n\npermissions:"
        ),
        "any triggering branch": replace_once("    branches:\n      - main\n", ""),
        "failed CI admitted": replace_once(
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.conclusion != 'cancelled'",
        ),
        "non-push CI admitted": replace_once("github.event.workflow_run.event == 'push' && ", ""),
        "disjunctive CI gate": replace_once(
            "github.event.workflow_run.conclusion == 'success' &&",
            "github.event.workflow_run.conclusion == 'success' ||",
        ),
        "other workflow admitted": replace_once(
            "github.event.workflow_run.path == '.github/workflows/ci.yml'",
            "github.event.workflow_run.path == '.github/workflows/other.yml'",
        ),
        "fork publication": replace_once("github.repository == 'ferrum-edge/ferrum-edge' && ", ""),
        "cancel in progress": replace_once(
            "  cancel-in-progress: false\n", "  cancel-in-progress: true\n"
        ),
        "no pre-build head check": replace_in_job("resolve", HEAD_COMPARE, "if false; then"),
        "stale pre-build run falls through": replace_in_job(
            "resolve",
            'not publishing a stale latest"\n'
            '            echo "publish=false" >> "$GITHUB_OUTPUT"\n'
            "            exit 0\n",
            'not publishing a stale latest"\n',
        ),
        "no promote head check": replace_in_job("promote", HEAD_COMPARE, "if false; then"),
        "unpinned action": replace_once(build_push, "docker/build-push-action@v7"),
        "action pin drifts from release": replace_once(
            build_push, "docker/build-push-action@" + "0" * 40
        ),
        "version tag": replace_once(
            '-t "ferrumedge/ferrum-edge:latest"', '-t "ferrumedge/ferrum-edge:1.2.3"'
        ),
        "extra series tag": replace_once(
            ghcr_latest, ghcr_latest + '            -t "ghcr.io/${GITHUB_REPOSITORY}:1.2" \\\n'
        ),
        "latest before signing": replace_once(
            '-t "ferrumedge/ferrum-edge:main-${SOURCE_SHA}"', '-t "ferrumedge/ferrum-edge:latest"'
        ),
        "eBPF variant": replace_once("target: runtime\n", "target: runtime-ebpf\n"),
        "different build features": replace_once(
            "FEATURES=cloud-secrets\n", "FEATURES=cloud-secrets,ebpf\n"
        ),
        "expression in shell": replace_once(
            "          set -euo pipefail\n          checked_out=",
            "          set -euo pipefail\n"
            '          echo "${{ github.event.workflow_run.head_branch }}"\n'
            "          checked_out=",
        ),
        "permission escalation": replace_in_job(
            "resolve",
            "    permissions:\n      contents: read\n",
            "    permissions:\n      contents: write\n",
        ),
        "non-blocking build": replace_once(
            "    timeout-minutes: 240\n", "    timeout-minutes: 240\n    continue-on-error: true\n"
        ),
        "persisted checkout credentials": replace_once(
            "persist-credentials: false", "persist-credentials: true"
        ),
        "unexpected secret": replace_once(
            "${{ secrets.DOCKERHUB_TOKEN }}", "${{ secrets.RELEASE_TAG_TOKEN }}"
        ),
        "promote without attestation": replace_once(
            "    needs: [resolve, attest]\n", "    needs: [resolve, manifest]\n"
        ),
        "direct docker push": replace_in_job(
            "promote",
            "          set -euo pipefail\n",
            '          set -euo pipefail\n          docker push "ferrumedge/ferrum-edge:latest"\n',
        ),
    }
    for label, mutate in mutations.items():
        mutated = mutate(workflow)
        if mutated is None:
            failures.append(f"self-test mutation {label!r} no longer applies to the workflow")
            continue
        if not validate_workflow(mutated, release):
            failures.append(f"self-test mutation {label!r} was not rejected")

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
