#!/usr/bin/env python3
"""Statically verify the release image signing and attestation contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REMOTE_ACTION = re.compile(r"(?m)^\s*uses:\s*([^\s#]+)")
PIPE_TO_SHELL = re.compile(
    r"(?im)(?:curl|wget|invoke-webrequest|iwr|irm)[^\n|]*\|\s*"
    r"(?:sudo\s+)?(?:ba|z|k)?sh\b"
)
SYFT_IMAGE = (
    "anchore/syft@sha256:"
    "9a9f85314017f1ea798fb012edfa7fe9259923910f82c8d4bc983ab5c765e60b"
)
TRUSTED_CREATE_RELEASE_NEEDS = {
    "build-release-binaries",
    "build-release-arm64-cross",
    "docker-manifest",
    "docker-ebpf-manifest",
}


def extract_job(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if not match:
        raise RuntimeError(f"could not find jobs.{job} in release.yml")
    return match.group("body")


def extract_needs(job_body: str) -> set[str]:
    inline = re.search(
        r"(?m)^    needs: \[(?P<needs>[A-Za-z0-9_-]+(?:, [A-Za-z0-9_-]+)*)\]$",
        job_body,
    )
    if inline:
        return set(inline.group("needs").split(", "))
    scalar = re.search(r"(?m)^    needs: ([A-Za-z0-9_-]+)$", job_body)
    if scalar:
        return {scalar.group(1)}
    return set()


def validate_external_action_pins(workflow: str) -> list[str]:
    errors: list[str] = []
    for reference in REMOTE_ACTION.findall(workflow):
        if reference.startswith("./"):
            continue
        owner_repo, separator, revision = reference.rpartition("@")
        if not separator or not owner_repo or not FULL_SHA.fullmatch(revision):
            errors.append(
                f"external GitHub Action reference {reference!r} is not pinned "
                "to a full commit SHA"
            )
    return errors


def validate_release_workflow(workflow: str) -> list[str]:
    errors = validate_external_action_pins(workflow)

    try:
        attest_job = extract_job(workflow, "attest-release-images")
        create_release = extract_job(workflow, "create-release")
        gate_job = extract_job(workflow, "release-attestation-gate")
    except RuntimeError as error:
        return [*errors, str(error)]

    if extract_needs(attest_job) != {"docker-manifest", "docker-ebpf-manifest"}:
        errors.append(
            "jobs.attest-release-images must depend exactly on both final "
            "manifest jobs"
        )

    create_needs = extract_needs(create_release)
    if create_needs != TRUSTED_CREATE_RELEASE_NEEDS:
        errors.append(
            "jobs.create-release must keep the trusted ARM64 publication "
            "dependency contract and must not gain an attestation needs edge"
        )

    if extract_needs(gate_job) != {"create-release", "attest-release-images"}:
        errors.append(
            "jobs.release-attestation-gate must depend exactly on create-release "
            "and attest-release-images"
        )
    if not re.search(r"(?m)^    if: always\(\)$", gate_job):
        errors.append(
            "jobs.release-attestation-gate must use if: always() so attestation "
            "failure cannot skip the fail-closed publication gate"
        )
    if not re.search(
        r"(?m)^    permissions:\n      contents: write$",
        gate_job,
    ):
        errors.append(
            "jobs.release-attestation-gate must retain contents: write so it "
            "can retract a release after attestation failure"
        )
    for token in (
        "CREATE_RESULT: ${{ needs.create-release.result }}",
        "ATTEST_RESULT: ${{ needs.attest-release-images.result }}",
        'if [ "$ATTEST_RESULT" != "success" ]; then',
        "gh release delete",
        "release publication is blocked until attest-release-images succeeds",
    ):
        if token not in gate_job:
            errors.append(
                f"jobs.release-attestation-gate is missing fail-closed token {token!r}"
            )

    id_token_grants = re.findall(r"(?m)^\s+id-token:\s*write\s*$", workflow)
    if len(id_token_grants) != 1:
        errors.append(
            "release.yml must grant id-token: write exactly once, on the "
            "attestation job"
        )
    if not re.search(
        r"(?m)^    permissions:\n      id-token: write\n      packages: write$",
        attest_job,
    ):
        errors.append(
            "jobs.attest-release-images must have the exact id-token/packages "
            "write permission block"
        )

    if workflow.count("provenance: false") != 2 or "provenance: true" in workflow:
        errors.append(
            "both push-by-digest platform builds must keep provenance disabled; "
            "manifest provenance is generated after assembly"
        )

    required_tokens = (
        "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
        SYFT_IMAGE,
        "for platform in linux/amd64 linux/arm64; do",
        '--platform "$platform"',
        "--type slsaprovenance1",
        "--type spdxjson",
        'cosign sign --yes "$image_ref"',
        "https://slsa.dev/provenance/v1",
        "https://token.actions.githubusercontent.com",
        '.critical.image["docker-manifest-digest"] == $digest',
        "any(.subject[]?; .digest.sha256 == $digest)",
        ".digest.gitCommit == $source_sha",
        "] | length >= 2",
        "compare_registry_manifests standard",
        "compare_registry_manifests ebpf",
        'generate_sboms \\\n            standard docker "$STANDARD_DOCKER_REF"',
        'generate_sboms \\\n            standard ghcr "$STANDARD_GHCR_REF"',
        'generate_sboms \\\n            ebpf docker "$EBPF_DOCKER_REF"',
        'generate_sboms \\\n            ebpf ghcr "$EBPF_GHCR_REF"',
        'jq -e -f "$work/require_manifest.jq"',
        'jq -n \\',
        '--arg build_type',
        '-f "$work/create_provenance.jq"',
    )
    for token in required_tokens:
        if token not in attest_job:
            errors.append(
                f"jobs.attest-release-images is missing contract token {token!r}"
            )

    for invocation in (
        'resolve_manifest standard_docker "ferrumedge/ferrum-edge:${TAG_NAME}"',
        'resolve_manifest standard_ghcr "ghcr.io/${GITHUB_REPOSITORY}:${TAG_NAME}"',
        'resolve_manifest ebpf_docker "ferrumedge/ferrum-edge:${TAG_NAME}-ebpf"',
        'resolve_manifest ebpf_ghcr "ghcr.io/${GITHUB_REPOSITORY}:${TAG_NAME}-ebpf"',
        'sign_and_attest standard docker "$STANDARD_DOCKER_REF"',
        'sign_and_attest standard ghcr "$STANDARD_GHCR_REF"',
        'sign_and_attest ebpf docker "$EBPF_DOCKER_REF"',
        'sign_and_attest ebpf ghcr "$EBPF_GHCR_REF"',
        'verify_image standard docker "$STANDARD_DOCKER_REF"',
        'verify_image standard ghcr "$STANDARD_GHCR_REF"',
        'verify_image ebpf docker "$EBPF_DOCKER_REF"',
        'verify_image ebpf ghcr "$EBPF_GHCR_REF"',
    ):
        if invocation not in attest_job:
            errors.append(
                "jobs.attest-release-images does not cover every image family "
                f"and registry: missing {invocation!r}"
            )

    if PIPE_TO_SHELL.search(workflow):
        errors.append("release.yml contains a pipe-to-shell download")
    for checksum_token in (
        '$expectedProtocSha256 = "5d3ff218d7d91eea95f7569bcb5a98f3030f8996d44151279d9772edcff76082"',
        "$actualProtocSha256 = (Get-FileHash -Algorithm SHA256 $protocZip)",
        '$expectedNasmSha256 = "161d0bfaff53c2f9e9f3e69fd0672323ebabafd1268976a5cec11be92a19aee7"',
        "$actualNasmSha256 = (Get-FileHash -Algorithm SHA256 $nasmZip)",
    ):
        if checksum_token not in workflow:
            errors.append(
                f"release download verification is missing {checksum_token!r}"
            )

    return errors


def run_self_test(workflow: str) -> list[str]:
    failures: list[str] = []
    if validate_release_workflow(workflow):
        failures.append("the checked-in release workflow does not satisfy the contract")
        return failures

    mutations = (
        (
            "protoc archive checksum",
            workflow.replace(
                "$actualProtocSha256 = (Get-FileHash -Algorithm SHA256 $protocZip)",
                "$actualProtocSha256 = $expectedProtocSha256",
                1,
            ),
        ),
        (
            "id-token scope",
            workflow.replace("      id-token: write", "      id-token: read", 1),
        ),
        (
            "push-by-digest provenance",
            workflow.replace("          provenance: false", "          provenance: true", 1),
        ),
        (
            "immutable Syft image",
            workflow.replace(SYFT_IMAGE, "anchore/syft:v1.49.0", 1),
        ),
        (
            "subject digest verification",
            workflow.replace(
                "any(.subject[]?; .digest.sha256 == $digest)",
                "any(.subject[]?; .digest.sha256 != $digest)",
            ),
        ),
        (
            "trusted create-release needs",
            workflow.replace(
                "    needs: [build-release-binaries, build-release-arm64-cross, docker-manifest, docker-ebpf-manifest]",
                "    needs: [build-release-binaries, build-release-arm64-cross, docker-manifest, docker-ebpf-manifest, attest-release-images]",
                1,
            ),
        ),
        (
            "release attestation gate",
            workflow.replace(
                "    needs: [create-release, attest-release-images]",
                "    needs: [create-release]",
                1,
            ),
        ),
        (
            "gate rollback delete",
            workflow.replace("gh release delete", "gh release view", 1),
        ),
        (
            "gate attestation result",
            workflow.replace(
                "ATTEST_RESULT: ${{ needs.attest-release-images.result }}",
                "ATTEST_RESULT: ${{ needs.create-release.result }}",
                1,
            ),
        ),
        (
            "gate release-delete permission",
            workflow.replace(
                "  release-attestation-gate:\n"
                "    name: Gate release on image attestation\n",
                "  release-attestation-gate:\n"
                "    name: Gate release on image attestation\n"
                "    permissions:\n"
                "      contents: read\n",
                1,
            ).replace(
                "    permissions:\n"
                "      contents: write\n"
                "    steps:\n"
                "      - name: Require attestation success and "
                "retract unverified releases",
                "    steps:\n"
                "      - name: Require attestation success and "
                "retract unverified releases",
                1,
            ),
        ),
    )
    for label, mutated in mutations:
        if not validate_release_workflow(mutated):
            failures.append(f"self-test did not reject mutation of {label}")
    return failures


def main() -> int:
    workflow_path = Path(".github/workflows/release.yml")
    workflow = workflow_path.read_text(encoding="utf-8")
    errors = validate_release_workflow(workflow)
    errors.extend(run_self_test(workflow))
    if not errors:
        print(
            "Release image attestation contract covers two image families, "
            "two registries, immutable subjects, least-privilege OIDC, and a "
            "fail-closed publication gate compatible with trusted Cross policy."
        )
        return 0
    for error in errors:
        print(f"::error::{error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
