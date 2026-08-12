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
    "docker-ebpf-tools-manifest",
}
# Every published multi-arch image family, as the frozen attestation job names
# it. Each entry must be resolved to an immutable digest, cross-compared between
# registries, scanned on both platforms, signed, attested, and verified.
IMAGE_FAMILIES = (
    ("standard", "", "STANDARD"),
    ("ebpf", "-ebpf", "EBPF"),
    ("ebpftools", "-ebpf-tools", "EBPF_TOOLS"),
)
FINAL_MANIFEST_JOBS = {
    "docker-manifest",
    "docker-ebpf-manifest",
    "docker-ebpf-tools-manifest",
}
# One per push-by-digest platform build: the `docker` job, plus the `-ebpf` and
# `-ebpf-tools` builds that share the `docker-ebpf` matrix job.
EXPECTED_PROVENANCE_DISABLED = 3


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

    if extract_needs(attest_job) != FINAL_MANIFEST_JOBS:
        errors.append(
            "jobs.attest-release-images must depend exactly on every final "
            "manifest job"
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

    if (
        workflow.count("provenance: false") != EXPECTED_PROVENANCE_DISABLED
        or "provenance: true" in workflow
    ):
        errors.append(
            "every push-by-digest platform build must keep provenance disabled; "
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

    # Each family is checked as a whole: resolved from its canonical tag to an
    # immutable digest, cross-compared between registries, scanned on both
    # platforms, signed, attested, and verified. A family that is published but
    # missing any of these would ship unsigned under an advertised release tag.
    family_invocations: list[str] = []
    for family, tag_suffix, variable_prefix in IMAGE_FAMILIES:
        docker_reference = f"${variable_prefix}_DOCKER_REF"
        ghcr_reference = f"${variable_prefix}_GHCR_REF"
        # The canonical tag must stay bound to its own family key, whether the
        # invocation fits on one line or uses a shell line continuation.
        for registry_repository in (
            r"ferrumedge/ferrum-edge:\$\{TAG_NAME\}",
            r"ghcr\.io/\$\{GITHUB_REPOSITORY\}:\$\{TAG_NAME\}",
        ):
            registry_key = "docker" if "ferrumedge" in registry_repository else "ghcr"
            resolution = (
                rf"resolve_manifest {family}_{registry_key}"
                rf"(?: \\\n\s+| )\"{registry_repository}"
                rf"{re.escape(tag_suffix)}\"\n"
            )
            if not re.search(resolution, attest_job):
                errors.append(
                    "jobs.attest-release-images does not resolve the canonical "
                    f"{family!r} {registry_key} tag to an immutable digest"
                )
        family_invocations.extend(
            (
                f"compare_registry_manifests {family}\n",
                f'generate_sboms \\\n            {family} docker "{docker_reference}"',
                f'generate_sboms \\\n            {family} ghcr "{ghcr_reference}"',
                f'sign_and_attest {family} docker "{docker_reference}"',
                f'sign_and_attest {family} ghcr "{ghcr_reference}"',
                f'verify_image {family} docker "{docker_reference}"',
                f'verify_image {family} ghcr "{ghcr_reference}"',
            )
        )
    for invocation in family_invocations:
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
                "    needs: [build-release-binaries, build-release-arm64-cross, docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest]",
                "    needs: [build-release-binaries, build-release-arm64-cross, docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest, attest-release-images]",
                1,
            ),
        ),
        (
            "create-release tools-manifest dependency",
            workflow.replace(
                "    needs: [build-release-binaries, build-release-arm64-cross, docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest]",
                "    needs: [build-release-binaries, build-release-arm64-cross, docker-manifest, docker-ebpf-manifest]",
                1,
            ),
        ),
        (
            "attestation tools-manifest dependency",
            workflow.replace(
                "    needs: [docker-manifest, docker-ebpf-manifest, docker-ebpf-tools-manifest]",
                "    needs: [docker-manifest, docker-ebpf-manifest]",
                1,
            ),
        ),
        (
            "tools-image canonical tag resolution",
            workflow.replace(
                'resolve_manifest ebpftools_docker \\\n'
                '            "ferrumedge/ferrum-edge:${TAG_NAME}-ebpf-tools"\n',
                "",
                1,
            ),
        ),
        (
            "tools-image signing",
            workflow.replace(
                '          sign_and_attest ebpftools ghcr "$EBPF_TOOLS_GHCR_REF"\n',
                "",
                1,
            ),
        ),
        (
            "tools-image SBOM generation",
            workflow.replace(
                "          generate_sboms \\\n"
                '            ebpftools docker "$EBPF_TOOLS_DOCKER_REF" \\\n'
                '            "$DOCKERHUB_USERNAME" "$DOCKERHUB_PASSWORD"\n',
                "",
                1,
            ),
        ),
        (
            "tools-image attestation verification",
            workflow.replace(
                '          verify_image ebpftools docker "$EBPF_TOOLS_DOCKER_REF"\n',
                "",
                1,
            ),
        ),
        (
            "tools-image cross-registry manifest comparison",
            workflow.replace(
                "          compare_registry_manifests ebpftools\n",
                "",
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
            "Release image attestation contract covers three image families "
            "(default, -ebpf, -ebpf-tools), two registries, immutable subjects, "
            "least-privilege OIDC, and a fail-closed publication gate compatible "
            "with trusted Cross policy."
        )
        return 0
    for error in errors:
        print(f"::error::{error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
