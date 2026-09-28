#!/usr/bin/env python3
"""Hosted CI checks for the DOC-02 migrate Kubernetes contract.

Kept out of `.github/workflows/ci.yml` shell so the trusted ARM64 build-policy
gate can compare unprotected workflow surfaces without freezing routine Helm
validation edits.

Process launches (helm template / kubectl dry-run) stay in the trusted workflow
shell. This script only statically parses captured results and repository files.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

MIGRATE_EXAMPLES = {
    "migrate-job-up.yaml": {"action": "up", "dry_run": False},
    "migrate-job-status.yaml": {"action": "status", "dry_run": False},
    "migrate-job-up-dry-run.yaml": {"action": "up", "dry_run": True},
    "migrate-job-config.yaml": {"action": "config", "dry_run": False},
}

BINARY_MODES = (
    "database",
    "file",
    "cp",
    "dp",
    "mesh",
    "injector",
    "node_agent",
    "migrate",
)


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def validate_migrate_examples(root: Path) -> None:
    examples_dir = root / "charts" / "ferrum-gateway" / "examples"
    for name, expect in MIGRATE_EXAMPLES.items():
        text = (examples_dir / name).read_text(encoding="utf-8")
        if not re.search(r"(?m)^kind:\s*Job\s*$", text):
            fail("Migrate example not a Job", f"{name} must be kind: Job")
        if not re.search(r"(?m)^\s*- name: FERRUM_MODE\s*$", text) or not re.search(
            r"(?m)^\s+value:\s*migrate\s*$", text
        ):
            fail("Migrate example missing FERRUM_MODE", name)
        if not re.search(
            rf"(?m)^\s*- name: FERRUM_MIGRATE_ACTION\s*$\n\s+value:\s*{re.escape(expect['action'])}\s*$",
            text,
        ):
            fail("Migrate example wrong action", name)
        has_dry = bool(re.search(r"(?m)^\s*- name: FERRUM_MIGRATE_DRY_RUN\s*$", text))
        if has_dry != expect["dry_run"]:
            fail("Migrate example dry-run mismatch", name)
        if "runAsNonRoot: true" not in text or "runAsUser: 65532" not in text:
            fail("Migrate example security drift", name)
        if name == "migrate-job-config.yaml":
            if "persistentVolumeClaim:" not in text or (
                "claimName: ferrum-file-config-migration" not in text
            ):
                fail(
                    "Config migration is ephemeral",
                    "config migration must use the documented writable PVC",
                )
            if (
                re.search(r"(?m)^\s*- name:\s*work\s*$\n\s+emptyDir:", text)
                or "busybox:" in text
            ):
                fail(
                    "Config migration output is not durable",
                    "config migration must not rely on emptyDir or an unpinned copy helper",
                )
    print("migrate job examples ok")


def validate_mode_contract_docs(root: Path) -> None:
    mode_contract = root / "docs" / "kubernetes_deployment.md"
    text = mode_contract.read_text(encoding="utf-8")
    for mode in BINARY_MODES:
        if not re.search(rf"(?m)^\| `{re.escape(mode)}` \|", text):
            fail(
                "Missing mode Kubernetes contract",
                f"{mode} must appear in the operating-mode table",
            )
    if "External pre-deploy Job" not in text:
        fail(
            "Missing external migrate contract",
            "docs/kubernetes_deployment.md must describe External pre-deploy Job",
        )
    if "charts/ferrum-gateway/examples/migrate-job-" not in text:
        fail(
            "Missing migrate Job example pointer",
            "docs/kubernetes_deployment.md must point at migrate-job examples",
        )

    stale = re.compile(
        r"migrate.*pointer to the right chart|migrate.*ferrum-mesh chart",
        re.IGNORECASE,
    )
    for relative in (
        Path("charts/ferrum-gateway/README.md"),
        Path("charts/ferrum-gateway/values.yaml"),
    ):
        content = (root / relative).read_text(encoding="utf-8")
        if stale.search(content):
            fail(
                "Stale migrate chart redirect",
                f"{relative} must not claim another chart owns migrate",
            )
    print("mode contract docs ok")


def validate_chart_mode_messages(results_dir: Path) -> None:
    migrate_err = results_dir / "migrate-mode.err"
    if not migrate_err.is_file():
        fail(
            "Missing migrate mode capture",
            "workflow must capture helm stderr to migrate-mode.err before this script",
        )
    migrate_text = migrate_err.read_text(encoding="utf-8")
    if "external pre-deploy Kubernetes Job" not in migrate_text:
        fail(
            "migrate mode message drift",
            "mode=migrate must mention external pre-deploy Kubernetes Job",
        )
    if re.search(r"live in the ferrum-mesh", migrate_text, re.IGNORECASE):
        fail(
            "migrate pointed at ferrum-mesh",
            "migrate must not redirect to the mesh chart",
        )

    mesh_err = results_dir / "mesh-mode.err"
    if not mesh_err.is_file():
        fail(
            "Missing mesh mode capture",
            "workflow must capture helm stderr to mesh-mode.err before this script",
        )
    mesh_text = mesh_err.read_text(encoding="utf-8")
    if "ferrum-mesh chart" not in mesh_text:
        fail(
            "mesh mode message drift",
            "mode=mesh must point operators at the ferrum-mesh chart",
        )
    print("chart mode messages ok")


# `latest` and `main-<sha>` are the moving development channel published from
# `main` by main-latest-image.yml (owner decision 2026-09-28), and the historical
# `latest-ebpf*` tags are retired. Documentation may name them, but a surface
# that deploys an image must pin a published release: chart values, templates
# (`.tpl` helpers included), examples, and schemas, and any Kubernetes/Helm
# usage shown in the docs (an `image:` field, a `tag:` value, or
# `--set image.tag=`, quoted or not).
DEVELOPMENT_TAG = r"(?:latest(?:-ebpf[\w.-]*)?|main-[0-9a-f]{7,40})(?![\w.-])"
REGISTRY_IMAGE = r"(?:(?:docker\.io/)?ferrumedge/ferrum-edge|ghcr\.io/ferrum-edge/ferrum-edge)"
CHART_MANIFEST_SUFFIXES = frozenset({".yaml", ".yml", ".json", ".tpl", ".txt"})

DEVELOPMENT_IMAGE = re.compile(rf"{REGISTRY_IMAGE}:{DEVELOPMENT_TAG}")
DEVELOPMENT_TAG_VALUE = re.compile(
    rf"(?m)^\s*(?:-\s+)?tag:\s*[\"']?{DEVELOPMENT_TAG}[\"']?\s*(?:#.*)?$"
)
DEVELOPMENT_IMAGE_FIELD = re.compile(
    rf"(?m)^\s*(?:-\s+)?image:\s*[\"']?{REGISTRY_IMAGE}:{DEVELOPMENT_TAG}"
)
DEVELOPMENT_SET_TAG = re.compile(rf"image\.tag=[\"']?{DEVELOPMENT_TAG}")
DEVELOPMENT_TEMPLATE_DEFAULT = re.compile(rf"default\s+[\"']{DEVELOPMENT_TAG}[\"']")


def is_chart_manifest(relative: str) -> bool:
    path = Path(relative)
    return path.parts[:1] == ("charts",) and path.suffix in CHART_MANIFEST_SUFFIXES


def development_tag_findings(files: dict[str, str]) -> list[tuple[str, str]]:
    """Return `(title, detail)` for each file that deploys a development tag.

    `files` maps repository-relative paths to their text. Chart manifests and
    templates are held to every pattern; Markdown only to deployment examples.
    """

    findings: list[tuple[str, str]] = []
    for relative, text in files.items():
        if is_chart_manifest(relative):
            if (
                DEVELOPMENT_IMAGE.search(text)
                or DEVELOPMENT_TAG_VALUE.search(text)
                or DEVELOPMENT_SET_TAG.search(text)
                or DEVELOPMENT_TEMPLATE_DEFAULT.search(text)
            ):
                findings.append(
                    (
                        "Development image tag in a chart",
                        f"{relative} deploys latest, latest-ebpf*, or main-<sha>; charts "
                        "must default to a published version or the chart appVersion",
                    )
                )
        elif relative.endswith(".md") and (
            DEVELOPMENT_TAG_VALUE.search(text)
            or DEVELOPMENT_IMAGE_FIELD.search(text)
            or DEVELOPMENT_SET_TAG.search(text)
        ):
            findings.append(
                (
                    "Development image tag in a deployment example",
                    f"{relative} deploys latest, latest-ebpf*, or main-<sha> in a "
                    "Kubernetes or Helm example; pin a published version or digest",
                )
            )
    return findings


def published_image_tag_files(root: Path) -> dict[str, str]:
    paths = [*sorted((root / "docs").glob("*.md"))]
    paths.extend(
        path
        for path in sorted((root / "charts").rglob("*"))
        if path.is_file() and (path.suffix in CHART_MANIFEST_SUFFIXES or path.suffix == ".md")
    )
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8") for path in paths
    }


def validate_published_image_tags(root: Path) -> None:
    findings = development_tag_findings(published_image_tag_files(root))
    if findings:
        fail(*findings[0])
    print("published image tags ok")


def run_self_test(root: Path = REPO_ROOT) -> list[str]:
    """Mutation self-test for the published image tag rule."""

    failures: list[str] = []
    files = published_image_tag_files(root)
    baseline = development_tag_findings(files)
    if baseline:
        failures.append(
            "the checked-in docs and charts must satisfy the published image tag rule: "
            + "; ".join(detail for _, detail in baseline)
        )

    rejected = {
        "chart values tag": ("charts/example/values.yaml", "image:\n  tag: latest\n"),
        "quoted chart values tag": ("charts/example/values.yaml", 'image:\n  tag: "latest"\n'),
        "chart main-sha tag": ("charts/example/values.yaml", "  tag: main-0123abcd\n"),
        "chart image reference": (
            "charts/example/templates/job.yaml",
            "image: ghcr.io/ferrum-edge/ferrum-edge:latest@sha256:" + "0" * 64 + "\n",
        ),
        "template default": (
            "charts/example/templates/_helpers.tpl",
            '{{- .Values.image.tag | default "latest" }}\n',
        ),
        "historical eBPF tag in a chart": (
            "charts/example/values.yaml",
            "  tag: latest-ebpf-tools\n",
        ),
        "docs quoted set tag": (
            "docs/example.md",
            'helm install gw charts/ferrum-gateway --set image.tag="latest"\n',
        ),
        "docs single-quoted set tag": (
            "docs/example.md",
            "helm install gw charts/ferrum-gateway --set image.tag='main-0123abcd'\n",
        ),
        "docs image field": (
            "docs/example.md",
            "    image: ferrumedge/ferrum-edge:latest\n",
        ),
        "docs historical eBPF image": (
            "docs/example.md",
            "    image: docker.io/ferrumedge/ferrum-edge:latest-ebpf\n",
        ),
        "chart README set tag": (
            "charts/example/README.md",
            "--set image.tag=latest-ebpf\n",
        ),
    }
    for label, (relative, text) in rejected.items():
        if not development_tag_findings({relative: text}):
            failures.append(f"published image tag self-test {label!r} was not rejected")

    accepted = {
        "docs names latest in prose": (
            "docs/example.md",
            "`latest` on `ferrumedge/ferrum-edge` follows main.\n",
        ),
        "docs pull of latest": ("docs/example.md", "docker pull ferrumedge/ferrum-edge:latest\n"),
        "docs published set tag": ("docs/example.md", "--set image.tag=<published-tag>\n"),
        "chart published tag": ("charts/example/values.yaml", '  tag: "0.9.5"\n'),
        "chart release eBPF tag": ("charts/example/values.yaml", "  tag: v0.9.5-ebpf\n"),
        "local build tag": ("docs/example.md", "docker build -t ferrum-edge:latest .\n"),
    }
    for label, (relative, text) in accepted.items():
        if development_tag_findings({relative: text}):
            failures.append(f"published image tag self-test {label!r} was rejected")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (defaults to the checkout containing this script)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        help="Directory with helm template stdout/stderr captures from the workflow",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the published image tag mutation self-test and exit",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.self_test:
        failures = run_self_test(root)
        for failure in failures:
            print(f"::error title=Published image tag self-test::{failure}")
        return 1 if failures else 0
    if args.results_dir is None:
        parser.error("--results-dir is required unless --self-test is given")
    results_dir = args.results_dir.resolve()

    validate_chart_mode_messages(results_dir)
    validate_migrate_examples(root)
    validate_mode_contract_docs(root)
    validate_published_image_tags(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
