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
        required=True,
        help="Directory with helm template stdout/stderr captures from the workflow",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    results_dir = args.results_dir.resolve()

    validate_chart_mode_messages(results_dir)
    validate_migrate_examples(root)
    validate_mode_contract_docs(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
