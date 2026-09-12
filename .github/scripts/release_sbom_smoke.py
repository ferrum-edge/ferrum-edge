#!/usr/bin/env python3
"""Hosted-only, anonymous reproduction of the production SPDX contract (#4856).

Extract the actual release scan command and predicates; do not maintain a more
permissive test implementation. Only the pinned Syft scanner runs, never the
Ferrum images. Evidence is not publication authorization.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap


# From the successful immutable manifest resolution in run 33984483575,
# job 101372033947 (source af1bfcccc1c9eefc1aa118e8eff8fd218e9e6c4a).
DIGESTS = {
    "standard": "25544aab4d9cd34276c5bb4fbbd59ae565297e9b833be78ec878c8fc7e4deeed",
    "ebpf": "9479352b03a1f5d1857046cdcc516d64d428252822e3ff765c978b172d021f95",
    "ebpftools": "774341dacfd1dd0d0c63f03f2228a150f31c04bc4e0b55ab93311a646bf82332",
}
REPOSITORIES = {
    "docker": "ferrumedge/ferrum-edge",
    "ghcr": "ghcr.io/ferrum-edge/ferrum-edge",
}
# Exact predicate from release.yml at the failed run's source commit, before
# c27e5e55eda97047a35af0bb0fd87fea760dcb82 accepted DESCRIBES relationships.
HISTORICAL_PREDICATE = Path(".github/fixtures/release-sbom/require_sbom-af1bfcccc1c9.jq")


def exactly_one(pattern: str, source: str) -> str:
    matches = re.findall(pattern, source, re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise ValueError("release SBOM contract extraction changed; review the hosted harness")
    return matches[0]


def production_contract(workflow: str) -> tuple[str, str, str]:
    job = exactly_one(
        r"^  attest-release-images:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow
    )

    def predicate(name: str) -> str:
        return textwrap.dedent(exactly_one(
            rf"^          cat > \"\$work/{name}\.jq\" <<'JQ'\n(.*?)^          JQ$",
            job,
        ))

    scan = exactly_one(
        r"^              (docker run --rm \\\n.*?"
        r'^                -o "spdx-json=/out/\$\{family\}_\$\{registry\}-\$\{arch\}\.spdx\.json")$',
        job,
    )
    if len(re.findall(r"anchore/syft@sha256:[0-9a-f]{64}", scan)) != 1:
        raise ValueError("production scanner must remain digest-pinned")
    if 'jq -e -f "$work/require_sbom.jq" "$output" >/dev/null' not in job:
        raise ValueError("production SPDX validation invocation changed")
    # The policy must see executable code as literals. Compare the literal
    # scanner invocation below with production as data; never execute extracted
    # workflow text. Ignore only line indentation/continuation and shell exec;
    # preserve quoting so a shell-semantics change cannot pass as equivalent.
    tree = ast.parse(Path(__file__).read_text())
    scans = [
        ast.literal_eval(node.args[0])[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess" and node.func.attr == "run"
        and isinstance(node.args[0], ast.List)
        and isinstance(node.args[0].elts[-1], ast.Constant)
        and str(node.args[0].elts[-1].value).startswith("exec docker run")
    ]
    normalized_scan = " ".join(line.strip().removesuffix("\\").rstrip()
                               for line in scan.splitlines())
    if len(scans) != 1 or scans[0].removeprefix("exec ") != normalized_scan:
        raise ValueError("literal scanner command differs from production")
    return predicate("require_manifest"), predicate("require_sbom"), scan


def run_stage(
    stage: str, work: Path, env: dict[str, str],
    results: dict, timeout: float = 300, expected_exit_code: int = 0,
) -> bool:
    """Persist an operation's status even on timeout; never swallow failure."""
    if stage not in ("manifest", "manifest-validation", "syft-scan", "spdx-validation",
                     "historical-spdx-validation"):
        raise ValueError("unsupported diagnostic stage")
    if expected_exit_code != 0 and (stage != "historical-spdx-validation" or expected_exit_code != 1):
        raise ValueError("only the historical predicate may expect rejection")
    results[stage] = {"status": "running"}
    status_file = work / "status.json"
    status_file.write_text(json.dumps(results, indent=2) + "\n")
    with (work / f"{stage}.stdout.txt").open("wb") as stdout, (
        work / f"{stage}.stderr.txt"
    ).open("wb") as stderr:
        try:
            # Literal shell programs with quoted environment data follow the
            # existing hosted harness pattern. No variable selects a program.
            if stage == "manifest":
                result = subprocess.run([
                    "bash", "-euo", "pipefail", "-c",
                    'exec docker buildx imagetools inspect "$image_ref" --format "{{json .Manifest}}"',
                ], env=env, stdout=stdout, stderr=stderr, check=False, timeout=timeout)
            elif stage == "manifest-validation":
                result = subprocess.run([
                    "bash", "-euo", "pipefail", "-c",
                    'exec jq -e -f "$work/require_manifest.jq" "$work/manifest.stdout.txt"',
                ], env=env, stdout=stdout, stderr=stderr, check=False, timeout=timeout)
            elif stage == "syft-scan":
                result = subprocess.run([
                    "bash", "-euo", "pipefail", "-c",
                    'exec docker run --rm '
                    '-e SYFT_CHECK_FOR_APP_UPDATE=false '
                    '-e SYFT_REGISTRY_AUTH_USERNAME="$registry_username" '
                    '-e SYFT_REGISTRY_AUTH_PASSWORD="$registry_password" '
                    '-v "$work:/out" '
                    'anchore/syft@sha256:9a9f85314017f1ea798fb012edfa7fe9259923910f82c8d4bc983ab5c765e60b '
                    'scan "registry:${image_ref}" --platform "$platform" '
                    '-o "spdx-json=/out/${family}_${registry}-${arch}.spdx.json"',
                ], env=env, stdout=stdout, stderr=stderr, check=False, timeout=timeout)
            elif stage == "spdx-validation":
                result = subprocess.run([
                    "bash", "-euo", "pipefail", "-c",
                    'exec jq -e -f "$work/require_sbom.jq" "$work/${family}_${registry}-${arch}.spdx.json"',
                ], env=env, stdout=stdout, stderr=stderr, check=False, timeout=timeout)
            else:
                result = subprocess.run([
                    "bash", "-euo", "pipefail", "-c",
                    'exec jq -e -f "$work/historical_require_sbom.jq" "$work/${family}_${registry}-${arch}.spdx.json"',
                ], env=env, stdout=stdout, stderr=stderr, check=False, timeout=timeout)
            results[stage] = {"exit_code": result.returncode}
        except subprocess.TimeoutExpired:
            results[stage] = {"status": "timeout", "timeout_seconds": timeout}
        except OSError as error:
            results[stage] = {"status": "launch_error", "errno": error.errno}
    results[stage]["expected_exit_code"] = expected_exit_code
    status_file.write_text(json.dumps(results, indent=2) + "\n")
    passed = results[stage].get("exit_code") == expected_exit_code
    print(f"{stage}: {json.dumps(results[stage])}", flush=True)
    if not passed:
        print(f"::error::{stage} failed; inspect release-sbom evidence")
    return passed


def describe_spdx(path: Path) -> dict:
    """Report shapes/counts separately from the unmodified jq gate."""
    if not path.exists():
        return {"file_exists": False}
    try:
        document = json.loads(path.read_text())
    except (ValueError, UnicodeError):
        return {"file_exists": True, "bytes": path.stat().st_size, "json_valid": False}
    if not isinstance(document, dict):
        return {"json_valid": True, "object": False}
    summary = {"json_valid": True, "object": True, "fields": {}}
    for key in ("spdxVersion", "documentNamespace", "packages", "documentDescribes", "relationships"):
        value = document.get(key)
        summary["fields"][key] = {
            "type": type(value).__name__,
            "length": len(value) if isinstance(value, (str, list, dict)) else None,
        }
    relationships = document.get("relationships")
    summary["document_describes_relationships"] = sum(
        isinstance(rel, dict)
        and rel.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and rel.get("relationshipType") == "DESCRIBES"
        for rel in (relationships if isinstance(relationships, list) else [])
    )
    return summary


def main() -> int:
    family = os.environ["SBOM_FAMILY"]
    registry = os.environ["SBOM_REGISTRY"]
    arch = os.environ["SBOM_ARCH"]
    if arch not in ("amd64", "arm64"):
        raise ValueError("unsupported production platform")
    image_ref = f"{REPOSITORIES[registry]}@sha256:{DIGESTS[family]}"
    work = Path(os.environ["RUNNER_TEMP"]) / "release-sbom-evidence"
    work.mkdir(parents=True, exist_ok=False)
    results = {"image_ref": image_ref, "platform": f"linux/{arch}",
               "workflow_sha": os.environ["GITHUB_SHA"]}
    manifest_filter, sbom_filter, scan = production_contract(
        Path(".github/workflows/release.yml").read_text()
    )
    (work / "require_manifest.jq").write_text(manifest_filter)
    (work / "require_sbom.jq").write_text(sbom_filter)
    (work / "historical_require_sbom.jq").write_text(HISTORICAL_PREDICATE.read_text())
    (work / "scan-command.txt").write_text(scan + "\n")

    # No job credentials, Docker credential helpers, registry secrets, or
    # scanner debug environment are passed into subprocesses or artifacts.
    with tempfile.TemporaryDirectory(prefix="anonymous-sbom-") as config:
        # Find setup-buildx's CLI plugin without importing Docker login state.
        (Path(config) / "config.json").write_text(json.dumps({
            "cliPluginsExtraDirs": [str(Path.home() / ".docker" / "cli-plugins")],
        }))
        env = {"PATH": os.environ["PATH"], "HOME": config, "DOCKER_CONFIG": config,
               "work": str(work), "family": family, "registry": registry,
               "arch": arch, "platform": f"linux/{arch}", "image_ref": image_ref,
               "registry_username": "", "registry_password": ""}
        if not run_stage("manifest", work, env, results):
            return 1
        manifest = work / "manifest.stdout.txt"
        if not run_stage("manifest-validation", work, env, results):
            return 1
        data = json.loads(manifest.read_text())
        if data["digest"] != f"sha256:{DIGESTS[family]}":
            raise ValueError("registry returned a different immutable subject")
        results["platform_digest"] = next(
            item["digest"] for item in data["manifests"]
            if item["platform"].get("architecture") == arch
            and item["platform"].get("os") == "linux"
        )
        scanned = run_stage("syft-scan", work, env, results, timeout=480)
        output = work / f"{family}_{registry}-{arch}.spdx.json"
        (work / "spdx-summary.json").write_text(json.dumps(describe_spdx(output), indent=2) + "\n")
        # Run jq even after scan failure: record missing/partial output, but a
        # valid leftover file must never turn a failed scan into success.
        valid = run_stage("spdx-validation", work, env, results)
        historical_rejection = run_stage("historical-spdx-validation", work, env, results,
                                         expected_exit_code=1)
        return 0 if scanned and valid and historical_rejection else 1


if __name__ == "__main__":
    raise SystemExit(main())
