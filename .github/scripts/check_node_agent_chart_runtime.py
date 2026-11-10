#!/usr/bin/env python3
"""Reject container-runtime escape mounts in Ferrum node-agent/ambient charts.

`docs/node_agent_security.md` claims CI rejects chart diffs that add a container
runtime socket mount or `privileged: true` on the node-agent / ambient
workloads. This checker is that gate.

The Helm Chart job extracts this script from the base branch and runs it against
the pull request's chart tree. While that step remains wired, a pull request
cannot make the job execute its proposed checker. The workflow wiring remains a
reviewed PR surface and is independently checked by `verify_required_ci.py`.
The job is deliberately separate from `ci-plan`: the trusted ARM64 Cross build
policy freezes the per-job digest of every Cross-sensitive `ci.yml` job, and
`ci-plan` is one of them.

The scanner checks both chart sources (after stripping comments) and manifests
Helm renders for every chart under `charts/` (defaults, example values, and the
mesh node-agent/ambient switches), so helpers and expressions cannot conceal
dangerous output in either chart.
Rendered checks prefer `FERRUM_TRUSTED_HELM` when CI pins the installer output.

Usage:
  python3 -I .github/scripts/check_node_agent_chart_runtime.py --self-test
  python3 -I .github/scripts/check_node_agent_chart_runtime.py
  python3 -I .github/scripts/check_node_agent_chart_runtime.py --root <path>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Bound helm failure detail so a hostile chart cannot flood CI logs or smuggle
# oversized stderr into the fail-closed diagnostic.
MAX_HELM_ERROR_CHARS = 2048
DEFAULT_HELM_RENDER_TIMEOUT_SECONDS = 60.0
TRUSTED_HELM_ENV = "FERRUM_TRUSTED_HELM"

EXAMPLE_VALUE_GLOBS: tuple[str, ...] = (
    "examples/**/*.yaml",
    "examples/**/*.yml",
    "examples/**/*.json",
)


def default_repo_root() -> Path:
    """Resolve the Ferrum checkout when the script may be base-extracted to TEMP.

    Trusted CI copies this file under `$RUNNER_TEMP` and runs it with
    `python3 -I`, so `__file__`-relative parents are not the repository. Prefer
    the process working directory (CI checks out and runs from the repo root)
    and only fall back to the in-tree `.github/scripts/` layout.
    """

    cwd = Path.cwd()
    if (cwd / "charts" / "ferrum-mesh" / "templates").is_dir():
        return cwd
    if (REPO_ROOT / "charts" / "ferrum-mesh" / "templates").is_dir():
        return REPO_ROOT
    return cwd


# Fail closed if any of these governed surfaces is missing or unreadable.
REQUIRED_RELATIVE_PATHS: tuple[str, ...] = (
    "charts/ferrum-mesh/templates/node-agent-daemonset.yaml",
    "charts/ferrum-mesh/templates/ambient-daemonset.yaml",
    "charts/ferrum-mesh/values.yaml",
)

# Every rendered template and every values/example input is governed. Keeping
# this recursive and chart-wide prevents a rename, a second DaemonSet template,
# a helper fragment, or the sibling gateway chart from becoming an escape hatch.
GOVERNED_GLOBS: tuple[str, ...] = (
    "charts/**/templates/**/*",
    "charts/**/values*.yaml",
    "charts/**/values*.yml",
    "charts/**/values*.json",
    "charts/**/examples/**/*.yaml",
    "charts/**/examples/**/*.yml",
    "charts/**/examples/**/*.json",
    "charts/**/files/**/*",
)

HELM_COMMENT_RE = re.compile(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", re.DOTALL)
FULL_LINE_HASH_COMMENT_RE = re.compile(r"(?m)^\s*#.*$")
# Trailing YAML `#` comments outside simple quoted scalars.
TRAILING_HASH_COMMENT_RE = re.compile(
    r"(?m)^(?P<code>(?:[^#'\"\n]|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")*?)\s+#.*$"
)
YAML_LINE_CONTINUATION_RE = re.compile(r"\\\r?\n[ \t]*")
YAML_JSON_CODEPOINT_ESCAPE_RE = re.compile(
    r"\\(?:x(?P<x>[0-9a-fA-F]{2})|u(?P<u>[0-9a-fA-F]{4})|U(?P<U>[0-9a-fA-F]{8}))"
)

# Reject a privileged field unless its value is a literal false. This catches
# hard-coded true, inline YAML/JSON, and Helm expressions such as
# `privileged: {{ .Values.foo }}` whose default might be false but which would
# otherwise create an operator-controlled privilege escalation.
PRIVILEGED_ASSIGNMENT_RE = re.compile(
    r"(?im)(?:^[ \t]*|[,{][ \t]*)[\"']?privileged[\"']?[ \t]*:[ \t]*"
    r"(?P<value>[^,}\n]+)"
)
LITERAL_FALSE_VALUES = frozenset(("false", '"false"', "'false'"))

# Path / socket references that grant container-runtime or host-escape access.
PROHIBITED_REFERENCE_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("docker.sock", re.compile(r"docker\.sock", re.IGNORECASE)),
    ("containerd.sock", re.compile(r"containerd\.sock", re.IGNORECASE)),
    ("crio.sock", re.compile(r"cri-?o\.sock", re.IGNORECASE)),
    ("runtime.sock", re.compile(r"(?:^|[\s\"'=/])runtime\.sock\b", re.IGNORECASE)),
    ("/var/run/docker", re.compile(r"/var/run/docker(?:/|\b)", re.IGNORECASE)),
    ("/var/lib/docker", re.compile(r"/var/lib/docker(?:/|\b)", re.IGNORECASE)),
    ("/run/containerd", re.compile(r"/run/containerd(?:/|\b)", re.IGNORECASE)),
    (
        "/var/run/containerd",
        re.compile(r"/var/run/containerd(?:/|\b)", re.IGNORECASE),
    ),
    (
        "/var/lib/containerd",
        re.compile(r"/var/lib/containerd(?:/|\b)", re.IGNORECASE),
    ),
    ("/run/crio", re.compile(r"/run/cri-?o(?:/|\b)", re.IGNORECASE)),
    ("/var/run/crio", re.compile(r"/var/run/cri-?o(?:/|\b)", re.IGNORECASE)),
    ("/var/lib/crio", re.compile(r"/var/lib/cri-?o(?:/|\b)", re.IGNORECASE)),
)


def strip_chart_comments(text: str) -> str:
    """Remove Helm block comments and YAML `#` comments before scanning."""

    without_helm = HELM_COMMENT_RE.sub("", text)
    without_full = FULL_LINE_HASH_COMMENT_RE.sub("", without_helm)
    return TRAILING_HASH_COMMENT_RE.sub(r"\g<code>", without_full)


def normalize_interpreted_escapes(text: str) -> str:
    """Expose YAML/JSON escapes before applying security regexes.

    Kubernetes parses rendered YAML/JSON before it consumes fields such as
    `hostPath.path` and `securityContext.privileged`. A raw-text scan must
    therefore not let `dock\\u0065r.sock`, an escaped `privile\\u0067ed` key,
    or a YAML double-quoted line continuation hide the value Kubernetes will
    see. Decoding outside a quoted scalar can only create a conservative false
    positive; it cannot make the gate more permissive.
    """

    joined = YAML_LINE_CONTINUATION_RE.sub("", text)

    def decode(match: re.Match[str]) -> str:
        raw = match.group("x") or match.group("u") or match.group("U")
        assert raw is not None
        value = int(raw, 16)
        if value > 0x10FFFF:
            return match.group(0)
        return chr(value)

    return YAML_JSON_CODEPOINT_ESCAPE_RE.sub(decode, joined).replace(r"\/", "/")


def iter_scan_paths(root: Path) -> list[Path]:
    paths: set[Path] = set()
    missing: list[str] = []
    for relative in REQUIRED_RELATIVE_PATHS:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            missing.append(relative)
            continue
        paths.add(path)
    if missing:
        raise FileNotFoundError(
            "required node-agent/ambient chart surfaces missing or not regular "
            f"files: {', '.join(missing)}"
        )
    for pattern in GOVERNED_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path.is_symlink():
                relative = path.relative_to(root).as_posix()
                raise OSError(
                    f"governed chart surface must not be a symlink: {relative}"
                )
            if path.is_file():
                paths.add(path)
    return sorted(paths)


def scan_text(relative: str, text: str) -> list[str]:
    content = normalize_interpreted_escapes(strip_chart_comments(text))
    findings: list[str] = []
    for match in PRIVILEGED_ASSIGNMENT_RE.finditer(content):
        value = match.group("value").strip().lower()
        if value not in LITERAL_FALSE_VALUES:
            findings.append(
                f"{relative}: privileged must be literal false "
                "(true or dynamic values are prohibited)"
            )
            break
    for label, pattern in PROHIBITED_REFERENCE_RES:
        if pattern.search(content):
            findings.append(
                f"{relative}: prohibited container-runtime/host-escape "
                f"reference ({label})"
            )
    return findings


def scan_file(root: Path, path: Path) -> list[str]:
    if path.is_symlink():
        raise OSError(f"governed chart surface must not be a symlink: {path}")
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"scan path escapes repository root: {path}") from exc
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"unreadable chart surface {relative}: {exc}") from exc
    return scan_text(relative, text)


def _bound_helm_detail(text: str) -> str:
    cleaned = text.replace("\x00", "").strip()
    if len(cleaned) <= MAX_HELM_ERROR_CHARS:
        return cleaned
    return f"{cleaned[:MAX_HELM_ERROR_CHARS]}...[truncated]"


def resolve_helm_binary() -> str:
    """Resolve the Helm binary used for authoritative rendered-manifest checks.

    Prefer `FERRUM_TRUSTED_HELM` when CI points at the pinned installer output so
    a later PATH prepend cannot substitute a fake renderer. Fall back to
    `PATH` lookup for local use. Either source must be a regular executable
    file (never a symlink). When the trusted env var is set it is mandatory:
    PATH is not consulted as a silent fallback.
    """

    trusted = os.environ.get(TRUSTED_HELM_ENV, "").strip()
    candidate = trusted if trusted else (shutil.which("helm") or "")
    if not candidate:
        raise FileNotFoundError("helm is required to inspect rendered chart manifests")

    path = Path(candidate)
    try:
        if path.is_symlink():
            raise FileNotFoundError(
                f"helm binary must not be a symlink: {candidate}"
            )
        if not path.is_file():
            raise FileNotFoundError(
                f"helm binary is not a regular file: {candidate}"
            )
        mode = path.stat().st_mode
        if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            raise FileNotFoundError(f"helm binary is not executable: {candidate}")
    except OSError as exc:
        raise FileNotFoundError(
            f"helm is required to inspect rendered chart manifests ({exc})"
        ) from exc
    return str(path)


# Extra renders beyond the defaults and the example values files. The mesh
# node-agent and ambient workloads are off by default, so they are also rendered
# switched on.
CHART_EXTRA_RENDERS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "ferrum-mesh": (
        (
            "node-agent-and-ambient",
            ("--set", "nodeAgent.enabled=true", "--set", "ambient.enabled=true"),
        ),
    ),
}

TOP_LEVEL_YAML_KEY_RE = re.compile(
    r"(?m)^[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[\"']?[ \t]*:(?:[ \t]|$)"
)


def iter_chart_directories(root: Path) -> list[Path]:
    """Return every chart directory directly under `charts/`.

    The rendered pass covers every chart, not one named chart, so a chart
    added beside `ferrum-mesh` and `ferrum-gateway` is rendered too. A
    symlinked `charts/` or chart directory fails closed.
    """

    charts_dir = root / "charts"
    if charts_dir.is_symlink():
        raise OSError(f"charts directory must not be a symlink: {charts_dir}")
    if not charts_dir.is_dir():
        return []
    directories: list[Path] = []
    for child in sorted(charts_dir.iterdir()):
        if child.is_symlink():
            raise OSError(f"chart directory must not be a symlink: {child}")
        if child.is_dir():
            directories.append(child)
    return directories


def example_is_values_input(chart: Path, path: Path) -> bool:
    """Whether Helm could accept this example file as a values input.

    Chart examples also hold plain Kubernetes manifests (for example the
    gateway chart's migrate Jobs). They carry no template expressions and are
    already source-scanned, and Helm refuses them as values when the chart's
    `values.schema.json` forbids unknown top-level keys. Only that provable
    case is skipped; any file whose keys cannot be read, or a chart without
    such a schema, is rendered, so an unreadable input fails closed in Helm.
    """

    schema_path = chart / "values.schema.json"
    if schema_path.is_symlink() or not schema_path.is_file():
        return True
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        return True
    properties = schema.get("properties")
    allowed = set(properties) if isinstance(properties, dict) else set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return True
    if path.suffix == ".json":
        try:
            document = json.loads(text)
        except ValueError:
            return True
        keys = set(document) if isinstance(document, dict) else set()
    else:
        keys = {
            match.group("key")
            for match in TOP_LEVEL_YAML_KEY_RE.finditer(strip_chart_comments(text))
        }
    return not keys or keys <= allowed


def iter_chart_example_value_files(root: Path, chart_name: str) -> list[Path]:
    """Discover one chart's example values inputs in parity with GOVERNED_GLOBS."""

    charts_dir = root / "charts"
    chart_path = charts_dir / chart_name
    examples_path = chart_path / "examples"
    for label, directory in (
        ("charts", charts_dir),
        (f"{chart_name} chart", chart_path),
        (f"{chart_name} examples", examples_path),
    ):
        if directory.is_symlink():
            raise OSError(f"{label} directory must not be a symlink: {directory}")
    if not examples_path.is_dir():
        return []
    for candidate in examples_path.rglob("*"):
        if candidate.is_symlink():
            raise OSError(
                f"chart example tree must not contain symlinks: {candidate}"
            )

    chart = chart_path.resolve()
    examples_root = examples_path.resolve()
    try:
        examples_root.relative_to(chart)
    except ValueError as exc:
        raise ValueError(
            f"{chart_name} examples directory escapes chart boundary"
        ) from exc
    discovered: set[Path] = set()
    for pattern in EXAMPLE_VALUE_GLOBS:
        for path in sorted(chart.glob(pattern)):
            if path.is_symlink():
                relative = path.resolve().as_posix() if path.exists() else path.as_posix()
                raise OSError(
                    f"chart example values must not be a symlink: {relative}"
                )
            if not path.is_file():
                continue
            resolved = path.resolve()
            try:
                resolved.relative_to(examples_root)
                resolved.relative_to(root.resolve())
            except ValueError as exc:
                raise ValueError(
                    f"chart example values escape repository/chart boundary: {path}"
                ) from exc
            if example_is_values_input(chart, resolved):
                discovered.add(resolved)
    return sorted(discovered)


def render_chart_manifests(
    root: Path,
    *,
    helm_bin: str | None = None,
    timeout_seconds: float = DEFAULT_HELM_RENDER_TIMEOUT_SECONDS,
) -> list[tuple[str, str]]:
    """Render every chart with its defaults, extra switches, and example values.

    GHSA-4xcp-8c2m-g84j: rendering only `charts/ferrum-mesh` let a socket path
    that a `charts/ferrum-gateway` template builds at render time (for example
    with `printf`) pass both layers, although that chart is deployed into the
    same clusters.
    """

    helm = helm_bin if helm_bin is not None else resolve_helm_binary()
    mesh = root / "charts/ferrum-mesh"
    if mesh.is_symlink() or not mesh.is_dir():
        raise OSError("charts/ferrum-mesh must be a regular directory")
    renders: list[tuple[str, Path, list[str]]] = []
    for chart in iter_chart_directories(root):
        name = chart.name
        renders.append((f"{name}:defaults", chart, []))
        for label, extra_args in CHART_EXTRA_RENDERS.get(name, ()):
            renders.append((f"{name}:{label}", chart, list(extra_args)))
        for values in iter_chart_example_value_files(root, name):
            label = values.relative_to(chart.resolve()).as_posix()
            renders.append((f"{name}:values:{label}", chart, ["--values", str(values)]))

    manifests: list[tuple[str, str]] = []
    for label, chart, extra_args in renders:
        command = [helm, "template", "ferrum-runtime-lint", str(chart), *extra_args]
        try:
            result = subprocess.run(
                command,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"helm render {label} timed out") from exc
        if result.returncode != 0:
            detail = _bound_helm_detail(result.stderr) or _bound_helm_detail(
                result.stdout
            )
            raise OSError(f"helm render {label} failed: {detail}")
        manifests.append((label, result.stdout))
    return manifests


def check_repository(
    root: Path | None = None,
    *,
    render: bool = False,
    helm_bin: str | None = None,
    timeout_seconds: float = DEFAULT_HELM_RENDER_TIMEOUT_SECONDS,
) -> list[str]:
    base = default_repo_root() if root is None else root
    if not base.is_dir():
        raise NotADirectoryError(f"chart check root is not a directory: {base}")
    findings: list[str] = []
    for path in iter_scan_paths(base):
        findings.extend(scan_file(base, path))
    if render:
        for label, manifest in render_chart_manifests(
            base, helm_bin=helm_bin, timeout_seconds=timeout_seconds
        ):
            findings.extend(scan_text(f"helm-render:{label}", manifest))
    return findings


def _write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _required_tree(root: Path, *, node_agent: str, ambient: str, values: str) -> None:
    _write(root / REQUIRED_RELATIVE_PATHS[0], node_agent)
    _write(root / REQUIRED_RELATIVE_PATHS[1], ambient)
    _write(root / REQUIRED_RELATIVE_PATHS[2], values)


_CLEAN_NODE_AGENT = """\
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferrum-mesh-node-agent
spec:
  template:
    spec:
      containers:
        - name: ferrum-edge
          securityContext:
            privileged: false
          volumeMounts:
            - name: bpf-fs
              mountPath: /sys/fs/bpf
            - name: cgroup
              mountPath: /sys/fs/cgroup
              readOnly: true
      volumes:
        - name: bpf-fs
          hostPath:
            path: /sys/fs/bpf
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
"""

_CLEAN_AMBIENT = """\
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferrum-mesh-ambient
spec:
  template:
    spec:
      containers:
        - name: ferrum-edge
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
"""

_CLEAN_VALUES = """\
nodeAgent:
  enabled: true
  security:
    # Pod-wide seccomp profile. RuntimeDefault is the containerd default
    # and permits every syscall the agent needs.
    seccompProfile:
      type: RuntimeDefault
  cni:
    hostSocketDir: /var/run/ferrum
    socketFileName: node-agent-cni.sock
ambient:
  enabled: true
  spire:
    socketHostPath: /run/spire/sockets
"""


def run_self_test() -> list[str]:
    """Synthetic fixtures: prohibited examples fail; legitimate chart content passes."""

    failures: list[str] = []

    constructed_source = (
        'path: {{ printf "/%s/%s/%s.%s" "var" "run" "docker" "sock" }}'
    )
    if scan_text("constructed-source", constructed_source):
        failures.append("constructed Helm source unexpectedly matched a literal path")
    constructed_render = "path: /var/run/docker.sock"
    if not scan_text("constructed-render", constructed_render):
        failures.append("rendered Helm expression did not expose its prohibited path")
    constructed_privileged_render = "securityContext:\n  privileged: true\n"
    if not scan_text("constructed-privileged-render", constructed_privileged_render):
        failures.append(
            "rendered Helm privileged assignment did not expose privileged: true"
        )
    encoded_render = r'path: "\u002fvar\u002frun\u002fdock\u0065r\u002esock"'
    if not scan_text("encoded-render", encoded_render):
        failures.append("YAML/JSON codepoint escapes hid a prohibited socket path")
    continued_render = 'path: "/var/run/dock\\\n  er.sock"'
    if not scan_text("continued-render", continued_render):
        failures.append("YAML line continuation hid a prohibited socket path")
    encoded_privileged = r'"privile\u0067ed": true'
    if not scan_text("encoded-privileged", encoded_privileged):
        failures.append("escaped privileged key was not rejected")

    with tempfile.TemporaryDirectory(prefix="ferrum-chart-runtime-lint-") as tmp:
        good_root = Path(tmp) / "good"
        _required_tree(
            good_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        try:
            findings = check_repository(good_root)
        except Exception as exc:  # noqa: BLE001 - self-test must surface any failure
            failures.append(f"clean fixture unexpectedly raised: {exc}")
        else:
            if findings:
                failures.append(f"clean fixture unexpectedly failed: {findings}")

        comment_only = Path(tmp) / "comment-only"
        _required_tree(
            comment_only,
            node_agent=(
                _CLEAN_NODE_AGENT
                + "\n# Do not mount /var/run/docker.sock or containerd.sock\n"
            ),
            ambient=(
                _CLEAN_AMBIENT
                + "\n{{- /* privileged: true and /run/containerd are forbidden */ -}}\n"
            ),
            values=_CLEAN_VALUES,
        )
        try:
            findings = check_repository(comment_only)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"comment-only fixture unexpectedly raised: {exc}")
        else:
            if findings:
                failures.append(
                    f"comment-only documentation fixture false-positived: {findings}"
                )

        bad_cases: list[tuple[str, str, str, str]] = [
            (
                "docker.sock mount",
                _CLEAN_NODE_AGENT.replace(
                    "path: /sys/fs/bpf",
                    "path: /var/run/docker.sock",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "containerd host storage",
                _CLEAN_NODE_AGENT.replace(
                    "path: /sys/fs/cgroup",
                    "path: /var/lib/containerd",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "crio socket",
                _CLEAN_NODE_AGENT,
                _CLEAN_AMBIENT.replace(
                    "path: /run/spire/sockets",
                    "path: /var/run/crio/crio.sock",
                    1,
                ),
                _CLEAN_VALUES,
            ),
            (
                "runtime.sock spelling",
                _CLEAN_NODE_AGENT.replace(
                    "mountPath: /sys/fs/bpf",
                    "mountPath: /var/run/runtime.sock",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "privileged true",
                _CLEAN_NODE_AGENT.replace("privileged: false", "privileged: true", 1),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "dynamic privileged value",
                _CLEAN_NODE_AGENT.replace(
                    "privileged: false",
                    "privileged: {{ .Values.nodeAgent.security.privileged }}",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "inline privileged true",
                _CLEAN_NODE_AGENT.replace(
                    "securityContext:\n            privileged: false",
                    'securityContext: {"privileged": true}',
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "values docker socket path",
                _CLEAN_NODE_AGENT,
                _CLEAN_AMBIENT,
                _CLEAN_VALUES + "\n  extraHostPath: /var/run/docker.sock\n",
            ),
        ]
        for label, node_agent, ambient, values in bad_cases:
            bad_root = Path(tmp) / label.replace(" ", "-")
            _required_tree(
                bad_root,
                node_agent=node_agent,
                ambient=ambient,
                values=values,
            )
            try:
                findings = check_repository(bad_root)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{label}: prohibited fixture raised: {exc}")
                continue
            if not findings:
                failures.append(f"{label}: prohibited fixture was not rejected")

        renamed_surface_root = Path(tmp) / "additional-template"
        _required_tree(
            renamed_surface_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        _write(
            renamed_surface_root
            / "charts/ferrum-gateway/templates/runtime-access-daemonset.yaml",
            """\
apiVersion: apps/v1
kind: DaemonSet
spec:
  template:
    spec:
      volumes:
        - name: runtime
          hostPath:
            path: /run/containerd/containerd.sock
""",
        )
        try:
            findings = check_repository(renamed_surface_root)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"additional template fixture raised: {exc}")
        else:
            if not findings:
                failures.append(
                    "additional/renamed chart template was not governed"
                )

        symlink_root = Path(tmp) / "symlink"
        _required_tree(
            symlink_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        symlink_target = symlink_root / "clean-ambient.yaml"
        _write(symlink_target, _CLEAN_AMBIENT)
        governed_symlink = symlink_root / REQUIRED_RELATIVE_PATHS[1]
        governed_symlink.unlink()
        try:
            governed_symlink.symlink_to(symlink_target)
        except (NotImplementedError, OSError):
            # Some non-Linux developer environments do not permit symlinks.
            pass
        else:
            try:
                check_repository(symlink_root)
            except (FileNotFoundError, OSError):
                pass
            else:
                failures.append("symlinked governed chart surface was accepted")

        missing_root = Path(tmp) / "missing"
        _write(missing_root / REQUIRED_RELATIVE_PATHS[0], _CLEAN_NODE_AGENT)
        # ambient + values deliberately absent
        try:
            check_repository(missing_root)
        except FileNotFoundError:
            pass
        else:
            failures.append("missing required chart surfaces did not fail closed")

        unreadable_root = Path(tmp) / "unreadable"
        _required_tree(
            unreadable_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        target = unreadable_root / REQUIRED_RELATIVE_PATHS[0]
        target.chmod(0)
        try:
            try:
                check_repository(unreadable_root)
            except OSError:
                pass
            else:
                # Some environments (e.g. root) may still read mode 0 files.
                if target.read_text(encoding="utf-8") == _CLEAN_NODE_AGENT:
                    pass  # cannot simulate unreadable; skip assertion
                else:
                    failures.append("unreadable chart surface did not fail closed")
        finally:
            target.chmod(0o644)

        example_root = Path(tmp) / "examples-discovery"
        _required_tree(
            example_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        _write(
            example_root / "charts/ferrum-mesh/examples/nested/dev-values.yaml",
            "nodeAgent:\n  enabled: true\n",
        )
        _write(
            example_root / "charts/ferrum-mesh/examples/nested/prod-values.yml",
            "ambient:\n  enabled: true\n",
        )
        _write(
            example_root / "charts/ferrum-mesh/examples/nested/extra-values.json",
            '{"nodeAgent":{"enabled":true}}\n',
        )
        try:
            discovered = {
                path.relative_to(
                    (example_root / "charts/ferrum-mesh").resolve()
                ).as_posix()
                for path in iter_chart_example_value_files(example_root, "ferrum-mesh")
            }
        except Exception as exc:  # noqa: BLE001
            failures.append(f"example discovery raised: {exc}")
        else:
            expected = {
                "examples/nested/dev-values.yaml",
                "examples/nested/prod-values.yml",
                "examples/nested/extra-values.json",
            }
            if discovered != expected:
                failures.append(
                    "example discovery missed nested yaml/yml/json inputs: "
                    f"{sorted(discovered)}"
                )

        # Symlink rejection happens before discovery can report anything, so
        # each negative fixture gets its OWN root. Planting the symlink inside
        # `example_root` made every later positive render against that tree
        # abort on the symlink instead of exercising the render path.
        outside_examples = Path(tmp) / "outside-examples"
        _write(outside_examples / "escape-values.yaml", "nodeAgent:\n  enabled: true\n")

        symlink_dir_root = Path(tmp) / "examples-symlinked-directory"
        _required_tree(
            symlink_dir_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        _write(
            symlink_dir_root / "charts/ferrum-mesh/examples/dev-values.yaml",
            "nodeAgent:\n  enabled: true\n",
        )
        example_symlink = (
            symlink_dir_root / "charts/ferrum-mesh/examples/symlinked-directory"
        )
        try:
            example_symlink.symlink_to(outside_examples, target_is_directory=True)
        except (NotImplementedError, OSError):
            # Some non-Linux developer environments do not permit symlinks.
            pass
        else:
            try:
                iter_chart_example_value_files(symlink_dir_root, "ferrum-mesh")
            except OSError:
                pass
            else:
                failures.append("symlinked chart example directory was accepted")

        symlink_file_root = Path(tmp) / "examples-symlinked-file"
        _required_tree(
            symlink_file_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        symlinked_values = (
            symlink_file_root / "charts/ferrum-mesh/examples/escape-values.yaml"
        )
        symlinked_values.parent.mkdir(parents=True, exist_ok=True)
        try:
            symlinked_values.symlink_to(outside_examples / "escape-values.yaml")
        except (NotImplementedError, OSError):
            pass
        else:
            try:
                iter_chart_example_value_files(symlink_file_root, "ferrum-mesh")
            except OSError:
                pass
            else:
                failures.append("symlinked chart example values file was accepted")
            try:
                check_repository(symlink_file_root)
            except OSError:
                pass
            else:
                failures.append(
                    "symlinked chart example values file passed the source scan"
                )

        render_root = Path(tmp) / "render-failures"
        _required_tree(
            render_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        bin_dir = Path(tmp) / "fake-helm-bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        missing_helm = bin_dir / "missing"
        missing_helm.mkdir(parents=True, exist_ok=True)
        original_path = os.environ.get("PATH", "")
        original_trusted = os.environ.pop(TRUSTED_HELM_ENV, None)
        try:
            os.environ["PATH"] = str(missing_helm)
            try:
                check_repository(render_root, render=True)
            except FileNotFoundError:
                pass
            else:
                failures.append("missing helm binary did not fail closed")
        finally:
            os.environ["PATH"] = original_path
            if original_trusted is not None:
                os.environ[TRUSTED_HELM_ENV] = original_trusted

        nonzero_helm = bin_dir / "nonzero-helm"
        _write(
            nonzero_helm,
            "#!/bin/sh\n"
            "echo 'synthetic helm failure detail' >&2\n"
            "exit 7\n",
        )
        nonzero_helm.chmod(0o755)
        try:
            check_repository(render_root, render=True, helm_bin=str(nonzero_helm))
        except OSError as exc:
            if "helm render" not in str(exc) or "failed" not in str(exc):
                failures.append(f"nonzero helm render error malformed: {exc}")
        else:
            failures.append("nonzero helm render did not fail closed")

        timeout_helm = bin_dir / "timeout-helm"
        _write(timeout_helm, "#!/bin/sh\nwhile true; do sleep 1; done\n")
        timeout_helm.chmod(0o755)
        try:
            check_repository(
                render_root,
                render=True,
                helm_bin=str(timeout_helm),
                timeout_seconds=0.05,
            )
        except OSError as exc:
            if "timed out" not in str(exc):
                failures.append(f"helm timeout error malformed: {exc}")
        else:
            failures.append("helm render timeout did not fail closed")

        recording_helm = bin_dir / "recording-helm"
        record_path = Path(tmp) / "helm-args.txt"
        _write(
            recording_helm,
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{record_path}"\n'
            "cat <<'EOF'\n"
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n"
            "EOF\n",
        )
        recording_helm.chmod(0o755)
        try:
            findings = check_repository(
                example_root, render=True, helm_bin=str(recording_helm)
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"recording helm render raised: {exc}")
        else:
            if findings:
                failures.append(
                    f"clean example render unexpectedly failed: {findings}"
                )
            recorded = (
                record_path.read_text(encoding="utf-8") if record_path.is_file() else ""
            )
            for needle in (
                "nested/dev-values.yaml",
                "nested/prod-values.yml",
                "nested/extra-values.json",
                "nodeAgent.enabled=true",
                "ambient.enabled=true",
            ):
                if needle not in recorded:
                    failures.append(
                        f"recording helm did not receive expected render input "
                        f"({needle})"
                    )
            # defaults + node-agent/ambient + 3 nested examples
            if recorded.count("template ferrum-runtime-lint") < 5:
                failures.append(
                    "recording helm did not observe default, ambient, and "
                    f"example renders: {recorded.count('template ferrum-runtime-lint')}"
                )

        hostile_render_helm = bin_dir / "hostile-render-helm"
        _write(
            hostile_render_helm,
            "#!/bin/sh\n"
            "cat <<'EOF'\n"
            "apiVersion: apps/v1\n"
            "kind: DaemonSet\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - securityContext:\n"
            "            privileged: true\n"
            "      volumes:\n"
            "        - hostPath:\n"
            "            path: /var/run/docker.sock\n"
            "EOF\n",
        )
        hostile_render_helm.chmod(0o755)
        try:
            findings = check_repository(
                render_root, render=True, helm_bin=str(hostile_render_helm)
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"hostile render fixture raised: {exc}")
        else:
            if not any("privileged" in finding for finding in findings):
                failures.append(
                    "hostile rendered privileged: true was not rejected"
                )
            if not any("docker.sock" in finding for finding in findings):
                failures.append(
                    "hostile rendered docker.sock mount was not rejected"
                )

        # GHSA-4xcp-8c2m-g84j: the rendered pass covers every chart. A
        # gateway-chart template that builds a runtime socket path with
        # `printf` passes the source scan and must be caught once rendered;
        # the chart's values examples are rendered and its plain manifest
        # examples (refused by its closed values schema) are not.
        gateway_root = Path(tmp) / "gateway-render"
        _required_tree(
            gateway_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        gateway_chart = gateway_root / "charts/ferrum-gateway"
        _write(
            gateway_chart / "templates/runtime-access.yaml",
            "apiVersion: apps/v1\n"
            "kind: DaemonSet\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      volumes:\n"
            "        - hostPath:\n"
            '            path: {{ printf "/%s/%s/%s.%s" "var" "run" "docker" "sock" }}\n',
        )
        _write(
            gateway_chart / "values.schema.json",
            '{"type": "object", "additionalProperties": false, '
            '"properties": {"mode": {"type": "string"}}}\n',
        )
        _write(gateway_chart / "values.yaml", "mode: file\n")
        _write(gateway_chart / "examples/file-values.yaml", "mode: file\n")
        _write(
            gateway_chart / "examples/migrate-job.yaml",
            "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: migrate\n",
        )
        try:
            source_only = check_repository(gateway_root)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"gateway source-scan fixture raised: {exc}")
        else:
            if source_only:
                failures.append(
                    "constructed gateway socket path unexpectedly matched the "
                    f"source scan: {source_only}"
                )
        gateway_record = Path(tmp) / "gateway-helm-args.txt"
        gateway_helm = bin_dir / "gateway-render-helm"
        _write(
            gateway_helm,
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{gateway_record}"\n'
            'case "$*" in\n'
            "  *charts/ferrum-gateway*)\n"
            "    printf 'kind: DaemonSet\\nspec:\\n  path: /var/run/docker.sock\\n'\n"
            "    ;;\n"
            "  *)\n"
            "    printf 'kind: ConfigMap\\nmetadata:\\n  name: ok\\n'\n"
            "    ;;\n"
            "esac\n",
        )
        gateway_helm.chmod(0o755)
        try:
            findings = check_repository(
                gateway_root, render=True, helm_bin=str(gateway_helm)
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"gateway render fixture raised: {exc}")
        else:
            if not any(
                finding.startswith("helm-render:ferrum-gateway:")
                and "docker.sock" in finding
                for finding in findings
            ):
                failures.append(
                    "a printf-built socket path in a ferrum-gateway template "
                    "was not rejected by the rendered pass"
                )
            recorded = (
                gateway_record.read_text(encoding="utf-8")
                if gateway_record.is_file()
                else ""
            )
            if "examples/file-values.yaml" not in recorded:
                failures.append("gateway example values were not rendered")
            if "migrate-job.yaml" in recorded:
                failures.append(
                    "a gateway manifest example refused by the closed values "
                    "schema was rendered as values"
                )
            if "charts/ferrum-mesh" not in recorded:
                failures.append("the mesh chart dropped out of the rendered pass")

        oversized = "x" * (MAX_HELM_ERROR_CHARS + 50)
        bounded = _bound_helm_detail(oversized)
        if "truncated" not in bounded or len(bounded) > MAX_HELM_ERROR_CHARS + 20:
            failures.append("helm error detail was not bounded")

    # The live repository tree must also pass (guards regressing main).
    try:
        live_findings = check_repository(default_repo_root())
    except Exception as exc:  # noqa: BLE001
        failures.append(f"repository chart scan raised: {exc}")
    else:
        if live_findings:
            failures.append(f"repository chart scan failed: {live_findings}")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject prohibited container-runtime mounts and privileged: true "
            "in Ferrum node-agent/ambient chart surfaces"
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root to scan (default: ferrum-edge checkout root)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run synthetic fixtures and scan the live chart tree",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        failures = run_self_test()
        for failure in failures:
            print(f"::error::self-test: {failure}", file=sys.stderr)
        if failures:
            return 1
        print(
            "node-agent/ambient chart runtime lint self-test passed "
            "(recursive chart sources and rendered-expression regression)"
        )
        return 0

    try:
        findings = check_repository(args.root, render=True)
    except (OSError, ValueError, NotADirectoryError, FileNotFoundError) as exc:
        print(f"::error::chart runtime lint failed closed: {exc}", file=sys.stderr)
        return 1

    for finding in findings:
        print(f"::error::{finding}", file=sys.stderr)
    if findings:
        return 1
    print(
        "node-agent/ambient chart runtime lint passed "
        "(recursive chart sources plus Helm-rendered manifests)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
