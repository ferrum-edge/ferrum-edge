#!/usr/bin/env python3
"""Select full or lightweight CI for a pull request's changed files."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath

from live_suite_path_filter import matched_files, self_test as live_suite_self_test


# This planner is copied from the trusted base branch before CI executes it.
# Keeping the action/tool policy here means a pull request cannot weaken the
# scanner it is evaluated by, and avoids adding a new executable surface to the
# Cross-protected CI workflow.
ACTION_SHA40 = re.compile(r"^[0-9a-f]{40}$")
ACTION_DOCKER_SHA256 = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
ACTION_DOCKER_FROM_SHA256 = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
ACTION_USES_VALUE = (
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|\$\{\{[^\r\n]*\}\}|[^\s,#}]+)'
)
ACTION_USES_KEY = r'(?:uses|"uses"|\'uses\')'
ACTION_USES_BLOCK = re.compile(
    rf"^\s*(?:-\s*)?(?P<key>{ACTION_USES_KEY})\s*:\s*"
    rf"(?P<ref>{ACTION_USES_VALUE})\s*(?:#.*)?$",
    re.MULTILINE,
)
ACTION_USES_FLOW = re.compile(
    rf"(?:^|[{{,])\s*(?P<key>{ACTION_USES_KEY})\s*:\s*"
    rf"(?P<ref>{ACTION_USES_VALUE})"
    r"(?=\s*(?:[,}]|#|$))",
    re.MULTILINE,
)
ACTION_USES_DECLARATION = re.compile(
    rf"(?:^|[{{,])\s*(?:-\s*)?(?P<key>{ACTION_USES_KEY})\s*:",
    re.MULTILINE,
)
ACTION_FOLDED_RUN = re.compile(
    r"^(?P<indent> *)(?:-\s*)?(?:run|\"run\"|'run')\s*:\s*>[+-]?\s*(?:#.*)?$"
)
ACTION_DOCKER_FROM = re.compile(
    r"^\s*FROM(?:\s+--platform=\S+)?\s+(?P<image>\S+)",
    re.IGNORECASE | re.MULTILINE,
)
ACTION_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b",
    re.IGNORECASE,
)
ACTION_MUTABLE_HELM_INSTALL = re.compile(
    r"raw\.githubusercontent\.com/helm/helm/"
    r"(?:refs/heads/)?[^/\s]+/[^\s]*(?:get-helm-3|install[^\s]*)|"
    r"https://raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/"
    r"(?:refs/heads/)?(?:main|master)/[^\s]*install|"
    r"get\.helm\.sh/helm-install",
    re.IGNORECASE,
)
ACTION_DIRECT_K8S_TOOL_DOWNLOAD = re.compile(
    r"(?:kind\.sigs\.k8s\.io/dl/|"
    r"github\.com/kubernetes-sigs/kind/releases/download/|"
    r"dl\.k8s\.io/release/.*/kubectl|"
    r"cdn\.dl\.k8s\.io/release/.*/kubectl|"
    r"storage\.googleapis\.com/kubernetes-release/release/.*/kubectl|"
    r"go\s+install\s+sigs\.k8s\.io/kind@|"
    r"get\.helm\.sh/helm-)",
    re.IGNORECASE,
)
ACTION_DISALLOWED_HELM = re.compile(r"^azure/setup-helm(?:@|$)", re.IGNORECASE)


def normalize_action_uses_ref(raw: str) -> str:
    ref = raw.strip()
    if len(ref) >= 2 and ref[0] == ref[-1] and ref[0] in {"\"", "'"}:
        ref = ref[1:-1].strip()
    return ref


def action_pin_status(raw: str) -> tuple[bool, str]:
    """Validate one parsed `uses:` value without resolving untrusted paths."""
    ref = normalize_action_uses_ref(raw)
    if not ref:
        return False, "empty uses reference"
    if "${{" in ref:
        return False, f"dynamic or partially interpolated uses ref: {ref}"
    if ref.startswith("./"):
        # Local dependencies have no @ref syntax. Treat every character as path data
        # so an embedded `@../` cannot hide traversal from the parts check.
        local = ref
        if "\\" in local:
            return False, f"local dependency path must use forward slashes: {ref}"
        parts = PurePosixPath(local).parts
        local_action = (
            len(parts) >= 3 and tuple(parts[:2]) == (".github", "actions")
        )
        local_workflow = (
            len(parts) == 3
            and tuple(parts[:2]) == (".github", "workflows")
            and PurePosixPath(parts[-1]).suffix in {".yml", ".yaml"}
        )
        if ".." in parts or not (local_action or local_workflow):
            return False, f"local dependency outside approved GitHub paths: {ref}"
        if local_workflow:
            return True, "repository-local reusable workflow"
        return True, "repository-local action"
    if ref.startswith(("../", "/")):
        return False, f"local dependency outside approved GitHub paths: {ref}"
    if ref.startswith("docker://"):
        if not ACTION_DOCKER_SHA256.fullmatch(ref):
            return False, f"mutable Docker uses ref (require @sha256 digest): {ref}"
        return True, "digest-pinned Docker image"
    if "@" not in ref:
        return False, f"missing action pin (@ref): {ref}"
    name, pin = ref.rsplit("@", 1)
    if not name:
        return False, f"missing action name: {ref}"
    if ACTION_DISALLOWED_HELM.match(name):
        return (
            False,
            "azure/setup-helm is disallowed; use "
            "./.github/actions/setup-kubernetes-tools",
        )
    if not ACTION_SHA40.fullmatch(pin):
        return False, f"mutable action ref (not a 40-char SHA): {ref}"
    return True, "sha-pinned"


def find_action_uses_refs(text: str) -> list[tuple[int, str]]:
    """Extract block and flow-style `uses:` values, including spaced expressions."""
    refs: list[tuple[int, str]] = []
    seen: set[tuple[int, int]] = set()
    for pattern in (ACTION_USES_BLOCK, ACTION_USES_FLOW):
        for match in pattern.finditer(text):
            span = match.span("ref")
            if span in seen:
                continue
            seen.add(span)
            line_no = text.count("\n", 0, match.start("ref")) + 1
            refs.append((line_no, normalize_action_uses_ref(match.group("ref"))))
    return sorted(refs)


def find_unparsed_action_uses_lines(text: str) -> list[int]:
    """Fail closed when a `uses:` declaration is not parsed by an approved shape."""
    parsed_keys: set[tuple[int, int]] = set()
    for pattern in (ACTION_USES_BLOCK, ACTION_USES_FLOW):
        parsed_keys.update(match.span("key") for match in pattern.finditer(text))
    return [
        text.count("\n", 0, match.start("key")) + 1
        for match in ACTION_USES_DECLARATION.finditer(text)
        if match.span("key") not in parsed_keys
    ]


def folded_run_views(text: str) -> list[tuple[int, str]]:
    """Return folded YAML `run: >` bodies as the shell text they approximate."""
    lines = text.splitlines()
    views: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = ACTION_FOLDED_RUN.match(lines[index])
        if match is None:
            index += 1
            continue
        parent_indent = len(match.group("indent"))
        body: list[str] = []
        cursor = index + 1
        while cursor < len(lines):
            line = lines[cursor]
            if not line.strip():
                body.append("")
                cursor += 1
                continue
            indentation = len(line) - len(line.lstrip(" "))
            if indentation <= parent_indent:
                break
            body.append(line.strip())
            cursor += 1
        views.append((index + 1, " ".join(body)))
        index = cursor
    return views


def action_policy_yaml_files(repo_root: Path) -> tuple[list[Path], list[str]]:
    workflows = repo_root / ".github" / "workflows"
    actions = repo_root / ".github" / "actions"
    failures: list[str] = []
    if not workflows.is_dir():
        failures.append("missing .github/workflows directory")
    if not actions.is_dir():
        failures.append("missing .github/actions directory")
    files = [*workflows.glob("*.yml"), *workflows.glob("*.yaml")]
    # Local actions may be nested more than one directory below
    # `.github/actions`; scan every manifest so nesting cannot bypass policy.
    files.extend(actions.rglob("action.yml"))
    files.extend(actions.rglob("action.yaml"))
    # A local Docker action is only as immutable as every base image in its
    # Dockerfile. Scan conventional and suffixed Dockerfile names recursively.
    files.extend(actions.rglob("Dockerfile"))
    files.extend(actions.rglob("Dockerfile.*"))
    for scan_root in (workflows, actions):
        if not scan_root.is_dir():
            continue
        for path in scan_root.rglob("*"):
            if path.is_symlink():
                failures.append(
                    f"{action_policy_relative_path(path, repo_root)}: "
                    "workflow/action policy paths must not be symlinks"
                )
    if not files:
        failures.append("no workflow or composite-action YAML found")
    return sorted(set(files)), failures


def action_policy_relative_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def scan_action_policy_text(
    text: str,
    rel: str,
    *,
    allow_direct_downloads: bool,
) -> list[str]:
    failures: list[str] = []
    for line_no in find_unparsed_action_uses_lines(text):
        failures.append(
            f"{rel}:{line_no}: uses declaration has an unsupported or "
            "unparseable value"
        )
    for line_no, ref in find_action_uses_refs(text):
        ok, reason = action_pin_status(ref)
        if not ok:
            failures.append(f"{rel}:{line_no}: {reason}")

    pipe_found = False
    mutable_helm_found = False
    direct_download_found = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ACTION_PIPE_TO_SHELL.search(line):
            pipe_found = True
            failures.append(
                f"{rel}:{line_no}: pipe-to-shell installer is forbidden"
            )
        if ACTION_MUTABLE_HELM_INSTALL.search(line):
            mutable_helm_found = True
            failures.append(
                f"{rel}:{line_no}: mutable-branch Helm installer is forbidden"
            )
        if not allow_direct_downloads and ACTION_DIRECT_K8S_TOOL_DOWNLOAD.search(line):
            direct_download_found = True
            failures.append(
                f"{rel}:{line_no}: direct kind/kubectl/Helm download must use "
                "./.github/actions/setup-kubernetes-tools"
            )

    # Explicit shell continuations can split a forbidden URL or `| bash`
    # across physical YAML lines. Collapse those continuations after dropping
    # comment-only lines, then add a file-level finding if the line scan did not
    # already locate the same category.
    non_comment_text = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    continued = re.sub(r"\\\r?\n[ \t]*", "", non_comment_text)
    if not pipe_found and ACTION_PIPE_TO_SHELL.search(continued):
        failures.append(f"{rel}: continued pipe-to-shell installer is forbidden")
    if not mutable_helm_found and ACTION_MUTABLE_HELM_INSTALL.search(continued):
        failures.append(f"{rel}: continued mutable-branch Helm installer is forbidden")
    if (
        not allow_direct_downloads
        and not direct_download_found
        and ACTION_DIRECT_K8S_TOOL_DOWNLOAD.search(continued)
    ):
        failures.append(
            f"{rel}: continued direct kind/kubectl/Helm download must use "
            "./.github/actions/setup-kubernetes-tools"
        )
    for line_no, folded in folded_run_views(text):
        if not pipe_found and ACTION_PIPE_TO_SHELL.search(folded):
            pipe_found = True
            failures.append(
                f"{rel}:{line_no}: folded pipe-to-shell installer is forbidden"
            )
        if not mutable_helm_found and ACTION_MUTABLE_HELM_INSTALL.search(folded):
            mutable_helm_found = True
            failures.append(
                f"{rel}:{line_no}: folded raw Helm installer is forbidden"
            )
        if (
            not allow_direct_downloads
            and not direct_download_found
            and ACTION_DIRECT_K8S_TOOL_DOWNLOAD.search(folded)
        ):
            direct_download_found = True
            failures.append(
                f"{rel}:{line_no}: folded direct kind/kubectl/Helm download "
                "must use ./.github/actions/setup-kubernetes-tools"
            )
    return failures


def scan_action_dockerfile(text: str, rel: str) -> list[str]:
    failures: list[str] = []
    for match in ACTION_DOCKER_FROM.finditer(text):
        image = match.group("image")
        if image.lower() == "scratch" or ACTION_DOCKER_FROM_SHA256.fullmatch(image):
            continue
        line_no = text.count("\n", 0, match.start("image")) + 1
        failures.append(
            f"{rel}:{line_no}: local-action Docker FROM must use @sha256: {image}"
        )
    return failures


def scan_action_policy_file(path: Path, repo_root: Path) -> list[str]:
    rel = action_policy_relative_path(path, repo_root)
    if path.is_symlink():
        return [f"{rel}: workflow/action YAML must not be a symlink"]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"{rel}: failed to read UTF-8 policy input: {exc}"]
    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        return scan_action_dockerfile(text, rel)
    return scan_action_policy_text(
        text,
        rel,
        allow_direct_downloads=(
            rel == ".github/actions/setup-kubernetes-tools/action.yml"
        ),
    )


def validate_action_pinning_policy(repo_root: Path) -> list[str]:
    root = repo_root.resolve()
    files, failures = action_policy_yaml_files(root)
    setup = root / ".github" / "actions" / "setup-kubernetes-tools" / "action.yml"
    if not setup.is_file() or setup.is_symlink():
        failures.append(
            "missing regular centralized installer: "
            ".github/actions/setup-kubernetes-tools/action.yml"
        )
    for path in files:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            failures.append(
                f"{action_policy_relative_path(path, root)}: path escapes repository"
            )
            continue
        failures.extend(scan_action_policy_file(path, root))
    return failures


def action_pinning_self_test() -> list[str]:
    failures: list[str] = []

    def expect_ok(ref: str) -> None:
        ok, reason = action_pin_status(ref)
        if not ok:
            failures.append(f"expected {ref!r} to pass: {reason}")

    def expect_bad(ref: str, needle: str) -> None:
        ok, reason = action_pin_status(ref)
        if ok or needle not in reason:
            failures.append(
                f"expected {ref!r} to fail with {needle!r}, got {reason!r}"
            )

    sha = "a" * 40
    digest = "b" * 64
    expect_ok(f"actions/checkout@{sha}")
    expect_ok("./.github/actions/setup-kubernetes-tools")
    expect_ok("./.github/workflows/reusable.yml")
    expect_ok(f"docker://registry.example/image@sha256:{digest}")
    expect_bad("${{ matrix.action }}", "dynamic or partially interpolated")
    expect_bad("actions/checkout@v7", "mutable action ref")
    expect_bad("actions/checkout@abcd123", "mutable action ref")
    expect_bad("actions/checkout", "missing action pin")
    expect_bad("./actions/evil", "outside approved GitHub paths")
    expect_bad("../.github/actions/evil", "outside approved GitHub paths")
    expect_bad("./.github/actions/../evil", "outside approved GitHub paths")
    expect_bad("./.github/actions/good@../../evil", "outside approved GitHub paths")
    expect_bad("./.github/actions-evil/tool", "outside approved GitHub paths")
    expect_bad("./.github/workflows/nested/reusable.yml", "outside approved GitHub paths")
    expect_bad("docker://alpine:latest", "mutable Docker uses ref")
    expect_bad("owner/action@${{ env.REF }}", "dynamic or partially interpolated")
    expect_bad("${{ env.ACTION }}", "dynamic or partially interpolated")
    expect_bad(f"azure/setup-helm@{sha}", "azure/setup-helm is disallowed")
    expect_bad(f"AZURE/setup-helm@{sha}", "azure/setup-helm is disallowed")

    sample = (
        "steps:\n"
        f"  - uses: actions/checkout@{sha} # pinned\n"
        "  - uses: '${{ matrix.action }}'\n"
        f"  - {{uses: owner/action@{sha}, name: inline}}\n"
        f"  - \"uses\": owner/quoted-block@{sha}\n"
        f"  - {{'uses': owner/quoted-flow@{sha}, name: quoted}}\n"
        "  # uses: owner/action@v7\n"
    )
    found = find_action_uses_refs(sample)
    expected = [
        f"actions/checkout@{sha}",
        "${{ matrix.action }}",
        f"owner/action@{sha}",
        f"owner/quoted-block@{sha}",
        f"owner/quoted-flow@{sha}",
    ]
    if [ref for _, ref in found] != expected:
        failures.append(f"uses parser mismatch: {found!r}")
    unparsed = find_unparsed_action_uses_lines(
        "steps:\n  - uses: &mutable actions/checkout@v7\n"
        "  - uses: !!str actions/checkout@v7\n"
    )
    if unparsed != [2, 3]:
        failures.append(f"unparsed uses declarations were not rejected: {unparsed!r}")
    continued_bad = (
        "steps:\n"
        "  - run: curl -fsSL https://kind.sigs.k8s.io/dl/\\\n"
        "      v0.27.0/kind-linux-amd64 \\\n"
        "      | bash\n"
    )
    continued_failures = scan_action_policy_text(
        continued_bad,
        "synthetic.yml",
        allow_direct_downloads=False,
    )
    if not any("pipe-to-shell" in failure for failure in continued_failures):
        failures.append("continued pipe-to-shell self-test was not rejected")
    if not any("direct kind" in failure for failure in continued_failures):
        failures.append("continued direct-download self-test was not rejected")
    folded_bad = (
        "steps:\n"
        "  - run: >-\n"
        "      curl -fsSL https://example.invalid/install.sh\n"
        "      | bash\n"
    )
    folded_failures = scan_action_policy_text(
        folded_bad,
        "synthetic-folded.yml",
        allow_direct_downloads=False,
    )
    if not any("folded pipe-to-shell" in failure for failure in folded_failures):
        failures.append("folded pipe-to-shell self-test was not rejected")
    alternate_downloads = (
        "run: |\n"
        "  curl https://storage.googleapis.com/kubernetes-release/release/v1.32.3/bin/linux/amd64/kubectl\n"
        "  curl https://cdn.dl.k8s.io/release/v1.32.3/bin/linux/amd64/kubectl\n"
        "  go install sigs.k8s.io/kind@v0.27.0\n"
        "  curl https://raw.githubusercontent.com/helm/helm/refs/heads/devel/scripts/get-helm-3\n"
        "  curl -fsSL https://get.helm.sh/helm-install -o /tmp/helm-install\n"
    )
    alternate_failures = scan_action_policy_text(
        alternate_downloads,
        "synthetic-downloads.yml",
        allow_direct_downloads=False,
    )
    if len(alternate_failures) < 4:
        failures.append(
            "alternate Kubernetes/Helm download self-test was not fully rejected: "
            f"{alternate_failures!r}"
        )
    helm_install_failures = scan_action_policy_text(
        "run: curl -fsSL https://get.helm.sh/helm-install -o /tmp/helm-install\n",
        ".github/actions/setup-kubernetes-tools/action.yml",
        allow_direct_downloads=True,
    )
    if not any("mutable-branch Helm installer" in failure for failure in helm_install_failures):
        failures.append(
            "get.helm.sh/helm-install self-test was not rejected in setup action: "
            f"{helm_install_failures!r}"
        )
    dockerfile_failures = scan_action_dockerfile(
        f"FROM alpine@sha256:{digest} AS pinned\nFROM scratch\nFROM ubuntu:latest\n",
        ".github/actions/example/Dockerfile",
    )
    if len(dockerfile_failures) != 1 or "ubuntu:latest" not in dockerfile_failures[0]:
        failures.append(
            f"local-action Docker pin self-test mismatch: {dockerfile_failures!r}"
        )
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        (root / ".github" / "workflows").mkdir(parents=True)
        nested = root / ".github" / "actions" / "nested" / "deeper"
        nested.mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(
            "jobs: {}\n", encoding="utf-8"
        )
        nested_manifest = nested / "action.yml"
        nested_manifest.write_text("runs: {using: composite, steps: []}\n", encoding="utf-8")
        nested_dockerfile = nested / "Dockerfile"
        nested_dockerfile.write_text(
            f"FROM alpine@sha256:{digest}\n", encoding="utf-8"
        )
        discovered, discovery_failures = action_policy_yaml_files(root)
        if discovery_failures:
            failures.append(
                f"nested action discovery unexpectedly failed: {discovery_failures!r}"
            )
        if nested_manifest not in discovered:
            failures.append("nested composite-action manifest was not scanned")
        if nested_dockerfile not in discovered:
            failures.append("nested local-action Dockerfile was not scanned")
    return failures


# These files cannot affect the Rust workspace, build/release inputs, runtime
# configuration, test harnesses, or GitHub Actions. Keep this allow-list narrow:
# an unrecognized path intentionally fails over to the full CI matrix.
LIGHTWEIGHT_PATTERNS = [
    re.compile(r"^\.agents/"),
    re.compile(r"^\.claude/"),
    re.compile(r"^docs/"),
    re.compile(r"(^|/)[^/]+\.md$"),
    re.compile(r"^LICENSE(?:-[^/]+)?$"),
]

# Markdown under vendor/ participates in VENDOR_INTEGRITY.sha256 and must run
# the vendored-patch and integration guards even when a manifest update was
# accidentally omitted.
FULL_CI_PREFIXES = ("vendor/",)

# These files deliberately trigger one or more live datapath suites. The
# required-CI verifier mechanically checks this set against both
# live_suite_path_filter.py and node-waypoint-ebpf-live.yml.
FULL_CI_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/ci_cd.md",
        "docs/configuration.md",
        "docs/mesh.md",
        "docs/mesh_multicluster_federation_runbook.md",
        "docs/mesh_supported_matrix.md",
        "docs/node_agent.md",
        "docs/plans/node_waypoint_transport_adr.md",
        "docs/spire_deployment.md",
    }
)

# Pull-request-only job gates. Keep these allow-lists narrow: a path must be
# known to affect the expensive suite before the planner schedules it. An
# unavailable/empty diff fails closed in select_job_gates() and schedules all
# gated jobs.
HELM_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"^charts/",
        r"^\.github/workflows/ci\.yml$",
        r"^\.github/actions/",
        r"^\.cargo/",
        r"^vendor/",
        r"^Dockerfile(?:\..*)?$",
        r"^\.dockerignore$",
        r"^Cargo\.(?:toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^build\.rs$",
        r"^proto/",
        r"^ferrum\.conf$",
        r"^src/lib\.rs$",
        r"^src/overload\.rs$",
        r"^src/runtime_metrics\.rs$",
        r"^src/(?:main|startup|cli)\.rs$",
        r"^src/config/",
        r"^src/config_sources/k8s/",
        r"^src/logging/",
        r"^src/modes/(?:control_plane|database|migrate|mod|tls_reload|grpc_tls_reload|db_tls_reload)\.rs$",
        r"^src/modes/mesh/",
        r"^src/admin/",
        r"^src/dns/",
        r"^src/grpc/",
        r"^src/identity/",
        r"^src/k8s_controller/",
        r"^src/proxy/client_ip\.rs$",
        r"^src/secrets/",
        r"^src/tls/",
        r"^src/util/sharding\.rs$",
        r"^src/xds/",
    )
]

EBPF_LIVE_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"^\.github/workflows/(?:ci|node-waypoint-ebpf-live)\.yml$",
        r"^\.github/actions/(?:setup-rust-ci|setup-sccache|setup-fast-linker|setup-kubernetes-tools|package-ferrum-runtime-image)/",
        r"^Cargo\.(?:toml|lock)$",
        r"^\.cargo/",
        r"^rust-toolchain\.toml$",
        r"^build\.rs$",
        r"^proto/",
        r"^ebpf/",
        r"^src/capture/",
        r"^src/ebpf/",
        r"^src/grpc/",
        r"^src/identity/",
        r"^src/k8s_controller/",
        r"^src/modes/control_plane\.rs$",
        r"^src/modes/mesh/",
        r"^src/modes/(?:node_agent|node_agent_cni_server)\.rs$",
        r"^src/plugins/mesh/",
        r"^src/plugins/prometheus_metrics\.rs$",
        r"^src/proxy/(?:backend_dispatch|grpc_proxy|hbone_pool|hbone_proxy|mesh_mtls_pool|mesh_tcp_egress|mesh_tcp_inbound|mesh_udp_capture|mesh_udp_frame|mod|netns_capture|netns_udp_capture|tcp_proxy|udp_batch)\.rs$",
        r"^src/(?:router_cache|socket_opts)\.rs$",
        r"^src/service_discovery/",
        r"^src/tls/",
        r"^tests/functional/functional_mesh_mode_test\.rs$",
        r"^tests/functional/fixtures/",
        r"^tests/k8s/lib/",
        r"^tests/k8s/node_waypoint_ebpf_live/",
        r"^tests/.*(?:capture|ebpf|netns|node_waypoint).*",
    )
]

JOB_GATE_NAMES = (
    "run_helm",
    "run_mesh_federation",
    "run_mesh_sidecar_smoke",
    "run_ebpf_live",
    "run_ebpf_build",
)

# Scripts whose logic controls the gate decisions themselves. Changing either
# force-runs every gated suite (see select_job_gates).
GATE_CONTROLLER_PATHS = frozenset(
    {
        ".github/scripts/pr_ci_plan.py",
        ".github/scripts/live_suite_path_filter.py",
    }
)


def is_lightweight_path(path: str) -> bool:
    if path.startswith(FULL_CI_PREFIXES) or path in FULL_CI_DOCUMENTATION_PATHS:
        return False
    return any(pattern.search(path) for pattern in LIGHTWEIGHT_PATTERNS)


def select_mode(event_name: str, changed_files: list[str]) -> tuple[str, str]:
    if event_name != "pull_request":
        return "full", f"full CI is required for {event_name}"

    # Fail closed when the diff cannot be established. An empty PR diff is
    # unusual, and running full validation is safer than silently skipping it.
    if not changed_files:
        return "full", "no changed files were detected; defaulting to full CI"

    full_ci_files = [path for path in changed_files if not is_lightweight_path(path)]
    if full_ci_files:
        return "full", f"full-CI input changed: {full_ci_files[0]}"

    return "light", "only documentation, license, or agent-instruction files changed"


def any_path_matches(patterns: list[re.Pattern[str]], changed_files: list[str]) -> bool:
    return any(pattern.search(path) for path in changed_files for pattern in patterns)


def select_job_gates(event_name: str, changed_files: list[str]) -> dict[str, bool]:
    if event_name != "pull_request" or not changed_files:
        return {name: True for name in JOB_GATE_NAMES}

    # These scripts decide which gated suites run. A PR that edits them is
    # evaluated by the TRUSTED base-branch copy (which cannot see its own
    # replacement's behavior), so force every gated suite on: a broken gate
    # change must prove the suites it controls still run before it can start
    # suppressing them on subsequent PRs.
    if any(path in GATE_CONTROLLER_PATHS for path in changed_files):
        return {name: True for name in JOB_GATE_NAMES}

    return {
        "run_helm": any_path_matches(HELM_PATTERNS, changed_files),
        "run_mesh_federation": bool(
            matched_files("mesh-federation", changed_files)
        ),
        "run_mesh_sidecar_smoke": bool(
            matched_files("mesh-e2e-sidecar", changed_files)
        ),
        "run_ebpf_live": any_path_matches(EBPF_LIVE_PATTERNS, changed_files),
        "run_ebpf_build": any(path.startswith("ebpf/") for path in changed_files),
    }


def read_changed_files(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def self_test() -> int:
    cases = [
        ("pull_request", ["docs/admin_api.md"], "light"),
        ("pull_request", ["README.md", "LICENSE-COMMERCIAL.md"], "light"),
        ("pull_request", [".agents/skills/opus-agents/scripts/dispatch-agent.sh"], "light"),
        ("pull_request", [".claude/rules/testing.md"], "light"),
        ("pull_request", ["docs/mesh.md"], "full"),
        ("pull_request", ["docs/configuration.md"], "full"),
        ("pull_request", ["docs/plans/node_waypoint_transport_adr.md"], "full"),
        (
            "pull_request",
            ["vendor/tungstenite-0.29.0-ferrum-patched/README.md"],
            "full",
        ),
        ("pull_request", ["src/proxy/legacy.rs", "notes.md"], "full"),
        ("pull_request", ["src/proxy/mod.rs"], "full"),
        ("pull_request", ["docs/admin_api.md", "Cargo.lock"], "full"),
        ("pull_request", [".github/workflows/ci.yml"], "full"),
        ("pull_request", ["tests/README.md", "tests/unit_tests.rs"], "full"),
        ("pull_request", [], "full"),
        ("push", ["docs/ci_cd.md"], "full"),
        ("workflow_dispatch", [], "full"),
    ]
    failures: list[str] = []
    for event_name, changed, expected in cases:
        mode, _ = select_mode(event_name, changed)
        if mode != expected:
            failures.append(
                f"{event_name} {changed!r}: expected {expected}, selected {mode}"
            )

    gate_cases = [
        (
            "pull_request",
            ["charts/ferrum-gateway/values.yaml"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            ["tests/k8s/multicluster-federation/run.sh"],
            {"run_mesh_federation": True},
        ),
        (
            "pull_request",
            ["src/backend_conn_limit.rs"],
            {"run_mesh_sidecar_smoke": True},
        ),
        (
            "pull_request",
            ["src/socket_opts.rs"],
            {"run_ebpf_live": True},
        ),
        (
            "pull_request",
            ["ebpf/ferrum-ebpf/src/main.rs"],
            {"run_ebpf_build": True, "run_ebpf_live": True},
        ),
        (
            "pull_request",
            ["docs/admin_api.md"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/scripts/pr_ci_plan.py"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/scripts/live_suite_path_filter.py"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            [".github/actions/setup-kubernetes-tools/action.yml"],
            {"run_ebpf_live": True, "run_helm": True},
        ),
        (
            "pull_request",
            [],
            {name: True for name in JOB_GATE_NAMES},
        ),
        ("push", ["docs/admin_api.md"], {name: True for name in JOB_GATE_NAMES}),
        ("workflow_dispatch", [], {name: True for name in JOB_GATE_NAMES}),
    ]
    for event_name, changed, expected in gate_cases:
        selected = select_job_gates(event_name, changed)
        for gate, expected_value in expected.items():
            if selected[gate] != expected_value:
                failures.append(
                    f"{event_name} {changed!r}: expected {gate}={expected_value}, "
                    f"selected {selected[gate]}"
                )

    if live_suite_self_test() != 0:
        failures.append("live-suite path-filter self-test failed")
    failures.extend(action_pinning_self_test())
    failures.extend(validate_action_pinning_policy(Path.cwd()))
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name")
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.event_name:
        parser.error("--event-name is required unless --self-test is used")

    changed_files = read_changed_files(args.changed_files)
    mode, reason = select_mode(args.event_name, changed_files)
    print(f"mode={mode}")
    print(f"reason={reason}")
    for name, enabled in select_job_gates(args.event_name, changed_files).items():
        print(f"{name}={str(enabled).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
