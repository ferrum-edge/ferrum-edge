#!/usr/bin/env python3
"""Select full or lightweight CI for a pull request's changed files."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath

from live_suite_path_filter import self_test as live_suite_self_test


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
# accidentally omitted. Files under charts/ are executable Helm inputs
# regardless of extension and must run the full CI mode that hosts chart
# security validation.
FULL_CI_PREFIXES = ("vendor/", "charts/")

# These checked-in artifacts are executable contract inputs, not lightweight
# prose. Changes must run the Rust parity tests and static contract validator.
FULL_CI_CONTRACT_PATHS = frozenset(
    {
        "docs/prometheus_metric_contract.json",
        "docs/prometheus_metrics.md",
    }
)

# These files deliberately trigger one or more live datapath suites. The
# required-CI verifier mechanically checks this set against both
# live_suite_path_filter.py and node-waypoint-ebpf-live.yml.
FULL_CI_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/ci_cd.md",
        "docs/configuration.md",
        "docs/cp_dp_mode.md",
        "docs/mesh.md",
        "docs/mesh_multicluster_federation_runbook.md",
        "docs/mesh_supported_matrix.md",
        "docs/node_agent.md",
        # Trigger of the CNI install-lifecycle live suite (issue #3908); the
        # required-CI verifier proves this set covers every live-suite
        # documentation trigger.
        "docs/node_agent_security.md",
        "docs/plans/node_waypoint_transport_adr.md",
        "docs/spire_deployment.md",
        "docs/tcp_udp_proxy.md",
    }
)

# Vendored-patch lifecycle governance inputs. The fail-closed parity gate that
# reads them (`scripts/check_vendored_patch_lifecycle.py`, run by the
# `dependency-audit` job) must keep its `mode == 'full'` guard — that is
# asserted by .github/scripts/verify_required_ci.py's DIRECT_FULL_CI_JOBS — so a
# governance-doc-only pull request would otherwise skip the only check that
# guards these files. They schedule no expensive path-gated suite.
FULL_CI_GOVERNANCE_PATHS = frozenset(
    {
        "docs/dependency-policy.md",
        "docs/vendored-patch-lifecycle.json",
        "PRODUCTION_READINESS.md",
    }
)

# Per-patch retirement plans. The same gate reads each README's path and its
# dated deliberate-fork reaffirmation text.
FULL_CI_GOVERNANCE_PREFIXES = ("docs/upstream-",)

# Pull-request-only job gates. Keep these allow-lists narrow: a path must be
# known to affect the expensive suite before the planner schedules it. An
# unavailable/empty diff, or a NUL stream that cannot be classified, fails
# closed in select_job_gates() and schedules all gated jobs.
HELM_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"^charts/",
        r"^\.github/workflows/ci\.yml$",
        r"^\.github/scripts/extract_rendered_prometheus_rules\.py$",
        r"^\.github/scripts/validate_prometheus_metric_contract\.py$",
        r"^\.github/scripts/verify_mesh_production_readiness\.py$",
        r"^scripts/check_helm_values_schema_parity\.py$",
        r"^\.github/actions/",
        r"^docs/prometheus_metric_contract\.json$",
        r"^docs/prometheus_metrics\.md$",
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
        r"^src/(?:main|gateway_entry|startup|cli)\.rs$",
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

# Compile-and-CI inputs shared by the three ci.yml live suites. These jobs
# cargo-test locally; they do not build the published runtime image, so
# Dockerfile / image-staging / kind tooling stay out. Dedicated live workflows
# (node-waypoint-ebpf-live, ambient-host-udp-live) keep their own filters.
LIVE_SUITE_SHARED_PATTERNS = (
    r"^\.github/workflows/ci\.yml$",
    r"^\.github/actions/(?:setup-rust-ci|setup-sccache|setup-fast-linker)/",
    r"^Cargo\.(?:toml|lock)$",
    r"^\.cargo/",
    r"^rust-toolchain\.toml$",
    r"^build\.rs$",
    r"^vendor/",
)

# Intentionally absent from all three per-suite gates (they were in the old
# single `run_ebpf_live` union). None of the ci.yml live jobs execute them, so
# narrowing per issue #3900 re-homes each to the dedicated workflows or leaves
# it compiler-gated by the always-run cargo jobs:
# - `src/k8s_controller/`: K8s watch/reconcile; no ci.yml live job boots a
#   cluster (owned by node-waypoint-ebpf-live and the dedicated
#   mesh-e2e-sidecar-live / multicluster-federation-live workflows).
# - `src/service_discovery/**` except `mesh.rs`: consul/DNS-SD/HTTP discovery
#   polls; only the `service_discovery/mesh.rs` leg the meshes traverse is kept
#   in netns + two-cluster.
# - `src/grpc/{mod,cp_trust,cp_trust_health,configsync_lifecycle}.rs`: CP trust
#   serving and ConfigSync lifecycle; the three suites exercise the dataplane,
#   not CP serving (`cp_server.rs` stays for the shared JWT issuer).
# - `src/modes/control_plane.rs`: CP runtime; not on any of the three datapaths.
# - `src/plugins/prometheus_metrics.rs`: plugin metric collection; not part of
#   the live datapath under test.
# Dockerfile / stage_iproute2_runtime.sh / setup-kubernetes-tools /
# package-ferrum-runtime-image are already justified by the shared-pattern
# comment above (the ci.yml jobs cargo-test locally and build no runtime image).
#
# `tests/k8s/lib/` (kind.sh, spire.sh, live_assertions.sh,
# native_probe_classify.py, spire_ambient_metrics.py) is the shared Kind/SPIRE
# live harness; no ci.yml live job consumes it, so none of the three gates list
# it. It is owned by node-waypoint-ebpf-live.yml, which gates it both in its
# `pull_request.paths` (`tests/k8s/lib/**`) and in its trusted planner scoped
# suite (ci_runtime_plan.py `node-waypoint-ebpf-live` lists `^tests/k8s/lib/`).
# ambient-host-udp-live.yml's `live_suite_path_filter.py` additionally gates the
# `live_assertions.sh` / `spire.sh` / `native_probe_classify.py` members, so the
# shared harness is covered by both dedicated live workflows.


def compile_path_patterns(*pattern_groups: tuple[str, ...]) -> list[re.Pattern[str]]:
    return [re.compile(pattern) for group in pattern_groups for pattern in group]


# `ebpf-live`: nightly BPF build + `ebpf::loader::live_kernel_tests` (load,
# verify, attach, map round-trip, connect4 redirect, inbound tc redirect).
#
# Direct production helpers those in-lib tests call, kept file-scoped rather
# than a `src/` union:
# - `kernel_probe::probe_kernel` → `crate::capture::should_fallback_to_iptables`
# - live datapath → `crate::proxy::create_proxy_socket` in `src/proxy/mod.rs`,
#   which sets `IP_TRANSPARENT` via `src/socket_opts.rs`
# - `crate::modes::node_agent::ingress_redirect_routing_commands`
# The functional harness is not a kernel input: that job runs
# `ebpf::loader::live_kernel_tests`, not `functional_mesh_mode_test.rs`.
EBPF_KERNEL_LIVE_PATTERNS = compile_path_patterns(
    LIVE_SUITE_SHARED_PATTERNS,
    (
        r"^\.github/actions/setup-bpf-linker/",
        r"^ebpf/",
        r"^src/capture/",
        r"^src/ebpf/",
        r"^src/modes/node_agent\.rs$",
        r"^src/proxy/mod\.rs$",
        r"^src/socket_opts\.rs$",
    ),
)

# `netns-capture-live`: in-lib netns/TPROXY/SO_ORIGINAL_DST tests plus the
# privileged `functional_mesh_live_source_capture_*` e2e (NetnsUdpCaptureManager,
# production REDIRECT, HBONE/mTLS relay). Distinct from the dedicated
# ambient-host-udp-live workflow.
#
# The two functional tests spawn real mesh-mode gateways, so the gate also
# covers the production boundaries they traverse rather than only capture
# producers: HBONE pool/proxy, mesh-mode runtime (native MeshSubscribe client),
# mesh gRPC subscribe (`src/grpc/mesh_*` plus JWT audience, the shared
# `cp_server` default issuer, and `GrpcJwtSecret` minting), identity/SVID,
# TLS/SPIFFE, mesh policy plugins, route selection, and `mesh_trust_registry`
# (attached to the HBONE/mTLS pools). Unrelated CP trust serving stays out.
NETNS_CAPTURE_LIVE_PATTERNS = compile_path_patterns(
    LIVE_SUITE_SHARED_PATTERNS,
    (
        r"^proto/",
        r"^src/capture/",
        r"^src/grpc/(?:mesh_|auth\.rs$|cp_server\.rs$|dp_client\.rs$)",
        r"^src/identity/",
        r"^src/modes/mesh/",
        r"^src/modes/(?:node_agent|node_agent_cni_server)\.rs$",
        r"^src/plugins/mesh/",
        r"^src/router_cache\.rs$",
        r"^src/service_discovery/mesh\.rs$",
        r"^src/socket_opts\.rs$",
        r"^src/tls/",
        r"^src/proxy/(?:backend_dispatch|hbone_pool|hbone_proxy|host_udp_capture|host_udp_capture_live_tests|mesh_mtls_pool|mesh_tcp_egress|mesh_tcp_inbound|mesh_trust_registry|mesh_udp_capture|mesh_udp_frame|mod|netns_capture|netns_udp_capture|tcp_proxy|udp_batch|udp_placement_migration)\.rs$",
        r"^tests/functional/functional_mesh_mode_test\.rs$",
    ),
)

# `two-cluster-mesh-live`: `functional_mesh_live_two_cluster_cross_cluster_protocol_matrix`
# plus `tests/functional/fixtures/two_cluster_spire.sh`. Cross-cluster HBONE,
# identity/SPIRE, east-west materialization, and mesh subscribe — not the
# in-lib kernel or netns primitive tests.
#
# Extra shared production helpers the matrix actually uses:
# - `src/socket_opts.rs`: `SO_ORIGINAL_DST` after `install_tcp_capture` REDIRECT
# - `src/proxy/mesh_trust_registry.rs`: federated / wrong-TD fail-closed
# - `src/grpc/auth.rs` + `src/grpc/cp_server.rs` + `src/grpc/dp_client.rs`:
#   native MeshSubscribe JWT authentication and shared issuer default
# Not included: `src/proxy/netns_capture.rs` (sidecar binds in its own netns)
# and CP-side trust serving (`cp_trust`).
TWO_CLUSTER_LIVE_PATTERNS = compile_path_patterns(
    LIVE_SUITE_SHARED_PATTERNS,
    (
        r"^proto/",
        r"^src/capture/",
        r"^src/grpc/(?:mesh_|auth\.rs$|cp_server\.rs$|dp_client\.rs$)",
        r"^src/identity/",
        r"^src/modes/mesh/",
        r"^src/plugins/mesh/",
        r"^src/proxy/(?:backend_dispatch|grpc_proxy|hbone_pool|hbone_proxy|mesh_mtls_pool|mesh_tcp_egress|mesh_tcp_inbound|mesh_trust_registry|mesh_udp_capture|mesh_udp_frame|mod|netns_udp_capture|tcp_proxy)\.rs$",
        r"^src/router_cache\.rs$",
        r"^src/service_discovery/mesh\.rs$",
        r"^src/socket_opts\.rs$",
        r"^src/tls/",
        r"^tests/functional/functional_mesh_mode_test\.rs$",
        r"^tests/functional/fixtures/two_cluster_spire\.sh$",
    ),
)

# Compile-graph and CI-controller inputs shared by the Secret Backends and
# PKCS#11 SoftHSM jobs. Either job compiles a private feature graph, so a
# toolchain, lockfile, vendored crate, proto, or rust-ci action change can
# alter what those suites build even when no secrets/PKCS source moved.
SHARED_FEATURE_JOB_PATTERNS = (
    r"^\.github/workflows/ci\.yml$",
    r"^\.github/actions/(?:setup-rust-ci|setup-sccache|setup-fast-linker)/",
    r"^Cargo\.(?:toml|lock)$",
    r"^\.cargo/",
    r"^rust-toolchain\.toml$",
    r"^build\.rs$",
    r"^proto/",
    r"^vendor/",
)

# Secret Backends compiles `--features secrets-vault,secrets-aws,secrets-gcp,
# secrets-azure --test secrets_functional` (then default-features
# `cross_backend`). Observable surfaces are the provider module, that test
# target, the TLS secret-source feature branches, nextest's serial override for
# it, Cargo feature/optional-dep wiring, and the startup path that calls
# `secrets::resolve_all_env_secrets()` before `EnvConfig` parse. `src/startup.rs`
# is listener-failure bookkeeping and is not on that path.
SECRETS_BACKENDS_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        *SHARED_FEATURE_JOB_PATTERNS,
        r"^src/secrets/",
        r"^src/tls/source/mod\.rs$",
        r"^tests/secrets_functional/",
        r"^src/(?:main|gateway_entry)\.rs$",
        r"^src/config/env_config\.rs$",
        r"^\.config/nextest\.toml$",
    )
]

# PKCS#11 SoftHSM compiles `--features pkcs11 --lib tls::pkcs11::tests` and
# `--test unit_tests tls::pkcs11`. Observable surfaces are the feature-gated
# module, the feature-gated config/inventory code, TLS load/backend/source/reload
# paths those tests call, the `tests/unit/tls` PKCS modules plus their `mod.rs`
# wiring, and Cargo `pkcs11`/`cryptoki` feature wiring. Sibling TLS unit files
# (ACME, FIPS) do not change what this job runs.
PKCS11_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        *SHARED_FEATURE_JOB_PATTERNS,
        r"^src/config/types\.rs$",
        r"^src/tls/pkcs11\.rs$",
        r"^src/tls/mod\.rs$",
        r"^src/tls/backend\.rs$",
        r"^src/tls/frontend_reload\.rs$",
        r"^src/tls/inventory\.rs$",
        r"^src/tls/source/",
        r"^tests/unit/tls/(?:mod\.rs|pkcs11)",
    )
]

JOB_GATE_NAMES = (
    "run_helm",
    "run_ebpf_kernel_live",
    "run_netns_capture_live",
    "run_two_cluster_live",
    "run_ebpf_build",
    "run_secrets_backends",
    "run_pkcs11",
)

# Scripts whose logic controls the gate decisions themselves. Changing either
# force-runs every gated suite (see select_job_gates).
GATE_CONTROLLER_PATHS = frozenset(
    {
        ".github/scripts/pr_ci_plan.py",
        ".github/scripts/live_suite_path_filter.py",
    }
)

# Conservative repository-relative charset matching origin/main. C0 controls,
# DEL, backslash, backticks, and other Markdown/shell metacharacters are
# rejected by omission so a hostile Git filename cannot split, quote, or
# interpolate its way past a secrets/PKCS path gate.
CLASSIFIABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@~ /-]{1,4096}$")
UNCLASSIFIABLE_REASON = (
    "changed paths were suppressed as unclassifiable; defaulting to full CI"
)


def is_lightweight_path(path: str) -> bool:
    if (
        path.startswith(FULL_CI_PREFIXES)
        or path in FULL_CI_CONTRACT_PATHS
        or path.startswith(FULL_CI_GOVERNANCE_PREFIXES)
        or path in FULL_CI_DOCUMENTATION_PATHS
        or path in FULL_CI_GOVERNANCE_PATHS
    ):
        return False
    return any(pattern.search(path) for pattern in LIGHTWEIGHT_PATTERNS)


def is_path_gated_event(event_name: str) -> bool:
    """Return whether this event may use a changed-file path gate.

    `pull_request` and `merge_group` both supply an accurate base/head range
    when the workflow derives the file list from the event payload. Every other
    event fails closed to full CI and every gated suite.
    """

    return event_name in {"pull_request", "merge_group"}


def select_mode(event_name: str, changed_files: list[str]) -> tuple[str, str]:
    if not is_path_gated_event(event_name):
        return "full", f"full CI is required for {event_name}"

    # Fail closed when the diff cannot be established. An empty PR/merge-group
    # diff is unusual, and running full validation is safer than silently
    # skipping it. Merge-group runs must never reduce to a no-op because
    # pull_request payload fields are absent.
    if not changed_files:
        return "full", "no changed files were detected; defaulting to full CI"

    if not job_gate_paths_are_classifiable(changed_files):
        return "full", UNCLASSIFIABLE_REASON

    full_ci_files = [path for path in changed_files if not is_lightweight_path(path)]
    if full_ci_files:
        return "full", f"full-CI input changed: {full_ci_files[0]}"

    return "light", "only documentation, license, or agent-instruction files changed"


def any_path_matches(patterns: list[re.Pattern[str]], changed_files: list[str]) -> bool:
    return any(pattern.search(path) for path in changed_files for pattern in patterns)


def is_classifiable_repo_path(path: str) -> bool:
    """Return whether one path is a conservative repository-relative Git path.

    `PurePosixPath.parts` collapses empty components, so classification splits
    on `/` itself. Leading/trailing whitespace, `.` / `..` / empty components,
    absolute paths, and any character outside the origin/main allowlist fail
    closed.
    """

    if path != path.strip():
        return False
    if not CLASSIFIABLE_PATH_RE.fullmatch(path):
        return False
    if path.startswith("/") or path.endswith("/"):
        return False
    parts = path.split("/")
    return bool(parts) and all(part not in {"", ".", ".."} for part in parts)


def job_gate_paths_are_classifiable(changed_files: list[str]) -> bool:
    """Return whether every changed path can be matched against job-gate allow-lists.

    Unclassifiable paths make `select_mode()` choose full CI and
    `select_job_gates()` schedule every gated suite, without interpolating the
    raw bytes into the reason string.
    """

    return all(is_classifiable_repo_path(path) for path in changed_files)


def select_job_gates(event_name: str, changed_files: list[str]) -> dict[str, bool]:
    if not is_path_gated_event(event_name) or not changed_files:
        return {name: True for name in JOB_GATE_NAMES}

    if not job_gate_paths_are_classifiable(changed_files):
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
        "run_ebpf_kernel_live": any_path_matches(
            EBPF_KERNEL_LIVE_PATTERNS, changed_files
        ),
        "run_netns_capture_live": any_path_matches(
            NETNS_CAPTURE_LIVE_PATTERNS, changed_files
        ),
        "run_two_cluster_live": any_path_matches(
            TWO_CLUSTER_LIVE_PATTERNS, changed_files
        ),
        "run_ebpf_build": any(path.startswith("ebpf/") for path in changed_files),
        "run_secrets_backends": any_path_matches(
            SECRETS_BACKENDS_PATTERNS, changed_files
        ),
        "run_pkcs11": any_path_matches(PKCS11_PATTERNS, changed_files),
    }


def parse_nul_changed_files(data: bytes) -> tuple[list[str], bool]:
    """Parse a `git diff --name-only --no-renames -z` changed-file stream.

    A nonempty stream must be a complete NUL-terminated sequence of UTF-8
    repository-relative paths. Framing, encoding, or shape failures return no
    paths and `classifiable=False` so callers fail closed without displaying
    hostile bytes. An empty stream is classifiable and means "no files".
    """

    if not data:
        return [], True
    if not data.endswith(b"\0"):
        return [], False
    records = data.split(b"\0")[:-1]
    if not records:
        return [], False
    paths: list[str] = []
    for record in records:
        if not record:
            return [], False
        try:
            path = record.decode("utf-8")
        except UnicodeDecodeError:
            return [], False
        if not is_classifiable_repo_path(path):
            return [], False
        paths.append(path)
    return paths, True


def plan_from_changed_bytes(
    event_name: str, data: bytes
) -> tuple[str, str, dict[str, bool], bool]:
    """Select mode and gates from a raw NUL changed-file stream.

    Unclassifiable input emits full mode, every job gate, `paths_classifiable`
    false, and the canned reason; it never returns parsed path strings to the
    caller. The workflow controller treats `paths_classifiable` as a
    trust/transport version handshake and force-runs every job gate unless the
    flag is exactly true, so an older newline-only trusted-base planner cannot
    honor syntactically valid false gates from a NUL stream.
    """

    changed_files, paths_classifiable = parse_nul_changed_files(data)
    if not paths_classifiable:
        return (
            "full",
            UNCLASSIFIABLE_REASON,
            {name: True for name in JOB_GATE_NAMES},
            False,
        )
    mode, reason = select_mode(event_name, changed_files)
    return mode, reason, select_job_gates(event_name, changed_files), True


def read_changed_files(path: Path | None) -> tuple[list[str], bool]:
    if path is None:
        return [], True
    return parse_nul_changed_files(path.read_bytes())


def nul_transport_self_test() -> list[str]:
    """Prove NUL framing and fail-closed classification without printing hostile bytes."""

    failures: list[str] = []
    all_true = {name: True for name in JOB_GATE_NAMES}

    parsed, classifiable = parse_nul_changed_files(
        b"docs/admin_api.md\0src/proxy/mod.rs\0"
    )
    if not classifiable or parsed != ["docs/admin_api.md", "src/proxy/mod.rs"]:
        failures.append("normal NUL stream must parse both repository paths")
    mode, _reason, gates, flag = plan_from_changed_bytes(
        "pull_request", b"docs/admin_api.md\0src/proxy/mod.rs\0"
    )
    if not flag or mode != "full":
        failures.append("classifiable code path must keep full mode")
    if gates["run_secrets_backends"] or gates["run_pkcs11"]:
        failures.append("proxy-only NUL stream must not force secrets/PKCS gates")

    parsed, classifiable = parse_nul_changed_files(b"")
    if not classifiable or parsed:
        failures.append("empty changed-file stream must stay classifiable and empty")
    mode, reason, gates, flag = plan_from_changed_bytes("pull_request", b"")
    if not flag or mode != "full" or gates != all_true:
        failures.append("empty NUL stream must fail closed to full CI and every gate")
    if reason != "no changed files were detected; defaulting to full CI":
        failures.append("empty NUL stream must keep the unavailable-diff reason")

    mode, _reason, gates, flag = plan_from_changed_bytes(
        "pull_request", b"src/secrets/env.rs\0"
    )
    if (
        not flag
        or mode != "full"
        or not gates["run_secrets_backends"]
        or gates["run_pkcs11"]
    ):
        failures.append("classifiable secrets path must keep the narrow secrets gate")
    mode, _reason, gates, flag = plan_from_changed_bytes(
        "merge_group", b"src/tls/pkcs11.rs\0"
    )
    if (
        not flag
        or mode != "full"
        or not gates["run_pkcs11"]
        or gates["run_secrets_backends"]
    ):
        failures.append("classifiable PKCS path must keep the narrow PKCS gate")

    unsafe_cases = (
        ("truncated-no-nul", b"src/secrets/env.rs"),
        ("truncated-after-record", b"docs/admin_api.md\0src/secrets/env.rs"),
        ("invalid-utf8", b"src/secrets/\xff.rs\0"),
        ("newline", b"src/secrets/\nenv.rs\0"),
        ("tab", b"src/secrets/\tenv.rs\0"),
        ("c0-soh", b"src/secrets/\x01env.rs\0"),
        ("c0-cr", b"src/secrets/\renv.rs\0"),
        ("c0-us", b"src/secrets/\x1fenv.rs\0"),
        ("del", b"src/secrets/\x7fenv.rs\0"),
        ("backslash", b"src\\secrets\\env.rs\0"),
        ("absolute", b"/src/secrets/env.rs\0"),
        ("traversal", b"src/../secrets/env.rs\0"),
        ("dot-prefix", b"./src/secrets/env.rs\0"),
        ("dot-inner", b"src/./secrets/env.rs\0"),
        ("empty-component", b"src//secrets/env.rs\0"),
        ("trailing-slash", b"src/secrets/env.rs/\0"),
        ("empty-record", b"\0"),
        ("backtick", b"src/secrets/`env.rs\0"),
        ("paren", b"src/secrets/env(rs)\0"),
        ("star", b"src/secrets/*.rs\0"),
        ("hash", b"src/secrets/env#.rs\0"),
        ("dollar", b"src/secrets/$env.rs\0"),
        ("semicolon", b"src/secrets/env.rs;\0"),
        ("single-quote", b"src/secrets/'env.rs\0"),
        ("double-quote", b'src/secrets/"env.rs\0'),
        ("newline-delimited", b"src/secrets/env.rs\ndocs/admin_api.md\n"),
    )
    for label, data in unsafe_cases:
        parsed, classifiable = parse_nul_changed_files(data)
        if classifiable or parsed:
            failures.append(
                f"{label}: NUL parse must reject the stream without returning paths"
            )
            continue
        for event_name in ("pull_request", "merge_group"):
            mode, reason, gates, flag = plan_from_changed_bytes(event_name, data)
            if flag:
                failures.append(f"{label}/{event_name}: must not mark paths classifiable")
            if mode != "full" or reason != UNCLASSIFIABLE_REASON:
                failures.append(
                    f"{label}/{event_name}: must emit full mode with the unclassifiable reason"
                )
            if gates != all_true:
                failures.append(f"{label}/{event_name}: must schedule every job gate")
            if not reason.isascii() or any(ord(char) < 32 for char in reason):
                failures.append(f"{label}/{event_name}: reason must stay safe ASCII")

    with tempfile.TemporaryDirectory() as temp_dir:
        stream = Path(temp_dir) / "changed"
        stream.write_bytes(b"src/tls/pkcs11.rs\0")
        files, ok = read_changed_files(stream)
        if not ok or files != ["src/tls/pkcs11.rs"]:
            failures.append("read_changed_files must parse a NUL-terminated PKCS path")
        stream.write_bytes(b"src/secrets/env.rs")
        files, ok = read_changed_files(stream)
        if ok or files:
            failures.append("read_changed_files must reject a truncated NUL stream")

    return failures


def self_test() -> int:
    cases = [
        ("pull_request", ["docs/admin_api.md"], "light"),
        ("pull_request", ["README.md", "LICENSE-COMMERCIAL.md"], "light"),
        ("pull_request", [".agents/skills/opus-agents/scripts/dispatch-agent.sh"], "light"),
        ("pull_request", [".claude/rules/testing.md"], "light"),
        ("pull_request", ["docs/mesh.md"], "full"),
        ("pull_request", ["docs/cp_dp_mode.md"], "full"),
        ("pull_request", ["docs/configuration.md"], "full"),
        ("pull_request", ["docs/plans/node_waypoint_transport_adr.md"], "full"),
        ("pull_request", ["docs/prometheus_metric_contract.json"], "full"),
        ("pull_request", ["docs/prometheus_metrics.md"], "full"),
        (
            "pull_request",
            ["vendor/tungstenite-0.29.0-ferrum-patched/README.md"],
            "full",
        ),
        (
            "pull_request",
            ["charts/ferrum-mesh/templates/node-agent.md"],
            "full",
        ),
        ("pull_request", ["docs/vendored-patch-lifecycle.json"], "full"),
        ("pull_request", ["docs/dependency-policy.md"], "full"),
        (
            "pull_request",
            [
                "docs/upstream-h3-patches/"
                "002-extended-connect-websocket-protocol/README.md"
            ],
            "full",
        ),
        ("pull_request", ["src/proxy/legacy.rs", "notes.md"], "full"),
        ("pull_request", ["src/proxy/mod.rs"], "full"),
        ("pull_request", ["docs/admin_api.md", "Cargo.lock"], "full"),
        ("pull_request", [".github/workflows/ci.yml"], "full"),
        ("pull_request", ["tests/README.md", "tests/unit_tests.rs"], "full"),
        ("pull_request", [], "full"),
        ("merge_group", ["docs/admin_api.md"], "light"),
        ("merge_group", ["src/proxy/mod.rs"], "full"),
        ("merge_group", [], "full"),
        ("merge_group", ["docs/admin_api.md", "src/proxy/mod.rs"], "full"),
        ("push", ["docs/ci_cd.md"], "full"),
        ("workflow_dispatch", [], "full"),
        ("pull_request", ["src/../secrets/env.rs"], "full"),
        ("pull_request", ["docs/admin_api.md", "docs/`evil`.md"], "full"),
        ("merge_group", ["src/secrets/\tenv.rs"], "full"),
    ]
    failures: list[str] = []
    for event_name, changed, expected in cases:
        mode, _ = select_mode(event_name, changed)
        if mode != expected:
            failures.append(
                f"{event_name} {changed!r}: expected {expected}, selected {mode}"
            )

    for changed in (
        ["src/../secrets/env.rs"],
        ["docs/admin_api.md", "docs/`evil`.md"],
        ["src/secrets/\tenv.rs"],
    ):
        mode, reason = select_mode("pull_request", changed)
        if mode != "full" or reason != UNCLASSIFIABLE_REASON:
            failures.append(
                "unclassifiable string paths must emit full mode with the canned reason"
            )
        if any(path in reason for path in changed):
            failures.append("unclassifiable reason must not echo changed paths")

    gate_cases = [
        (
            "pull_request",
            ["charts/ferrum-gateway/values.yaml"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            ["docs/prometheus_metric_contract.json"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            ["docs/prometheus_metrics.md"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            [".github/scripts/validate_prometheus_metric_contract.py"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            [".github/scripts/extract_rendered_prometheus_rules.py"],
            {"run_helm": True},
        ),
        (
            "pull_request",
            ["tests/k8s/multicluster-federation/run.sh"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["src/backend_conn_limit.rs"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["docs/cp_dp_mode.md"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["src/modes/grpc_tls_reload.rs"],
            {"run_helm": True},
        ),
        # Per-suite positives: kernel loader/program, netns capture, two-cluster.
        (
            "pull_request",
            ["src/ebpf/loader.rs"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/proxy/netns_capture.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/socket_opts.rs"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/proxy/host_udp_capture.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/proxy/host_udp_capture_live_tests.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/proxy/udp_placement_migration.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/modes/mesh/mod.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/proxy/hbone_proxy.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/grpc/mesh_server.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/identity/mod.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["tests/functional/fixtures/two_cluster_spire.sh"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": True,
            },
        ),
        # Cross-gate positives for the repaired production boundaries: exact
        # kernel / netns / two-cluster values, not merely substring presence.
        (
            "pull_request",
            ["src/proxy/mod.rs"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/proxy/hbone_pool.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/proxy/mesh_trust_registry.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/modes/mesh/config_consumer/native_client.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/grpc/auth.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/grpc/dp_client.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/tls/mod.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/grpc/cp_server.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/proxy/backend_dispatch.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/proxy/tcp_proxy.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/router_cache.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/service_discovery/mesh.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/plugins/mesh/mesh_authz.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["ebpf/ferrum-ebpf/src/main.rs"],
            {
                "run_ebpf_build": True,
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        # Shared compile/CI inputs fire every live suite. The functional harness
        # is an input only for the jobs that actually run tests from that file
        # (netns + two-cluster). Kernel live tests live in src/ebpf/loader.rs.
        (
            "pull_request",
            ["Cargo.lock"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["rust-toolchain.toml"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            [".github/actions/setup-rust-ci/action.yml"],
            {
                "run_helm": True,
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            [".github/workflows/ci.yml"],
            {
                "run_helm": True,
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            [".github/actions/setup-bpf-linker/action.yml"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/modes/node_agent.rs"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["tests/functional/functional_mesh_mode_test.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        (
            "pull_request",
            ["src/capture/mod.rs"],
            {
                "run_ebpf_kernel_live": True,
                "run_netns_capture_live": True,
                "run_two_cluster_live": True,
            },
        ),
        # Meaningful negatives: dedicated ambient-host-UDP / image / k8s-tooling
        # / unrelated CP trust serving must not resurrect the old union gate.
        # Mesh TLS is a shared netns+two-cluster security boundary (see
        # src/tls/mod.rs above), not a kernel-live input.
        (
            "pull_request",
            ["tests/k8s/ambient_host_udp_live/run.sh"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["Dockerfile"],
            {
                "run_helm": True,
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            [".github/actions/setup-kubernetes-tools/action.yml"],
            {
                "run_helm": True,
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/grpc/cp_trust.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        # Plugin/admin-only: full CI, but none of the expensive live suites.
        (
            "pull_request",
            ["src/plugins/cors.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/admin/mod.rs"],
            {
                "run_ebpf_kernel_live": False,
                "run_netns_capture_live": False,
                "run_two_cluster_live": False,
            },
        ),
        (
            "pull_request",
            ["src/secrets/env.rs"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["tests/secrets_functional/cross_backend.rs"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/main.rs"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/gateway_entry.rs"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/config/env_config.rs"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/tls/source/mod.rs"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            ["src/tls/pkcs11.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["tests/unit/tls/pkcs11_softhsm_tests.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["src/tls/mod.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["src/tls/backend.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["src/config/types.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["src/tls/inventory.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["src/plugins/cors.rs"],
            {"run_secrets_backends": False, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/admin/mod.rs"],
            {"run_secrets_backends": False, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/startup.rs"],
            {"run_secrets_backends": False, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["tests/unit/secrets/env_tests.rs"],
            {"run_secrets_backends": False, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["tests/unit/tls/acme_store_ha_tests.rs"],
            {"run_pkcs11": False, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["Cargo.lock"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            ["Cargo.toml"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            ["vendor/tungstenite-0.29.0-ferrum-patched/src/lib.rs"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            [".github/actions/setup-rust-ci/action.yml"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            ["rust-toolchain.toml"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            [".github/workflows/ci.yml"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            ["build.rs"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            ["proto/ferrum.proto"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            [".cargo/config.toml"],
            {"run_secrets_backends": True, "run_pkcs11": True},
        ),
        (
            "pull_request",
            [".config/nextest.toml"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "pull_request",
            ["src/tls/frontend_reload.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "pull_request",
            ["src/../secrets/env.rs"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["docs/admin_api.md", "docs/`evil`.md"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["/src/secrets/env.rs"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["src/secrets/env.rs;"],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "pull_request",
            ["docs/admin_api.md"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        # Full CI, but none of the expensive path-gated suites.
        (
            "pull_request",
            ["docs/vendored-patch-lifecycle.json", "docs/dependency-policy.md"],
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
            [],
            {name: True for name in JOB_GATE_NAMES},
        ),
        (
            "merge_group",
            ["docs/admin_api.md"],
            {name: False for name in JOB_GATE_NAMES},
        ),
        (
            "merge_group",
            ["charts/ferrum-gateway/values.yaml"],
            {"run_helm": True},
        ),
        (
            "merge_group",
            ["src/secrets/env.rs"],
            {"run_secrets_backends": True, "run_pkcs11": False},
        ),
        (
            "merge_group",
            ["src/tls/pkcs11.rs"],
            {"run_pkcs11": True, "run_secrets_backends": False},
        ),
        (
            "merge_group",
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
    failures.extend(nul_transport_self_test())
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

    data = b""
    if args.changed_files is not None:
        data = args.changed_files.read_bytes()
    mode, reason, gates, paths_classifiable = plan_from_changed_bytes(
        args.event_name, data
    )
    print(f"mode={mode}")
    # Workflow ci-plan treats this flag as a trust/transport version handshake:
    # unless it is exactly "true", every job gate is forced on.
    print(f"paths_classifiable={str(paths_classifiable).lower()}")
    print(f"reason={reason}")
    for name, enabled in gates.items():
        print(f"{name}={str(enabled).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
