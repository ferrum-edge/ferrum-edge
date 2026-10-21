#!/usr/bin/env python3
"""Remote-only unchanged-profile linker canary and Ferrum symbol qualification.

Shipping ranking remains on SHIPPING_IMAGE. A symbol twin is eligible only after
shipping, fresh stripped and twin code/layout/build IDs match. Only the companion
build ID is assigned, explicitly; natural companion-ID reproducibility is not
claimed. Code/layout equivalence is checked independently. No image is pushed.
"""
import argparse
import difflib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import resource
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

from mesh_production_profile_symbols import Elf, require, sha256_file
from mesh_production_profile_linker import elf_build_id

SOURCE = "4a7be250e45a367314e3dec872ecbd512220558e"
SHIPPING_IMAGE = "ferrumedge/ferrum-edge@sha256:e95e7f8d0d19e5714cb4e93afb600ebe14a1703aab51e84ad5c2be822d82a4af"
BUILDER = "rust:latest@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
LIMITS = dict(build_seconds=7200, total_seconds=7800, metadata_bytes=8 * 1024**2,
              log_bytes=64 * 1024**2, source_bytes=512 * 1024**2,
              elf_bytes=1024**3, minimum_free_bytes=20 * 1024**3,
              stop_free_bytes=2 * 1024**3)
SHIM = Path(__file__).with_name("mesh_production_profile_linker.py")
CANARY_SOURCE = """#[inline(never)]
fn probe(mut x: u64) -> u64 {
    for i in 0..32 { x = std::hint::black_box(x.wrapping_mul(33).wrapping_add(i)); }
    x
}
fn main() { println!("{}", probe(std::hint::black_box(7))); }
"""
CANARY_MANIFEST = """[package]
name = "mesh-link-probe"
version = "0.0.0"
edition = "2024"
[features]
cloud-secrets = []
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
incremental = false
panic = "abort"
"""
VERSION_COMMAND = ('test -z "${CARGO_PROFILE_RELEASE_STRIP-}"; '
                   'test -z "${CARGO_PROFILE_RELEASE_DEBUG-}"; '
                   'test -z "${RUSTFLAGS-}"; test -z "${CARGO_ENCODED_RUSTFLAGS-}"; '
                   'test ! -e /build/.cargo/config.toml; test ! -e "${CARGO_HOME}/config.toml"; '
                   'test "$(command -v cc)" = /usr/bin/cc; command -v python3; '
                   'rustc -Vv; cargo -V; cc --version; ld --version')


def diagnostic_dockerfile(original):
    anchor = "COPY src ./src\n"
    require(original.count(anchor) == 1, "real-source Dockerfile anchor changed")
    require(original.count(f"FROM {BUILDER} AS builder\n") == 1, "pinned builder changed")
    require("COPY .cargo" not in original, "shipping Dockerfile unexpectedly copies Cargo configuration")
    insertion = ('COPY .mesh-profile/ /opt/mesh-link-capture/\n'
                 'RUN mkdir /profile-capture && chmod 0755 /opt/mesh-link-capture/cc && '
                 '/bin/sh -ec ' + "'" + VERSION_COMMAND + "'" + ' > /profile-capture/setup.txt\n'
                 'ENV PATH="/opt/mesh-link-capture:${PATH}"\n')
    return original.replace(anchor, anchor + insertion, 1)


def validate_profile(manifest):
    release = tomllib.loads(manifest)["profile"]["release"]
    expected = {"opt-level": 3, "lto": "fat", "codegen-units": 1,
                "strip": True, "incremental": False, "panic": "abort"}
    require(all(release.get(k) == v for k, v in expected.items()), "shipping release profile changed")
    require(release.get("debug", False) in (False, 0, "none"), "shipping profile has debuginfo")
    return dict(release, debug=False, diagnostic_override={}, linker_capture="PATH cc shim after real source COPY", features="cloud-secrets")


def qualify(production, diagnostic, minimum_functions=10000):
    opened = []
    result = dict(qualified=False, symbols_may_be_applied_to_shipping=False,
                  sampled_coverage_verified=False, source_line_attribution_verified=False)
    try:
        for path in (production, diagnostic):
            require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= LIMITS["elf_bytes"],
                    "missing/oversize ELF artifact")
            opened.append(Elf(path))
        left, right = opened
        result["shipping_build_id"], result["diagnostic_build_id"] = left.build_id(), right.build_id()
        require(result["shipping_build_id"] is not None and result["diagnostic_build_id"] is not None,
                "missing GNU build ID")
        require(left.kind == right.kind and left.kind in (2, 3) and left.entry == right.entry,
                "ELF type/entry mismatch")
        a, b = left.allocated(), right.allocated()
        for elf, sections in ((left, a), (right, b)):
            for name, section in sections.items():
                section["offset"] = elf.sections[name][4]
        result["excluded_build_id_sections"] = {"shipping": a.pop(".note.gnu.build-id", None),
                                                "diagnostic": b.pop(".note.gnu.build-id", None)}
        result["allocated_section_differences"] = [name for name in sorted(a.keys() | b.keys()) if a.get(name) != b.get(name)]
        result["shipping_executable_segments"] = left.executable_segments()
        result["diagnostic_executable_segments"] = right.executable_segments()
        require(not result["allocated_section_differences"], "allocated sections differ beyond build ID")
        require(bool(result["shipping_executable_segments"]) and
                result["shipping_executable_segments"] == result["diagnostic_executable_segments"],
                "executable segment bytes/addresses/layout differ")
        if minimum_functions:
            result["defined_function_symbols"] = right.functions()
            require(result["defined_function_symbols"] >= minimum_functions, "insufficient defined function symbols")
        result["qualified"] = True
        result["claim"] = "matching executable segments and allocated sections, excluding only GNU build ID"
        result["profiling_requirement"] = "pairwise comparison only; shipping attribution requires the three-way gate"
    except (OSError, ValueError, KeyError, IndexError, UnicodeError) as error:
        result["failure"] = {"type": type(error).__name__, "reason": str(error)}
    finally:
        for elf in opened:
            elf.close()
        result["artifacts"] = {role: {"path": str(path), "bytes": path.stat().st_size,
                                    "sha256": sha256_file(path)}
                               for role, path in (("shipping", production), ("diagnostic", diagnostic))
                               if path.is_file() and not path.is_symlink() and path.stat().st_size <= LIMITS["elf_bytes"]}
    return result


class Commands:
    def __init__(self, output, report):
        self.output, self.report = output, report
        self.started = time.monotonic()
        self.build_started = None
        self.serial = 0

    def run(self, argv, label, *, seconds=60, cap=None, cwd=None, build=False, check=True, cleanup=False):
        self.serial += 1
        cap = LIMITS["log_bytes"] if cap is None else cap
        deadline = time.monotonic() + min(seconds, 30) if cleanup else self.started + LIMITS["total_seconds"]
        if build:
            if self.build_started is None:
                self.build_started = time.monotonic()
            deadline = min(deadline, self.build_started + LIMITS["build_seconds"])
        timeout = min(seconds, deadline - time.monotonic())
        require(timeout > 0, "command/build time budget exhausted")
        stdout = self.output / f"{self.serial:02d}-{label}.stdout"
        stderr = self.output / f"{self.serial:02d}-{label}.stderr"
        record = dict(argv=argv, label=label, stdout=stdout.name, stderr=stderr.name,
                      timeout_seconds=timeout, per_stream_limit_bytes=cap)
        self.report.setdefault("commands", []).append(record)
        begin, child = time.monotonic(), None

        def child_limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))

        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                child = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=err,
                                         start_new_session=True, preexec_fn=child_limits)
                if build:
                    command_deadline = time.monotonic() + timeout
                    while child.poll() is None:
                        remaining = command_deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(argv, timeout)
                        free = os.statvfs(self.output)
                        require(free.f_bavail * free.f_frsize >= LIMITS["stop_free_bytes"],
                                "build stopped before exhausting disk reserve")
                        try:
                            child.wait(timeout=min(5, remaining))
                        except subprocess.TimeoutExpired:
                            pass
                    record["returncode"] = child.returncode
                else:
                    record["returncode"] = child.wait(timeout=timeout)
            except BaseException:
                if child is not None and child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=5)
                record["interrupted"] = True
                raise
            finally:
                record["elapsed_seconds"] = time.monotonic() - begin
                record["returncode"] = child.poll() if child is not None else None
                out.flush()
                err.flush()
                record["stdout_sha256"], record["stderr_sha256"] = sha256_file(stdout), sha256_file(stderr)
        require(stdout.stat().st_size <= cap and stderr.stat().st_size <= cap, "command output bound")
        if check:
            require(record["returncode"] == 0, f"{label} failed (see retained command outputs)")
        return stdout, record["returncode"]

    def json(self, argv, label):
        path, _ = self.run(argv, label, cap=LIMITS["metadata_bytes"])
        return json.loads(path.read_bytes())


def unpack_source(archive_path, destination):
    total = 0
    with tarfile.open(archive_path) as archive:
        members = []
        for member in archive:
            require(len(members) < 10000, "source archive member bound")
            members.append(member)
            total += member.size
            approved_link = member.issym() and member.name == "AGENTS.md" and member.linkname == "CLAUDE.md"
            require(total <= LIMITS["source_bytes"] and (member.isdir() or member.isreg() or approved_link),
                    "source archive size/type bound")
        archive.extractall(destination, members=members, filter="data")
    return dict(files=len(members), unpacked_bytes=total, archive_sha256=sha256_file(archive_path))


def image_info(commands, reference, label, *, source=False):
    rows = commands.json(["docker", "image", "inspect", reference], label)
    require(len(rows) == 1, "ambiguous Docker image")
    image = rows[0]
    require(image["Architecture"] == "amd64" and image["Os"] == "linux", "wrong runtime architecture")
    if source:
        require(image["Config"].get("Labels", {}).get("org.opencontainers.image.revision") == SOURCE,
                "runtime source revision mismatch")
    return {key: image.get(key) for key in ("Id", "RepoDigests", "Architecture", "Os", "Size", "Config")}


def extract_binary(commands, image, name, destination):
    created = False
    try:
        commands.run(["docker", "create", "--name", name, "--network", "none",
                      "--entrypoint", "/app/ferrum-edge", image, "version"], "create-" + name,
                     cap=LIMITS["metadata_bytes"])
        created = True
        archive, _ = commands.run(["docker", "cp", name + ":/app/ferrum-edge", "-"], "extract-" + name,
                                   cap=LIMITS["elf_bytes"] + 2 * 1024**2, seconds=180)
        with tarfile.open(archive) as source:
            members = source.getmembers()
            require(len(members) == 1 and members[0].name == "ferrum-edge" and members[0].isreg()
                    and 0 < members[0].size <= LIMITS["elf_bytes"], "unexpected binary archive")
            with source.extractfile(members[0]) as reader, destination.open("xb") as target:
                while block := reader.read(1024**2):
                    target.write(block)
        # Remove only this helper's redundant binary tar, retaining its hash/size receipt.
        archive.unlink()
    finally:
        if created:
            remove_container(commands, name)


def qualify_chain(shipping, fresh, twin, minimum_functions=10000):
    first = qualify(shipping, fresh, minimum_functions=0)
    second = qualify(fresh, twin, minimum_functions=minimum_functions)
    ids = [first.get("shipping_build_id"), first.get("diagnostic_build_id"), second.get("diagnostic_build_id")]
    qualified = first["qualified"] and second["qualified"] and bool(ids[0]) and len(set(ids)) == 1
    return dict(qualified=qualified, shipping_to_fresh=first, fresh_to_symbols=second,
                build_ids=ids, matching_build_ids=bool(ids[0]) and len(set(ids)) == 1,
                symbols_may_be_applied_to_shipping=qualified,
                symbol_companion_normalization=True, natural_build_id_reproducibility_claim=False,
                sampled_coverage_verified=False, source_line_attribution_verified=False,
                requirement="capture actual shipping mapped ELF hash/build ID; independently gate decoded sample coverage")


def shim_config(source_file, source_hash, *, canary=False):
    return dict(real_cc="/usr/bin/cc", source_file=source_file, source_sha256=source_hash,
                capture_dir="/work/capture" if canary else "/profile-capture",
                output_pattern=(r"/work/project/target/release/deps/mesh_link_probe-[0-9a-f]{16}" if canary
                                else r"/build/target/release/deps/ferrum_edge-[0-9a-f]{16}"),
                minimum_elf_bytes=1024 if canary else 1024**2)


def helper_hashes():
    return {path.name: sha256_file(path) for path in (Path(__file__), SHIM,
            Path(__file__).with_name("mesh_production_profile_symbols.py"))}


def validate_canary(path):
    require(path.is_file() and path.stat().st_size <= LIMITS["metadata_bytes"], "missing/oversize canary report")
    report = json.loads(path.read_bytes())
    require(report.get("action") == "canary" and report.get("qualified") is True
            and report.get("builder") == BUILDER and report.get("helpers") == helper_hashes()
            and report.get("canary", {}).get("matching_metadata") is True
            and report.get("canary", {}).get("identical_first_output") is True
            and report.get("canary", {}).get("same_result") is True
            and report.get("canary", {}).get("equivalence", {}).get("qualified") is True,
            "passed canary from exact builder/helper revision required")
    return dict(path=str(path), sha256=sha256_file(path), builder=report["builder"], helpers=report["helpers"])


def read_capture(directory, source_hash):
    require(not list(directory.glob("failure-*.json")), "link shim recorded a capture failure")
    slot = directory / "ferrum-edge"
    path = slot / "receipt.json"
    require(path.is_file() and path.stat().st_size <= LIMITS["metadata_bytes"], "missing/oversize link receipt")
    receipt = json.loads(path.read_bytes())
    require(receipt.get("captured") is True and receipt.get("original_returncode") == 0
            and receipt.get("secondary_returncode") == 0
            and receipt.get("source_sha256") == source_hash, "symbol twin was not captured successfully")
    require(receipt.get("original_sha256_before") == receipt.get("original_sha256_after") == sha256_file(slot / "stripped")
            and receipt.get("symbol_sha256") == sha256_file(slot / "symbols"), "link capture artifact hash mismatch")
    original_id = elf_build_id(slot / "stripped")
    require(receipt.get("symbol_companion_normalization") is True
            and receipt.get("natural_build_id_reproducibility_claim") is False
            and receipt.get("unassigned_companion_build_id") is None
            and receipt.get("original_auto_build_id") == receipt.get("assigned_companion_build_id")
            == receipt.get("observed_companion_build_id") == original_id == elf_build_id(slot / "symbols"),
            "explicit companion build-ID assignment not verified")
    return receipt


def remove_container(commands, name):
    commands.run(["docker", "rm", "-f", name], "remove-" + name, seconds=30,
                 cap=LIMITS["metadata_bytes"], check=False, cleanup=True)


def run_canary(output, commands, report, suffix):
    work = output / "canary"
    project, shim = work / "project", work / "shim"
    (project / "src").mkdir(parents=True)
    shim.mkdir()
    (work / "cargo-home").mkdir()
    (project / "src/main.rs").write_text(CANARY_SOURCE)
    (project / "Cargo.toml").write_text(CANARY_MANIFEST)
    shutil.copyfile(SHIM, shim / "cc")
    (shim / "cc").chmod(0o755)
    source_hash = sha256_file(project / "src/main.rs")
    (shim / "config.json").write_text(json.dumps(shim_config("/work/project/src/main.rs", source_hash, canary=True)))
    script = """set -eu
""" + VERSION_COMMAND + """
cd /work/project
cargo generate-lockfile --offline
cargo build --offline --locked --release --features cloud-secrets -vv 2>/work/control.log
cp target/release/mesh-link-probe /work/control
./target/release/mesh-link-probe > /work/control.result
rm -rf /work/project/target
PATH="/work/shim:$PATH" cargo build --offline --locked --release --features cloud-secrets -vv 2>/work/capture.log
cp target/release/mesh-link-probe /work/fresh
./target/release/mesh-link-probe > /work/fresh.result
"""
    (work / "run.sh").write_text(script)
    commands.run(["docker", "pull", "--platform", "linux/amd64", BUILDER], "canary-builder-pull", seconds=300)
    report["builder_image"] = image_info(commands, BUILDER, "canary-builder-image")
    container_user = f"{os.getuid()}:{os.getgid()}"
    report["canary_environment"] = dict(user=container_user, cargo_home="/work/cargo-home", network="none", root_filesystem="read-only",
                                         explanation="owned writable Cargo cache for both builds; pinned toolchain unchanged")
    name = "ferrum-link-canary-" + suffix
    try:
        commands.run(["docker", "run", "--name", name, "--user", container_user, "--network", "none", "--read-only",
                      "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
                      "--memory", "2g", "--cpus", "2", "--ulimit", "fsize=1073741824:1073741824",
                      "--tmpfs", "/tmp:rw,nosuid,size=256m", "--env", "CARGO_HOME=/work/cargo-home",
                      "--mount", f"type=bind,src={work},dst=/work",
                      "--entrypoint", "/bin/sh", report["builder_image"]["Id"], "/work/run.sh"],
                     "remote-canary", seconds=300, cap=LIMITS["metadata_bytes"])
    finally:
        remove_container(commands, name)
    receipt = read_capture(work / "capture", source_hash)
    require(all((work / name).stat().st_size <= LIMITS["metadata_bytes"]
                for name in ("control.log", "capture.log")), "canary compiler log bound")
    logs = [(work / name).read_text() for name in ("control.log", "capture.log")]
    metadata = [re.findall(r"-C metadata=([0-9a-f]+)", log) for log in logs]
    require(all(len(values) == 1 for values in metadata), "canary rustc metadata not uniquely observed")
    equivalence = qualify_chain(work / "control", work / "fresh", work / "capture/ferrum-edge/symbols", 1)
    report["canary"] = dict(matching_metadata=metadata[0] == metadata[1], metadata=metadata,
                            identical_first_output=sha256_file(work / "control") == sha256_file(work / "fresh"),
                            same_result=(work / "control.result").read_bytes() == (work / "fresh.result").read_bytes(),
                            receipt=receipt, equivalence=equivalence)
    report["qualified"] = (equivalence["qualified"] and report["canary"]["matching_metadata"]
                           and report["canary"]["identical_first_output"] and report["canary"]["same_result"])
    require(report["qualified"], "unchanged-profile linker canary failed")


def extract_capture(commands, image, name, destination):
    created = False
    try:
        commands.run(["docker", "create", "--name", name, "--network", "none", "--entrypoint", "/bin/true", image],
                     "create-" + name, cap=LIMITS["metadata_bytes"])
        created = True
        archive, _ = commands.run(["docker", "cp", name + ":/profile-capture/.", "-"], "extract-" + name,
                                   cap=2 * LIMITS["elf_bytes"] + 64 * 1024**2, seconds=180)
        destination.mkdir()
        total = 0
        with tarfile.open(archive) as source:
            rows, names = [], set()
            for row in source:
                require(len(rows) < 32 and row.name not in names, "capture file count/duplicate bound")
                names.add(row.name)
                rows.append(row)
                total += row.size
                require((row.isdir() or row.isreg()) and row.size <= LIMITS["elf_bytes"]
                        and total <= 2 * LIMITS["elf_bytes"] + 64 * 1024**2, "capture archive type/size bound")
            source.extractall(destination, members=rows, filter="data")
        archive.unlink()
    finally:
        if created:
            remove_container(commands, name)


def run_qualification(args, output, commands, report, suffix):
    require(args.repo is not None and args.canary_report is not None, "qualify requires --repo and --canary-report")
    report["canary_prerequisite"] = validate_canary(args.canary_report)
    runtime_tag, builder_tag = f"ferrum-capture-runtime:{suffix}", f"ferrum-capture-builder:{suffix}"
    report.update(fresh_runtime_local_tag=runtime_tag, builder_local_tag=builder_tag)
    source_check, _ = commands.run(["git", "rev-parse", "--verify", SOURCE + "^{commit}"], "source-commit", cwd=args.repo)
    require(source_check.read_text().strip() == SOURCE, "source commit mismatch")
    commands.run(["git", "show", "--no-patch", "--format=%H %T", SOURCE], "source-tree", cwd=args.repo)
    archive, _ = commands.run(["git", "archive", "--format=tar", SOURCE], "source-archive", cwd=args.repo,
                              seconds=120, cap=LIMITS["source_bytes"])
    context = output / "source"
    context.mkdir()
    report["source_archive"] = unpack_source(archive, context)
    original = (context / "Dockerfile").read_text()
    transformed = diagnostic_dockerfile(original)
    (output / "Dockerfile.shipping").write_text(original)
    (output / "Dockerfile.capture").write_text(transformed)
    (output / "Dockerfile.diff").write_text("".join(difflib.unified_diff(original.splitlines(True),
            transformed.splitlines(True), fromfile="Dockerfile.shipping", tofile="Dockerfile.capture")))
    (context / "Dockerfile").write_text(transformed)
    shim = context / ".mesh-profile"
    shim.mkdir()
    shutil.copyfile(SHIM, shim / "cc")
    source_hash = sha256_file(context / "src/main.rs")
    (shim / "config.json").write_text(json.dumps(shim_config("/build/src/main.rs", source_hash)))
    report["profile"] = validate_profile((context / "Cargo.toml").read_text())
    report["inputs"] = {p: sha256_file(context / p) for p in ("Dockerfile", "Cargo.toml", "Cargo.lock", "build.rs", "src/main.rs")}
    commands.run(["docker", "version"], "docker-version", cap=LIMITS["metadata_bytes"])
    commands.run(["docker", "pull", "--platform", "linux/amd64", SHIPPING_IMAGE], "shipping-pull", seconds=300)
    report["shipping"] = image_info(commands, SHIPPING_IMAGE, "shipping-image", source=True)
    require(SHIPPING_IMAGE in report["shipping"].get("RepoDigests", []), "shipping repository digest not retained")
    shipping = output / "shipping-ferrum-edge"
    extract_binary(commands, report["shipping"]["Id"], "ferrum-shipping-" + suffix, shipping)
    build = ["docker", "build", "--platform", "linux/amd64", "--progress", "plain", "--build-arg",
             "CARGO_PROFILE=release", "--build-arg", "FEATURES=cloud-secrets", "--label",
             "org.opencontainers.image.revision=" + SOURCE]
    commands.run(build + ["--target", "runtime", "--tag", runtime_tag, str(context)],
                 "capture-runtime-build", seconds=LIMITS["build_seconds"], build=True)
    commands.run(build + ["--target", "builder", "--tag", builder_tag, str(context)],
                 "capture-builder-export", seconds=LIMITS["build_seconds"], build=True)
    report["fresh_runtime"] = image_info(commands, runtime_tag, "fresh-runtime-image", source=True)
    report["fresh_builder"] = image_info(commands, builder_tag, "fresh-builder-image")
    fresh = output / "fresh-stripped-ferrum-edge"
    extract_binary(commands, report["fresh_runtime"]["Id"], "ferrum-fresh-" + suffix, fresh)
    captured = output / "capture"
    extract_capture(commands, report["fresh_builder"]["Id"], "ferrum-capture-" + suffix, captured)
    report["link_receipt"] = read_capture(captured, source_hash)
    require(sha256_file(fresh) == sha256_file(captured / "ferrum-edge/stripped"), "fresh runtime differs from captured original link")
    report["equivalence"] = qualify_chain(shipping, fresh, captured / "ferrum-edge/symbols")
    report["qualified"] = report["equivalence"]["qualified"]
    require(report["qualified"], "shipping/fresh/symbol identity gate failed; no shipping attribution permitted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("canary", "qualify"))
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--canary-report", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new directory; must not exist")
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and platform.system() == "Linux"
            and platform.machine() == "x86_64", "GitHub Actions Linux x64 only")
    output = args.output.absolute()
    output.mkdir(parents=False, exist_ok=False)
    report = dict(schema=2, action=args.action, qualified=False, source=SOURCE, shipping_image=SHIPPING_IMAGE,
                  builder=BUILDER, helpers=helper_hashes(), limits=LIMITS, ranking_image_unchanged=True)
    commands = Commands(output, report)
    suffix = os.urandom(6).hex()

    def interrupted(_signum, _frame):
        raise TimeoutError("build helper interrupted by deadline/cancellation")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        free = os.statvfs(output)
        require(free.f_bavail * free.f_frsize >= LIMITS["minimum_free_bytes"], "insufficient build disk reserve")
        if args.action == "canary":
            run_canary(output, commands, report, suffix)
        else:
            run_qualification(args, output, commands, report, suffix)
    except Exception as error:
        report["qualified"] = False
        report["failure"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        report["elapsed_seconds"] = time.monotonic() - commands.started
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"qualified": report["qualified"], "report": str(output / "report.json"),
                      "failure": report.get("failure")}))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
