"""Hosted capability driver. No benchmark or gateway launch exists in this lane."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import subprocess
import time

from evidence import assess
from live_contract import natural, validate_observer_record

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RUNTIME = Path("/tmp/ferrum-h3-proof")
MAX_TEXT = 256 * 1024
DROP = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]
PACKAGES = ["clang-18", "llvm-18", "libbpf-dev", "libbpf1", "libelf-dev", "gcc",
            "libelf1t64", "zlib1g", "zlib1g-dev", "binutils", "libc6", "libc6-dev",
            "linux-libc-dev", "iproute2", "util-linux", "python3"]


_ADDRESS_RE = re.compile(r"\b(?:0x[0-9a-fA-F]{8,16}|[fF]{4}[0-9a-fA-F]{12})\b")


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def scrub(text):
    # Retain verifier errors, redact address-like diagnostics; no kallsyms addresses.
    return _ADDRESS_RE.sub("[address-redacted]", text)


def command_env(action, **data):
    # Only these data fields cross into the fixed, scanned command inventory.
    allowed = {"output", "package", "version", "family", "netns", "capacity",
               "fault", "unprivileged", "mode"}
    if data.keys() - allowed:
        raise ValueError("unknown command data")
    env = {key: value for key, value in os.environ.items() if not key.startswith("H3_PROOF_")}
    env["H3_PROOF_ACTION"] = action
    env.update({f"H3_PROOF_{key.upper()}": str(value) for key, value in data.items()})
    return env


def command(action, timeout=15, **data):
    start = time.monotonic_ns()
    record = {"argv": ["bash", "tests/performance/multi_protocol/h3_proof/commands.sh"],
              "action": action, "data": data,
              "cwd": str(RUNTIME if action == "isolate" else ROOT), "start_ns": start}
    try:
        # Literal argv exposes the shell source to the repository policy reader.
        # It contains only fixed commands; environment values are validated data.
        result = subprocess.run(
            ["bash", "tests/performance/multi_protocol/h3_proof/commands.sh"],
            cwd=RUNTIME if action == "isolate" else ROOT,
            env=command_env(action, **data), capture_output=True, timeout=timeout, check=False,
        )
        record.update(argv=result.args, returncode=result.returncode,
                      stdout=scrub(result.stdout[:MAX_TEXT].decode("utf-8", "replace")),
                      stderr=scrub(result.stderr[:MAX_TEXT].decode("utf-8", "replace")),
                      truncated=len(result.stdout) > MAX_TEXT or len(result.stderr) > MAX_TEXT)
    except (OSError, subprocess.TimeoutExpired) as error:
        record.update(returncode=None, error=type(error).__name__, errno=getattr(error, "errno", None))
    record["end_ns"] = time.monotonic_ns()
    return record


def read_file(path, limit=MAX_TEXT):
    try:
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
        return {"text": data[:limit].decode("utf-8", "replace"), "truncated": len(data) > limit}
    except OSError as error:
        return {"error": type(error).__name__, "errno": error.errno}


def digest(path):
    try:
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                h.update(chunk)
        return {"sha256": h.hexdigest(), "size": size}
    except OSError as error:
        return {"error": type(error).__name__, "errno": error.errno}


def stage_runtime(out):
    # Fresh root-owned tree: nobody can traverse the runner's private checkout
    # ancestors. Keep identical repo-relative script paths so every execution
    # edge still names the committed source that policy scans. Never reuse a
    # pre-existing path (including a symlink) or change checkout permissions.
    RUNTIME.mkdir(mode=0o755)
    RUNTIME.chmod(0o755)
    target = RUNTIME
    for component in HERE.relative_to(ROOT).parts:
        target /= component
        target.mkdir(mode=0o755)
        target.chmod(0o755)
    for source in HERE.iterdir():
        if source.is_file():
            destination = target / source.name
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
    build = RUNTIME / "build"
    build.mkdir(mode=0o755)
    build.chmod(0o755)
    for name in ["observer", "observer.bpf.o", "pmu", "decoder_test"]:
        destination = build / name
        destination.write_bytes((out / "build" / name).read_bytes())
        destination.chmod(0o644 if name.endswith(".o") else 0o755)
    return {"root": str(RUNTIME),
            "source_hashes": {p.name: digest(p) for p in target.iterdir()},
            "object_hashes": {p.name: digest(p) for p in build.iterdir()}}


def provenance(out):
    staged = stage_runtime(out)
    files = ["/proc/sys/kernel/random/boot_id", "/proc/version", "/proc/cpuinfo",
             "/proc/self/status", "/proc/self/limits", "/proc/self/cgroup",
             "/sys/kernel/security/lsm", "/sys/kernel/security/lockdown",
             "/proc/sys/kernel/unprivileged_bpf_disabled", "/proc/sys/kernel/perf_event_paranoid",
             "/proc/sys/kernel/yama/ptrace_scope", "/proc/sys/kernel/kptr_restrict",
             "/proc/sys/net/core/bpf_jit_enable", "/proc/sys/net/core/bpf_jit_harden",
             "/proc/sys/net/core/rmem_max", "/proc/sys/net/core/wmem_max",
             "/proc/sys/net/core/rmem_default", "/proc/sys/net/core/wmem_default",
             "/etc/os-release", "/etc/apt/sources.list.d/ubuntu.sources"]
    record = {"schema": 1, "kernel": platform.uname()._asdict(),
              "runner": {key: os.environ.get(key) for key in ["ImageOS", "ImageVersion",
                          "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]},
              "files": {path: read_file(path) for path in files},
              "namespaces": {name: os.readlink(f"/proc/self/ns/{name}") for name in ["net", "pid", "mnt", "user"]},
              "btf": digest("/sys/kernel/btf/vmlinux"),
              "kernel_notes": digest("/sys/kernel/notes"),
              "kernel_config": read_file(f"/boot/config-{platform.release()}"),
              "package_status": digest("/var/lib/dpkg/status"),
              "tools": [command("clang-version"), command("cc-version"),
                        command("readelf-version"), command("uname")],
              "staged_runtime": staged,
              "source_hashes": {p.name: digest(p) for p in HERE.iterdir() if p.is_file()},
              "object_hashes": {p.name: digest(p) for p in (out / "build").iterdir() if p.is_file()},
              "tool_hashes": {p: digest(p) for p in ["/usr/bin/clang-18", "/usr/bin/cc",
                              "/usr/lib/x86_64-linux-gnu/libbpf.so.1", "/usr/bin/python3"]}}
    # The raw ELF notes contain build IDs, not packet data or kernel addresses.
    try:
        notes = Path("/sys/kernel/notes").read_bytes()
        offset, ids = 0, []
        while offset + 12 <= len(notes):
            import struct
            namesz, descsz, kind = struct.unpack_from("=III", notes, offset)
            offset += 12
            name = notes[offset:offset + namesz]
            offset += (namesz + 3) & ~3
            value = notes[offset:offset + descsz]
            offset += (descsz + 3) & ~3
            if name.rstrip(b"\0") == b"GNU" and kind == 3:
                ids.append(value.hex())
        record["kernel_build_ids"] = ids
    except OSError as error:
        record["kernel_build_ids"] = {"errno": error.errno}
    assert staged["source_hashes"] == record["source_hashes"], "staged source mismatch"
    assert staged["object_hashes"] == record["object_hashes"], "staged object mismatch"
    record["packages"] = command("packages")
    record["package_origins"] = command("package-origins")
    record["resolved_packages"] = []
    for package in PACKAGES:
        version = command("package-version", package=package)
        if version["returncode"] == 0:
            record["resolved_packages"].append(command("package-record", package=package, version=version["stdout"]))
        else:
            record["resolved_packages"].append(version)
    record["binary_build_ids"] = [command("observer-build-id"), command("pmu-build-id")]
    record["checkout"] = command("checkout")
    sources = out / "sources"
    sources.mkdir(exist_ok=True)
    for source in HERE.iterdir():
        if source.is_file():
            (sources / source.name).write_bytes(source.read_bytes())
    write(out / "provenance.json", record)


def readiness(process):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + 8
    try:
        while time.monotonic() < deadline and len(data) < 8192:
            if selector.select(0.1):
                char = os.read(process.stdout.fileno(), 1)
                if not char:
                    break
                data.extend(char)
                if char == b"\n":
                    return json.loads(data)
    finally:
        selector.close()
    raise AssertionError("observer readiness failed or exceeded 8 seconds")


def fixture_result(process, mode):
    assert process['returncode'] in (0, 1) and not process.get('truncated'), 'fixture failed to execute or capture'
    value = json.loads(process['stdout'])
    assert isinstance(value, dict) and value.get('mode') == mode, 'invalid fixture document'
    assert value.get('status') in ('supported', 'unsupported', 'error'), 'invalid fixture status'
    assert process['returncode'] == int(value['status'] == 'error'), 'fixture status/exit mismatch'
    assert all(natural(value.get(k)) for k in ('start_ns', 'end_ns')), 'invalid fixture interval'
    assert value['start_ns'] <= value['end_ns'], 'reversed fixture interval'
    if value['status'] == 'supported':
        assert isinstance(value.get('operations'), list) and value['operations'], 'missing fixture operations'
        assert isinstance(value.get('sockets'), list) and value['sockets'], 'missing fixture sockets'
    else:
        assert isinstance(value.get('reason'), str) and value['reason'], 'missing fixture failure reason'
    return value


def observer_case(out, family, mode, capacity=512, fault="normal", unprivileged=False):
    name = f"{family}-{mode}-{capacity}-{fault}{'-unprivileged' if unprivileged else ''}"
    log = out / f"{name}.log"
    args = [str(RUNTIME / "build" / "observer"), str(RUNTIME / "build" / "observer.bpf.o"),
            family, str(os.stat("/proc/self/ns/net").st_ino), str(capacity), fault]
    if unprivileged:
        args = DROP + args
    case = {"name": name, "observer_argv": args, "status": "error"}
    process = None
    try:
        with log.open("wb") as stream:
            process = subprocess.Popen(
                ["bash", "tests/performance/multi_protocol/h3_proof/commands.sh"],
                cwd=ROOT, env=command_env("observer", family=family,
                    netns=os.stat("/proc/self/ns/net").st_ino, capacity=capacity,
                    fault=fault, unprivileged="true" if unprivileged else "false"),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stream,
            )
            case["launcher_argv"] = process.args
            ready = readiness(process)
            case["ready"] = ready
            validate_observer_record(ready, family)
            assert ready['phase'] == 'ready', 'missing observer readiness'
            if ready["status"] != "supported":
                process.communicate(timeout=3)
                assert process.returncode == (1 if ready["status"] == "error" else 0)
                case.update(status=ready["status"], reason=ready["reason"])
                # Even denied/unattachable probes retain actual fixture operations.
                if fault == "normal" and not unprivileged:
                    fixture = command("fixture", mode=mode, timeout=10)
                    case["fixture_process"] = fixture
                    case["fixture"] = fixture_result(fixture, mode)
                    if fixture["returncode"] or case["fixture"]["status"] == "error":
                        case["status"] = "error"
                return case
            if fault != "normal":
                raise AssertionError("fault injection unexpectedly became supported")
            fixture = command("fixture", mode=mode, timeout=10)
            case["fixture_process"] = fixture
            case["fixture"] = fixture_result(fixture, mode)
            # A snapshot is exposed for integration, then explicit stop/final/detach.
            rest, _ = process.communicate(b"sq", timeout=5)
            case["snapshots"] = [json.loads(line) for line in rest.splitlines()]
            for row in case['snapshots']: validate_observer_record(row, family)
            assert process.returncode == 0, "observer map read or process failure"
            assert fixture["returncode"] == 0, "fixture deterministic failure"
            final = next(row for row in case["snapshots"] if row["phase"] == "final")
            assert not final['verifier_log_truncated'], 'observer diagnostics incomplete'
            case["assessment"] = assess(ready, final, case["fixture"], family, capacity == 1)
            case["status"] = case["assessment"]["status"]
    except (AssertionError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, StopIteration) as error:
        case.update(status="error", reason=type(error).__name__, detail=str(error)[:1024])
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=3)
        # Cap diagnostics even after a killed loader; redact kernel-like addresses.
        text = read_file(log, 768 * 1024)
        log.write_text(scrub(text.get("text", "")), encoding="utf-8")
        case["diagnostics_truncated"] = text.get("truncated", False)
        if text.get('error') or case['diagnostics_truncated']:
            # Keep any original load/fixture failure and its errno in ready.
            case['status'] = 'error'
            case.setdefault('reason', 'observer_diagnostics_incomplete')
        write(out / f"{name}.json", case)
    return case


def isolated(out):
    setup = [command("loopback")]
    tracefs = Path("/sys/kernel/tracing")
    if not (tracefs / "events/syscalls/sys_enter_recvmsg/id").exists():
        setup.append(command("tracefs"))
    targets = ["udp_sendmsg", "udp_send_skb", "udp_recvmsg", "run_bpf_filter",
               "reuseport_select_sock", "reuseport_attach_prog"]
    functions = read_file(tracefs / "available_filter_functions", 8 * 1024 * 1024)
    if "text" in functions:
        functions["text"] = "\n".join(line for line in functions["text"].splitlines()
                                        if line.split() and line.split()[0] in targets)
    formats = {name: read_file(tracefs / f"events/syscalls/{name}/format")
               for name in ["sys_enter_recvmsg", "sys_exit_recvmsg", "sys_enter_recvmmsg", "sys_exit_recvmmsg"]}
    write(out / "namespace.json", {"netns": os.stat("/proc/self/ns/net").st_ino,
                                    "setup": setup, "attachable_functions": functions,
                                    "tracepoint_formats": formats,
                                    "privileges": read_file("/proc/self/status")})
    if setup[0]["returncode"] != 0:
        return {"status": "unsupported", "reason": "isolated_loopback_setup", "cases": []}
    # Fixed suite, no arbitrary command, image, PID, cgroup or shell input.
    cases = []
    for family, mode in [("tx", "offload"), ("rx", "offload"),
                         ("classic", "classic-select"), ("classic", "classic-fallback"),
                         ("tx", "batches"), ("rx", "batches"), ("rx", "read-failure"),
                         ("rx", "recvmmsg-cases"), ("attach", "classic-select"), ("group", "classic-select")]:
        cases.append(observer_case(out, family, mode))
    cases.append(observer_case(out, "rx", "offload", capacity=1))
    cases.append(observer_case(out, "rx", "offload", fault="missing-btf"))
    cases.append(observer_case(out, "rx", "offload", fault="missing-symbol"))
    cases.append(observer_case(out, "rx", "offload", unprivileged=True))
    pmu = {"observer_privilege": command("pmu-observer"),
           "fixture_privilege": command("pmu-fixture")}
    write(out / "pmu.json", pmu)
    pmu_error = any(value["returncode"] != 0 for value in pmu.values())
    statuses = [case["status"] for case in cases[:7]]
    status = "error" if pmu_error or any(c["status"] == "error" for c in cases) else (
        "unsupported" if all(s == "unsupported" for s in statuses) else "partial_coverage")
    return {"schema": 1, "status": status, "cases": [{"name": c["name"], "status": c["status"]} for c in cases],
            "fixture_only": True, "issue_5588_closed": False,
            "unimplemented": ["IPv6", "read_recvfrom_RX_attribution", "compat_syscalls",
                              "gateway_process_lineage_and_socket_retirement", "gateway_role_peer_join",
                              "observer_overhead_calibration", "five_payload_four_pair_campaign"],
            "pmu_independent_of_socket_probe_status": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--suite", choices=["capability-v1"], default="capability-v1")
    parser.add_argument("--isolated", action="store_true")
    args = parser.parse_args()
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Linux" or os.environ.get("RUNNER_ARCH") != "X64"
            or platform.system() != "Linux" or platform.machine() != "x86_64"):
        parser.error("this entrypoint is exclusively for Linux amd64 GitHub-hosted execution")
    if os.geteuid() != 0:
        parser.error("the hosted driver requires root; fixtures drop all privileges separately")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.isolated:
        if ROOT != RUNTIME:
            parser.error("isolated execution requires the staged runtime")
        summary = isolated(out)
        write(out / "summary.json", summary)
        return int(summary["status"] == "error")
    provenance(out)
    write(out / "summary.json", {"schema": 1, "status": "error", "reason": "isolation_not_completed",
                                 "fixture_only": True, "issue_5588_closed": False})
    # Fixtures inherit only namespace placement; setpriv removes ALL capabilities.
    result = command("isolate", output=str(out), timeout=210)
    write(out / "isolation-process.json", result)
    summary_path = out / "summary.json"
    if json.loads(summary_path.read_text()).get("reason") == "isolation_not_completed":
        denied = result["returncode"] == 1 and "Operation not permitted" in result.get("stderr", "")
        write(summary_path, {"schema": 1, "status": "unsupported" if denied else "error",
                             "reason": "network_mount_namespace_denied" if denied else "driver_failed",
                             "fixture_only": True, "issue_5588_closed": False})
    summary = json.loads(summary_path.read_text())
    if result["returncode"] != 0 and summary["status"] != "unsupported":
        summary.update(status="error", reason="isolated_process_failed")
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    if size > 64 * 1024 * 1024:
        summary.update(status="error", reason="artifact_size_exceeded_64_MiB")
    summary["artifact_bytes_before_summary_update"] = size
    write(summary_path, summary)
    return int(summary["status"] == "error")


if __name__ == "__main__":
    raise SystemExit(main())
