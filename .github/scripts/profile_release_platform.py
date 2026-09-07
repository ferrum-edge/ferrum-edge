#!/usr/bin/env python3
"""Nonpublishing release-build telemetry; run only on hosted study runners."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest

TARGETS = {
    "x86_64-apple-darwin": "Darwin",
    "aarch64-apple-darwin": "Darwin",
    "x86_64-pc-windows-msvc": "Windows",
}
TOOLCHAIN = "1.98.1"
PROFILE = {"opt-level": 3, "lto": "fat", "codegen-units": 1,
           "strip": True, "incremental": False, "panic": "abort"}


def mac_processes(raw):
    result = []
    for line in raw.splitlines():
        pid, parent, rss, name = line.split(None, 3)
        result.append({"pid": int(pid), "parent": int(parent),
                       "rss_bytes": int(rss) * 1024, "name": name})
    return result


def windows_processes(rows):
    return [{"pid": int(p["ProcessId"]), "parent": int(p["ParentProcessId"]),
             "rss_bytes": int(p["WorkingSetSize"]), "name": p["Name"]}
            for p in rows]


def descendants(rows, root):
    by_pid = {row["pid"]: row for row in rows}
    if root not in by_pid:
        return []
    selected = {root}
    while True:
        children = {p["pid"] for p in rows if p["parent"] in selected}
        expanded = selected | children
        if expanded == selected:
            return [by_pid[pid] for pid in sorted(selected)]
        selected = expanded


def snapshot():
    if platform.system() == "Darwin":
        rows = mac_processes(subprocess.check_output(["ps", "-axo", "pid=,ppid=,rss=,comm="], text=True, timeout=20))
        host = {"vm_stat": subprocess.check_output(["vm_stat"], text=True, timeout=20),
                "swap": subprocess.check_output(["sysctl", "vm.swapusage"], text=True, timeout=20)}
        return rows, host
    raw = subprocess.check_output(
        ["pwsh", "-NoProfile", "-File", ".github/scripts/release_platform_windows.ps1", "-Mode", "Memory"],
        text=True, timeout=20)
    data = json.loads(raw)
    return windows_processes(data["processes"]), data["memory"]


def timing_units(html):
    marker = "const UNIT_DATA = "
    if marker not in html:
        raise ValueError("Cargo unit timing data missing")
    units, _ = json.JSONDecoder().raw_decode(html.split(marker, 1)[1])
    if not isinstance(units, list) or not units:
        raise ValueError("Cargo unit timing list empty")
    for unit in units:
        for key in ("start", "duration"):
            value = unit[key]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("Invalid Cargo unit time")
        for _, section in unit.get("sections") or []:
            start, end = section["start"], section["end"]
            if not (math.isfinite(start) and math.isfinite(end)
                    and 0 <= start <= end <= unit["duration"] + 0.02):
                raise ValueError("Invalid Cargo unit section")
    return units


def verify_toolchain(rust, cargo, installed, target):
    if f"release: {TOOLCHAIN}" not in rust.splitlines():
        raise ValueError("Active rustc differs from the study toolchain")
    if cargo.split()[:2] != ["cargo", TOOLCHAIN]:
        raise ValueError("Active Cargo differs from the study toolchain")
    if target not in installed.splitlines():
        raise ValueError("Study target missing from the active toolchain")


def retain_timings(source, output):
    if not source.exists():
        return None
    shutil.copyfile(source, output / "cargo-timing.html")
    units = timing_units(source.read_text())
    (output / "units.json").write_text(json.dumps(units, indent=2) + "\n")
    return units


def stop_tree(child):
    if child.poll() is not None:
        return
    if platform.system() == "Windows":
        # The fixed PowerShell program treats the owned PID only as numeric data.
        kill_env = os.environ.copy()
        kill_env["FERRUM_STUDY_CHILD_PID"] = str(child.pid)
        subprocess.run(["pwsh", "-NoProfile", "-File",
                        ".github/scripts/release_platform_windows.ps1", "-Mode", "Stop"],
                       env=kill_env, check=False, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    child.wait(timeout=20)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def profile_build(target, output):
    if platform.system() != TARGETS[target]:
        raise ValueError("Study target does not match this runner OS")
    manifest = tomllib.loads(Path("Cargo.toml").read_text())
    if any(manifest["profile"]["release"].get(k) != v for k, v in PROFILE.items()):
        raise ValueError("Shipping profile differs from the measured baseline")
    if any(k.startswith("CARGO_PROFILE_RELEASE_") for k in os.environ):
        raise ValueError("Release profile environment overrides are not permitted")
    rust = subprocess.check_output(["rustc", "-Vv"], text=True, timeout=20).strip()
    cargo = subprocess.check_output(["cargo", "-V"], text=True, timeout=20).strip()
    installed = subprocess.check_output(
        ["rustup", "target", "list", "--installed", "--toolchain", "1.98.1"],
        text=True, timeout=20).strip()
    verify_toolchain(rust, cargo, installed, target)
    output.mkdir(parents=True, exist_ok=True)
    target_dir = Path(tempfile.mkdtemp(prefix="release-platform-", dir=os.environ["RUNNER_TEMP"]))
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target_dir), RUSTC_WRAPPER="",
               CARGO_BUILD_RUSTC_WRAPPER="")
    command = ["cargo", "build", "--release", "--features", "cloud-secrets",
               "--target", target, "--locked", "--timings"]
    provenance = {
        "sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=20).strip(),
        "rust": rust, "cargo": cargo, "installed_targets": installed.splitlines(),
        "platform": platform.platform(), "machine": platform.machine(),
        "target": target, "command": command, "profile": manifest["profile"]["release"],
        "cargo_config_sha256": digest(Path(".cargo/config.toml")),
        "deployment_target": os.environ.get("MACOSX_DEPLOYMENT_TARGET"),
        "rustflags": os.environ.get("RUSTFLAGS"),
        "cache": "empty target and disabled compiler wrappers; no cache publication",
    }
    if platform.system() == "Darwin":
        provenance["cpu"] = subprocess.check_output(["sysctl", "machdep.cpu.brand_string", "hw.memsize", "hw.ncpu"], text=True, timeout=20).strip()
    else:
        provenance["cpu"] = subprocess.check_output(
            ["pwsh", "-NoProfile", "-File", ".github/scripts/release_platform_windows.ps1", "-Mode", "Cpu"],
            text=True, timeout=20).strip()
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    start = time.monotonic()
    samples, errors, peak = 0, 0, None
    result = {"build_complete": False, "validation_complete": False, "target": target}
    try:
        with (output / "build.log").open("wb") as log, (output / "memory.jsonl").open("w") as memory:
            if target == "x86_64-apple-darwin":
                child = subprocess.Popen(
                    ["cargo", "build", "--release", "--features", "cloud-secrets",
                     "--target", "x86_64-apple-darwin", "--locked", "--timings"],
                    env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            elif target == "aarch64-apple-darwin":
                child = subprocess.Popen(
                    ["cargo", "build", "--release", "--features", "cloud-secrets",
                     "--target", "aarch64-apple-darwin", "--locked", "--timings"],
                    env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            else:
                child = subprocess.Popen(
                    ["cargo", "build", "--release", "--features", "cloud-secrets",
                     "--target", "x86_64-pc-windows-msvc", "--locked", "--timings"],
                    env=env, stdout=log, stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            finished = threading.Event()
            completion = {}

            def wait_for_build():
                try:
                    try:
                        completion["exit_code"] = child.wait(timeout=150 * 60)
                    except subprocess.TimeoutExpired:
                        completion["timed_out"] = True
                        stop_tree(child)
                        completion["exit_code"] = child.wait()
                except Exception as error:
                    completion["observer_error"] = str(error)
                finally:
                    completion["wall_seconds"] = time.monotonic() - start
                    finished.set()

            waiter = threading.Thread(target=wait_for_build, daemon=True)
            waiter.start()
            try:
                while not finished.is_set():
                    elapsed = time.monotonic() - start
                    try:
                        rows, host = snapshot()
                        tree = descendants(rows, child.pid)
                        rss = sum(p["rss_bytes"] for p in tree)
                        if tree:
                            samples += 1
                            peak = max(peak or 0, rss)
                        observation = {"elapsed_seconds": elapsed, "processes": tree,
                                       "tree_rss_bytes": rss if tree else None, "host": host}
                    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                        errors += 1
                        observation = {"elapsed_seconds": elapsed, "sampling_error": str(error)}
                    memory.write(json.dumps(observation) + "\n")
                    memory.flush()
                    print(f"Build elapsed={elapsed:.0f}s samples={samples} sampled_peak_rss={peak}", flush=True)
                    finished.wait(10)
                waiter.join(timeout=30)
                if not finished.is_set():
                    raise RuntimeError("Cargo completion observer did not finish")
                if "observer_error" in completion:
                    raise RuntimeError(completion["observer_error"])
                result.update(exit_code=completion["exit_code"],
                              build_wall_seconds=completion["wall_seconds"],
                              timed_out=completion.get("timed_out", False))
            finally:
                stop_tree(child)
        result.update(build_complete=True,
                      sampled_peak_tree_rss_bytes=peak, memory_samples=samples,
                      sampling_errors=errors)
        units = None
        try:
            units = retain_timings(target_dir / "cargo-timings/cargo-timing.html", output)
        except (OSError, ValueError, KeyError, TypeError) as error:
            result["timing_error"] = str(error)
        result["timing_report_available"] = (output / "cargo-timing.html").is_file()
        if result.get("timed_out") or result["exit_code"] != 0:
            return 124 if result.get("timed_out") else result["exit_code"]
        if units is None:
            raise ValueError("Successful build has no valid Cargo timing data")
        binary = target_dir / target / "release" / ("ferrum-edge.exe" if platform.system() == "Windows" else "ferrum-edge")
        result.update(binary_bytes=binary.stat().st_size, binary_sha256=digest(binary))
        # Keep generated executables outside the checkout. Explicit workflow
        # steps perform the host smoke check after these measurements validate.
        smoke_dir = Path(os.environ["RUNNER_TEMP"]) / "ferrum-platform-study"
        smoke_dir.mkdir(exist_ok=True)
        shutil.copy2(binary, smoke_dir / binary.name)
        if platform.system() == "Darwin":
            load_commands = subprocess.check_output(["otool", "-l", "ferrum-edge"],
                                                    cwd=binary.parent, text=True, timeout=20)
            (output / "load-commands.txt").write_text(load_commands)
        if not samples:
            raise ValueError("No process-tree memory samples captured")
        rows = ["# Platform release build", "", f"Target: {target}",
                f"Build wall time: {result['build_wall_seconds']:.2f}s",
                f"Sampled peak process-tree RSS: {peak} bytes", "",
                "The ten-second samples are lower bounds on peak memory; shared pages may be counted repeatedly.",
                "Units overlap in wall time. Codegen sections do not isolate LLVM optimization from final linking.",
                "Build-script execution may include native builds but is not exclusively native compilation.", "",
                "| Longest Cargo units | Target | Seconds |", "| --- | --- | ---: |"]
        for unit in sorted(units, key=lambda u: u["duration"], reverse=True)[:20]:
            rows.append(f"| {unit['name']} | {unit['target']} | {unit['duration']:.2f} |")
        (output / "summary.md").write_text("\n".join(rows) + "\n")
        result["validation_complete"] = True
        return 0
    finally:
        result.update(wall_seconds=time.monotonic() - start,
                      sampled_peak_tree_rss_bytes=peak, memory_samples=samples,
                      sampling_errors=errors)
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")


class Contracts(unittest.TestCase):
    @unittest.skipUnless(platform.system() in {"Darwin", "Windows"}, "native telemetry runner required")
    def test_native_snapshot_records_the_owned_python_process(self):
        rows, host = snapshot()
        owned = [row for row in rows if row["pid"] == os.getpid()]
        self.assertEqual(len(owned), 1)
        self.assertGreater(owned[0]["rss_bytes"], 0)
        self.assertTrue(host)

    def test_wrong_active_compiler_and_missing_target_are_rejected(self):
        target = "x86_64-apple-darwin"
        verify_toolchain(f"rustc metadata\nrelease: {TOOLCHAIN}", f"cargo {TOOLCHAIN} (hash)", target, target)
        for rust, cargo, installed in (
            ("release: 1.97.1", f"cargo {TOOLCHAIN}", target),
            (f"release: {TOOLCHAIN}", "cargo 1.97.1", target),
            (f"release: {TOOLCHAIN}", f"cargo {TOOLCHAIN}", "aarch64-apple-darwin"),
        ):
            with self.assertRaises(ValueError):
                verify_toolchain(rust, cargo, installed, target)

    def test_partial_timing_report_is_copied_before_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "partial.html"
            output = root / "evidence"
            output.mkdir()
            source.write_text("incomplete Cargo timing report")
            with self.assertRaises(ValueError):
                retain_timings(source, output)
            self.assertEqual((output / "cargo-timing.html").read_text(), source.read_text())

    def test_stop_tree_terminates_an_owned_process(self):
        child = subprocess.Popen(["python", "-c", "import time; time.sleep(60)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=platform.system() != "Windows",
                                 creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP
                                                if platform.system() == "Windows" else 0))
        try:
            stop_tree(child)
            self.assertIsNotNone(child.poll())
            self.assertNotEqual(child.returncode, 0)
        finally:
            stop_tree(child)

    def test_tree_excludes_siblings_and_handles_out_of_order_children(self):
        rows = mac_processes("12 11 3 compiler\n20 1 99 unrelated\n10 1 1 cargo\n11 10 2 shell")
        tree = descendants(rows, 10)
        self.assertEqual([r["pid"] for r in tree], [10, 11, 12])
        self.assertEqual(sum(r["rss_bytes"] for r in tree), 6 * 1024)
        self.assertEqual(descendants(rows, 99), [])

    def test_parent_cycle_cannot_repeat_or_include_an_unrelated_process(self):
        rows = mac_processes("10 11 1 cargo\n11 10 2 compiler\n20 1 99 unrelated")
        self.assertEqual([r["pid"] for r in descendants(rows, 10)], [10, 11])

    def test_windows_units_remain_bytes(self):
        rows = windows_processes([{"ProcessId": 7, "ParentProcessId": 1,
                                  "Name": "cargo.exe", "WorkingSetSize": "4096"}])
        self.assertEqual(descendants(rows, 7)[0]["rss_bytes"], 4096)

    def test_missing_and_nonfinite_timings_fail(self):
        unit = {"start": 0, "duration": 2, "sections": [["frontend", {"start": 0, "end": 1}]]}
        self.assertEqual(timing_units("const UNIT_DATA = " + json.dumps([unit]) + ";"), [unit])
        for raw in ("", "const UNIT_DATA = []", 'const UNIT_DATA = [{"start":0,"duration":NaN}]',
                    'const UNIT_DATA = [{"start":0,"duration":-1}]'):
            with self.assertRaises(ValueError):
                timing_units(raw)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--output", type=Path, default=Path("study-results"))
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    if not args.target:
        parser.error("--target is required")
    raise SystemExit(profile_build(args.target, args.output))
