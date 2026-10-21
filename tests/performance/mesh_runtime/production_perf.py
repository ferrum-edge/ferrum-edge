#!/usr/bin/env python3
"""Optional hosted-only leaf-IP CPU profiles for exactly two mesh sidecars.

No kernel settings, global build-id caches, callchains, frame-pointer changes,
source-line attribution, or inclusive/async-task accounting. Host marker receipt
bounds have scheduler/pipe jitter. The ordinary ranking never imports this helper.
"""
from __future__ import annotations

from collections import Counter
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time

RAW_BYTES = 64 * 1024**2
DSO_BYTES = 1024**3
METADATA_BYTES = 16 * 1024**2
CAPTURE_SECONDS = 300
FREQUENCY = 49
KNOWN_FRACTION = 0.80
HERE = Path(__file__).resolve().parent
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEADER = re.compile(r"^\s*(.*?)\s+(\d+)/(\d+)\s+(\d+\.\d+):\s+(cpu-clock(?::[ukhS]+)?):\s*(.*?)\s*$")
LEAF = re.compile(r"^(?:0x)?([0-9a-fA-F]+)\s+(.+?)\s+\((.*?)\)\s*$")
RECORD = re.compile(r"\b(PERF_RECORD_[A-Z0-9_]+)\b")


def write(path, value):
    temporary = Path(path).with_suffix(Path(path).suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def sha256(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            result.update(block)
    return result.hexdigest()


def elf_reader():
    # Reuse the already reviewed bounded ELF64 identity parser. Importing this
    # module does not construct its registry client or perform any network I/O.
    path = HERE.parents[2] / ".github/scripts/mesh_production_profile_symbols.py"
    spec = importlib.util.spec_from_file_location("mesh_perf_elf_identity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Elf


def immutable_stat(info):
    # Reads may update atime; they must not be mistaken for source mutation.
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def process_identity(pid, proc=Path("/proc")):
    base = proc / str(pid)
    raw = (base / "stat").read_text()
    start = int(raw.rsplit(")", 1)[1].split()[19])
    executable = os.readlink(base / "exe")
    result = {"pid": pid, "starttime": start, "exe": executable,
              "exe_sha256": sha256(base / "exe"),
              "boot_id": (proc / "sys/kernel/random/boot_id").read_text().strip(),
              "namespaces": {name: (base / "ns" / name).stat().st_ino for name in ("pid", "mnt", "net", "time")},
              "clock": "CLOCK_MONOTONIC", "monotonic": time.monotonic()}
    if int((base / "stat").read_text().rsplit(")", 1)[1].split()[19]) != start:
        raise ValueError("PID generation changed during identity capture")
    return result


def same_identity(left, right):
    return all(left[key] == right[key] for key in ("pid", "starttime", "exe", "exe_sha256", "boot_id", "namespaces"))


def inspect(name):
    value = json.loads(subprocess.check_output(["docker", "inspect", name], timeout=5))[0]
    if not value["State"].get("Running") or not IMAGE.fullmatch(value.get("Image", "")):
        raise ValueError("sidecar not running or missing immutable Docker image ID")
    return {"name": name, "pid": value["State"]["Pid"], "image_id": value["Image"],
            "container_id": value["Id"], "image_ref": value["Config"]["Image"]}


def executable_maps(text):
    if len(text.encode()) > 1024**2:
        raise ValueError("maps metadata exceeds 1 MiB")
    mappings, virtual = {}, []
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 2 or "x" not in fields[1]:
            continue
        if len(fields) != 6 or not fields[5].startswith("/"):
            virtual.append(line)
            continue
        path = fields[5]
        if path.endswith(" (deleted)") or ".." in Path(path).parts:
            raise ValueError("deleted/unsafe executable mapping")
        major, minor = (int(v, 16) for v in fields[3].split(":"))
        record = {"path": path, "device_major": major, "device_minor": minor, "inode": int(fields[4])}
        if record["inode"] <= 0 or (path in mappings and mappings[path] != record):
            raise ValueError("inconsistent executable mapping identity")
        mappings[path] = record
    if len(mappings) > 256:
        raise ValueError("mapped DSO count exceeds 256")
    return list(mappings.values()), virtual


@contextlib.contextmanager
def mapped_fd(root, mapping):
    # Same strict technique as h1_trace.mapped_elf_fd: reject every symlink,
    # pin with O_PATH, check mapped dev/inode, then reopen that exact regular FD.
    # No fallback to a similarly named runner library is permitted.
    path = Path(mapping["path"])
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe mapped path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    pin = readable = None
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        pin = os.open(path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
        info = os.fstat(pin)
        expected = mapping["device_major"], mapping["device_minor"], mapping["inode"]
        if not stat.S_ISREG(info.st_mode) or (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino) != expected:
            raise ValueError("mapped inode replaced or nonregular")
        readable = os.open(f"/proc/self/fd/{pin}", os.O_RDONLY | os.O_NONBLOCK)
        if immutable_stat(os.fstat(readable)) != immutable_stat(info):
            raise ValueError("mapped inode changed before read")
        yield readable
    finally:
        if readable is not None:
            os.close(readable)
        if pin is not None:
            os.close(pin)
        os.close(directory)


def qualify_symbols(actual, candidate, Elf):
    # Explicit Ferrum/Envoy companions can have extra unallocated symbols,
    # but the GNU build ID, allocated sections, entry, and code layout must agree.
    if candidate.is_symlink() or not candidate.is_file() or not 0 < candidate.stat().st_size <= 4 * 1024**3:
        raise ValueError("missing/unsafe/oversize supplied symbol ELF")
    actual_sha, candidate_sha = sha256(actual), sha256(candidate)
    left, right = Elf(actual), Elf(candidate)
    try:
        build_id = left.build_id()
        if not build_id or right.build_id() != build_id:
            raise ValueError("symbol ELF build ID mismatch")
        if (left.kind, left.entry) != (right.kind, right.entry) or left.allocated() != right.allocated():
            raise ValueError("symbol ELF allocated code/data mismatch")
        segments = left.executable_segments()
        if not segments or segments != right.executable_segments() or right.functions() <= 0:
            raise ValueError("symbol ELF executable segment/function mismatch")
        return {"path": str(candidate), "sha256": candidate_sha, "build_id": build_id,
                "exact_elf_sha_match": actual_sha == candidate_sha,
                "binding": "same build ID, allocated sections, executable segments, entry/type",
                "source_lines_verified": False}
    finally:
        left.close()
        right.close()


def record_argv(perf, pid, directory):
    return [perf, "record", "-e", "cpu-clock:u", "-F", str(FREQUENCY), "--clockid", "mono",
            "--mmap-pages=64", "--timestamp", "--sample-cpu", "--buildid-all", "--buildid-mmap",
            "--no-buildid-cache", "--no-bpf-event", "--strict-freq", "--synth=mmap", "--delay=-1",
            "--max-size=64M", f"--control=fifo:{directory}/perf.control,{directory}/perf.ack",
            "-p", str(pid), "-o", str(directory / "perf.data")]


def validate_attributes(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = []
    if len(lines) != 1 or not lines[0].startswith("cpu-clock:u:"):
        return ["expected exactly one cpu-clock:u event"]
    line = lines[0]
    required = {"type": 1, "config": 0, "freq": 1, "inherit": 1, "exclude_kernel": 1,
                "use_clockid": 1, "clockid": 1}
    for key, expected in required.items():
        match = re.search(rf"(?:^|[, ]){key}\s*:\s*(0x[0-9a-fA-F]+|[0-9]+)\b", line)
        if not match or int(match[1], 16 if match[1].startswith("0x") else 10) != expected:
            errors.append(f"unexpected/missing event attribute {key}")
    frequency = re.search(r"\{\s*sample_period\s*,\s*sample_freq\s*\}\s*:\s*(\d+)", line)
    if not frequency or int(frequency[1]) != FREQUENCY:
        errors.append("actual frequency is not 49 Hz")
    sample = re.search(r"sample_type\s*:\s*([A-Z_|]+)", line)
    bits = set(sample[1].split("|")) if sample else set()
    if not {"IP", "TID", "TIME"} <= bits or bits & {"CALLCHAIN", "STACK_USER", "REGS_USER"}:
        errors.append("not a timestamped leaf-IP-only sample selection")
    for bit in ("exclude_user", "exclude_callchain_user", "exclude_callchain_kernel"):
        match = re.search(rf"\b{bit}\s*:\s*(\d+)", line)
        if bit == "exclude_user" and match and int(match[1]) != 0:
            errors.append("user samples excluded")
    return errors


def parse_leaves(text, pid, begin, end, retained_paths):
    if not all(type(v) in (float, int) and math.isfinite(v) for v in (begin, end)) or not begin < end:
        raise ValueError("invalid finite monotonic measurement bracket")
    aliases = {}
    for path in retained_paths:
        aliases.setdefault(Path(path).name, set()).add(path)
    counts, events, raw_lines = Counter(), [], []
    foreign = malformed = all_samples = outside = 0
    for line in text.splitlines():
        header = HEADER.match(line)
        if not header:
            if re.search(r"\d+\.\d+:\s+cpu-clock", line):
                malformed += 1
            continue
        all_samples += 1
        owner, tid, when = int(header[2]), int(header[3]), float(header[4])
        foreign += owner != pid
        if not begin <= when <= end:
            outside += 1
            continue
        leaf = LEAF.fullmatch(header[6])
        symbol, dso, ip = "UNKNOWN", "UNKNOWN", None
        if leaf:
            ip, original, displayed = leaf.groups()
            candidates = {displayed} if displayed in retained_paths else aliases.get(Path(displayed).name, set())
            if len(candidates) == 1 and owner == pid and int(ip, 16) != 0 and original not in ("[unknown]", "[unknown]!", "0x0") and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", original):
                dso = next(iter(candidates))
                symbol = re.sub(r"\+0x[0-9a-fA-F]+$", "", original)
        else:
            malformed += 1
        counts[(dso, symbol)] += 1
        events.append({"pid": owner, "tid": tid, "monotonic": when, "ip": ip,
                       "dso": dso, "symbol": symbol, "known": symbol != "UNKNOWN"})
        raw_lines.append(line)
    total = len(events)
    unknown = sum(value for (dso, symbol), value in counts.items() if symbol == "UNKNOWN")
    return {"all_capture_sample_count": all_samples, "measurement_sample_count": total,
            "outside_window_samples": outside, "foreign_pid_samples": foreign,
            "malformed_samples": malformed, "unknown_leaves": unknown, "known_leaves": total - unknown,
            "known_leaf_fraction": (total - unknown) / total if total else 0.0,
            "functions": [{"dso": dso, "symbol": symbol, "samples": count,
                           "fraction_all_measurement_leaves": count / total if total else 0.0}
                          for (dso, symbol), count in counts.most_common()],
            "events": events, "raw_window_lines": raw_lines}


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (RAW_BYTES, RAW_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Kill the attached perf recorder if its owning collector disappears.
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
        os._exit(125)


class PerfCapture:
    def __init__(self, containers, outputdir, symbol_elf_paths):
        if len(containers) != 2 or len({c["pid"] for c in containers}) != 2:
            raise ValueError("leaf capture requires two distinct sidecar processes")
        self.containers = [dict(c, role=c.get("role", role)) for c, role in zip(containers, ("source", "destination"))]
        if {c["role"] for c in self.containers} != {"source", "destination"}:
            raise ValueError("expected source and destination roles")
        if any(not IMAGE.fullmatch(c.get("image_id", "")) or type(c["pid"]) is not int or c["pid"] <= 1 for c in containers):
            raise ValueError("sidecar PID and immutable image IDs required")
        self.output = Path(outputdir).absolute()
        self.symbol_paths, self.symbol_reports = [], {}
        for source in symbol_elf_paths:
            path = Path(source["path"] if isinstance(source, dict) else source).absolute()
            self.symbol_paths.append(path)
            if isinstance(source, dict) and source.get("qualification_report"):
                self.symbol_reports[path] = Path(source["qualification_report"]).absolute()
        self.roles, self.blobs, self.retained_bytes = [], {}, 0
        self.stop_event = threading.Event()
        self.monitor = None
        self.started = self.stopped = False
        self.perf = shutil.which("perf") or "/usr/bin/perf"
        self.report = {"schema_version": 1, "valid": False, "errors": [], "roles": [],
            "event": "cpu-clock:u", "frequency_hz": FREQUENCY, "clock": "CLOCK_MONOTONIC",
            "raw_bytes_per_role_cap": RAW_BYTES, "mapped_elf_total_bytes_cap": DSO_BYTES,
            "capture_wall_seconds_cap": CAPTURE_SECONDS, "required_known_leaf_fraction": KNOWN_FRACTION,
            "scope": "per-role raw user CPU leaf samples; no callchains, async-inclusive accounting or source-line claims",
            "window": "host receipt of loadgen measurement markers; includes pipe/scheduler delivery jitter"}

    def environment(self):
        return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": str(self.output / "home"),
                "XDG_CONFIG_HOME": str(self.output / "home/config"), "PERF_CONFIG": "/dev/null",
                "PERF_BUILDID_DIR": str(self.output / "buildid-cache"), "DEBUGINFOD_URLS": ""}

    def persist(self):
        self.report["roles"] = [r["report"] for r in self.roles]
        self.report["retained_unique_mapped_elf_bytes"] = self.retained_bytes
        write(self.output / "capture.json", self.report)
        try:
            self.publish_artifacts()
        except (OSError, ValueError) as error:
            self.report["errors"].append(f"artifact handoff: {type(error).__name__}: {error}")
            self.report["valid"] = False
            write(self.output / "capture.json", self.report)

    def publish_artifacts(self):
        # Only our root/role directories and fixed public top-level files.
        # Never recurse into ELF/symfs/cache/home, follow a link, or modify a
        # hard link to a checkout/companion file. Raw events contain leaf IPs,
        # not sampled stack/register/heap/packet bytes.
        names = {"capture.json", "perf.data", "perf-record.stderr", "attributes.txt", "attributes.txt.stderr",
                 "record-types.txt", "record-types.txt.stderr", "buildids.txt", "buildids.txt.stderr",
                 "leaf-events-all.txt", "leaf-events-all.txt.stderr", "leaf-events-window.txt", "leaf-events-window.jsonl"}
        for directory in [self.output, *(role["directory"] for role in self.roles)]:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if os.fstat(fd).st_uid != os.geteuid():
                    raise ValueError("artifact directory not owned by collector")
                os.fchmod(fd, 0o755)
                for name in names:
                    try:
                        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid():
                        continue
                    file = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        current = os.fstat(file)
                        if (current.st_dev, current.st_ino, current.st_nlink, current.st_uid) != (before.st_dev, before.st_ino, 1, os.geteuid()):
                            raise ValueError("artifact changed during public handoff")
                        os.fchmod(file, 0o644)
                    finally:
                        os.close(file)
            finally:
                os.close(fd)

    def checked_identity(self, container):
        current = inspect(container["name"])
        if any(current[key] != container[key] for key in ("pid", "image_id")):
            raise ValueError("sidecar PID/image changed from caller's pinned identity")
        identity = process_identity(container["pid"])
        if identity["namespaces"]["time"] != Path("/proc/self/ns/time").stat().st_ino:
            raise ValueError("sidecar and collector time namespaces differ")
        return dict(current, process=identity)

    def retain(self, role):
        pid = role["container"]["pid"]
        text = Path(f"/proc/{pid}/maps").read_text()
        maps, virtual = executable_maps(text)
        role["report"]["virtual_executable_mappings"] = virtual
        deadline = time.monotonic() + 60
        for mapping in maps:
            if mapping["path"] in role["mappings"]:
                if any(role["mappings"][mapping["path"]][key] != mapping[key] for key in ("device_major", "device_minor", "inode")):
                    raise ValueError("mapped DSO identity changed during capture")
                continue
            with mapped_fd(f"/proc/{pid}/root", mapping) as fd:
                info = os.fstat(fd)
                if not 4 <= info.st_size <= DSO_BYTES or time.monotonic() >= deadline:
                    raise ValueError("mapped ELF retention size/deadline")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    if stream.read(4) != b"\x7fELF":
                        raise ValueError("executable mapped file is not ELF")
                    stream.seek(0)
                    digest = hashlib.sha256()
                    for block in iter(lambda: stream.read(1024**2), b""):
                        if time.monotonic() >= deadline:
                            raise ValueError("mapped ELF hash deadline")
                        digest.update(block)
                    digest = digest.hexdigest()
                    blob = self.output / "elfs" / (digest + ".elf")
                    if digest not in self.blobs:
                        if self.retained_bytes + info.st_size > DSO_BYTES:
                            raise ValueError("mapped ELF package exceeds 1 GiB")
                        stream.seek(0)
                        with blob.open("xb") as target:
                            copied = 0
                            while copied < info.st_size:
                                if time.monotonic() >= deadline:
                                    raise ValueError("mapped ELF copy deadline")
                                block = stream.read(min(1024**2, info.st_size - copied))
                                if not block:
                                    raise ValueError("mapped ELF truncated")
                                target.write(block)
                                copied += len(block)
                        self.retained_bytes += info.st_size
                        self.blobs[digest] = blob
                if immutable_stat(os.fstat(fd)) != immutable_stat(info) or sha256(blob) != digest:
                    raise ValueError("mapped ELF changed during acquisition")
            elf = self.Elf(blob)
            try:
                build_id = elf.build_id()
            finally:
                elf.close()
            if not build_id:
                raise ValueError("mapped ELF lacks GNU build ID")
            retained = dict(mapping, sha256=digest, bytes=info.st_size, build_id=build_id, blob=str(blob))
            symbol = blob
            if digest == role["report"]["identity_before"]["process"]["exe_sha256"]:
                matches = []
                for candidate in self.symbol_paths:
                    try:
                        binding = qualify_symbols(blob, candidate, self.Elf)
                        provenance = self.symbol_reports.get(candidate)
                        if provenance is not None:
                            if provenance.is_symlink() or not provenance.is_file() or not 0 < provenance.stat().st_size <= METADATA_BYTES:
                                raise ValueError("unsafe/oversize symbol qualification provenance")
                            binding["qualification_report"] = {"path": str(provenance), "sha256": sha256(provenance),
                                "scope": "upstream report retained by caller; local code/build-ID gate enforced independently"}
                        matches.append(binding)
                    except ValueError:
                        continue
                if self.symbol_paths and not matches:
                    raise ValueError("no supplied symbol ELF matches actual executable code/build ID")
                if matches:
                    role["report"]["symbol_binding"] = matches[0]
                    symbol = Path(matches[0]["path"])
            destination = role["directory"] / "symfs" / mapping["path"].lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(symbol)
            cached = self.output / "buildid-cache/.build-id" / build_id[:2] / build_id[2:]
            cached.parent.mkdir(parents=True, exist_ok=True)
            if not cached.exists():
                # perf supports this original regular-file build-id cache form.
                # A verified ELF link avoids copying multi-GiB companions.
                cached.symlink_to(symbol)
            role["mappings"][mapping["path"]] = retained
        role["report"]["mapped_elfs"] = list(role["mappings"].values())
        if not any(item["sha256"] == role["report"]["identity_before"]["process"]["exe_sha256"] for item in role["mappings"].values()):
            raise ValueError("actual process executable not present in retained mappings")

    def start(self):
        if self.started:
            raise ValueError("capture start already attempted")
        self.started = True
        self.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name in ("elfs", "buildid-cache", "home"):
            (self.output / name).mkdir(mode=0o700)
        try:
            self.Elf = elf_reader()
            for container in self.containers:
                directory = self.output / container["role"]
                directory.mkdir(mode=0o700)
                role = {"container": container, "directory": directory, "process": None, "handles": [], "fifo": {},
                        "mappings": {}, "report": {"role": container["role"], "errors": [], "identity_before": self.checked_identity(container)}}
                self.roles.append(role)
                self.retain(role)
                for name in ("perf.control", "perf.ack"):
                    path = directory / name
                    os.mkfifo(path, 0o600)
                    role["fifo"][name] = (os.open(path, os.O_RDWR | os.O_NONBLOCK), path.stat().st_ino)
                stderr = (directory / "perf-record.stderr").open("wb")
                role["handles"].append(stderr)
                argv = record_argv(self.perf, container["pid"], directory)
                role["report"]["record_argv"] = argv
                if not same_identity(role["report"]["identity_before"]["process"], self.checked_identity(container)["process"]):
                    raise ValueError("sidecar process changed before attaching perf")
                role["process"] = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=stderr,
                    env=self.environment(), start_new_session=True, preexec_fn=child_limits)
                role["started_at"] = time.monotonic()
                os.write(role["fifo"]["perf.control"][0], b"enable\n")
                deadline, receipt = time.monotonic() + 10, b""
                while time.monotonic() < deadline and role["process"].poll() is None:
                    try:
                        receipt += os.read(role["fifo"]["perf.ack"][0], 1024)
                    except BlockingIOError:
                        pass
                    if b"ack\n" in receipt:
                        role["report"]["enabled_at_monotonic"] = time.monotonic()
                        break
                    time.sleep(0.02)
                else:
                    raise RuntimeError("perf enable acknowledgement unavailable")
            self.monitor = threading.Thread(target=self.watch, daemon=True)
            self.monitor.start()
            self.persist()
            return self.report
        except BaseException as error:
            self.report["errors"].append(f"start: {type(error).__name__}: {error}")
            self.stop()
            raise

    def watch(self):
        while not self.stop_event.wait(0.1):
            for role in self.roles:
                process = role["process"]
                path = role["directory"] / "perf.data"
                limit = time.monotonic() - role["started_at"] >= CAPTURE_SECONDS
                full = path.exists() and path.stat().st_size >= RAW_BYTES
                if process.poll() is not None or limit or full:
                    reason = "capture wall limit" if limit else "raw byte limit" if full else "recorder exited before stop"
                    role["report"]["errors"].append(reason)
                    # Stop both owned recorders together before waiting; one
                    # failed recorder must not leave its peer past the wall cap.
                    for peer in self.roles:
                        process = peer["process"]
                        if process is not None and process.poll() is None:
                            peer["report"]["stop_requested_at_monotonic"] = time.monotonic()
                            os.killpg(process.pid, signal.SIGINT)
                    for peer in self.roles:
                        self.reap(peer)
                    return

    def reap(self, role):
        process = role["process"]
        if process is None:
            return
        if process.poll() is not None and "stop_requested_at_monotonic" not in role["report"]:
            role["report"]["errors"].append("recorder exited before requested stop")
        if process.poll() is None:
            try:
                role["report"]["stop_requested_at_monotonic"] = time.monotonic()
                os.killpg(process.pid, signal.SIGINT)
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                role["report"]["errors"].append("forced recorder cleanup")
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        role["report"]["record_returncode"] = process.returncode
        if process.returncode != 0:
            role["report"]["errors"].append(f"perf record exit {process.returncode}")

    def stop(self):
        if self.stopped:
            return self.report
        self.stopped = True
        self.stop_event.set()
        if self.monitor is not None:
            self.monitor.join(timeout=18)
            if self.monitor.is_alive():
                self.report["errors"].append("watchdog cleanup did not finish")
        for role in self.roles:
            try:
                self.reap(role)
                if role["process"] is None:
                    raise ValueError("recorder never started")
                after = self.checked_identity(role["container"])
                role["report"]["identity_after"] = after
                before = role["report"]["identity_before"]
                if after["container_id"] != before["container_id"] or not same_identity(before["process"], after["process"]):
                    raise ValueError("sidecar process/container generation or executable changed")
                self.retain(role)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                role["report"]["errors"].append(f"stop: {type(error).__name__}: {error}")
            finally:
                role["report"]["stopped_at_monotonic"] = time.monotonic()
                for handle in role["handles"]:
                    handle.close()
                for name, (fd, inode) in role["fifo"].items():
                    os.close(fd)
                    path = role["directory"] / name
                    if path.exists() and path.is_fifo() and path.stat().st_ino == inode:
                        path.unlink()
        self.persist()
        return self.report

    def command(self, role, name, arguments, *, raw_records=False):
        destination = role["directory"] / name
        errors = role["report"]["errors"]
        argv = [self.perf, *arguments]
        with (destination.with_suffix(destination.suffix + ".stderr")).open("wb") as stderr:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr, env=self.environment(),
                start_new_session=True, preexec_fn=child_limits)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline, size, pending, counts = time.monotonic() + 30, 0, b"", Counter()
            try:
                with destination.open("wb") as output:
                    while True:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("perf decode wall cap")
                        selected = selector.select(0.1)
                        if not selected and process.poll() is not None:
                            break
                        for key, _ in selected:
                            block = os.read(key.fileobj.fileno(), 65536)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            size += len(block)
                            if size > (256 * 1024**2 if raw_records else RAW_BYTES):
                                raise ValueError("perf decode output cap")
                            if raw_records:
                                pending += block
                                while b"\n" in pending:
                                    line, pending = pending.split(b"\n", 1)
                                    match = RECORD.search(line.decode(errors="replace"))
                                    if match:
                                        counts[match[1]] += 1
                                        output.write((match[1] + "\n").encode())
                                    if len(pending) > METADATA_BYTES:
                                        raise ValueError("raw record decoder line cap")
                            else:
                                output.write(block)
                        if not selector.get_map() and process.poll() is not None:
                            break
                process.wait(timeout=3)
                if process.returncode:
                    errors.append(f"{name}: perf exit {process.returncode}")
                return dict(counts)
            except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                errors.append(f"{name}: {type(error).__name__}: {error}")
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                return dict(counts)
            finally:
                selector.close()
                process.stdout.close()
                role["report"].setdefault("decode_commands", []).append({"argv": argv, "returncode": process.returncode})

    def decode(self, begin_monotonic, end_monotonic):
        if not self.stopped:
            self.stop()
        for role in self.roles:
            errors = role["report"]["errors"]
            try:
                if not all(type(value) in (int, float) and math.isfinite(value) for value in (begin_monotonic, end_monotonic)) or not begin_monotonic < end_monotonic:
                    raise ValueError("measurement bracket missing/nonfinite/reversed")
                if not (role["report"].get("enabled_at_monotonic", math.inf) <= begin_monotonic < end_monotonic <= role["report"]["stopped_at_monotonic"]):
                    raise ValueError("measurement bracket not covered by recorder lifetime")
                data = role["directory"] / "perf.data"
                if not data.is_file() or not 0 < data.stat().st_size < RAW_BYTES:
                    raise ValueError("missing/empty/oversize raw perf.data")
                for retained in role["mappings"].values():
                    if sha256(retained["blob"]) != retained["sha256"]:
                        raise ValueError("retained mapped ELF changed before decode")
                symbol = role["report"].get("symbol_binding")
                if symbol and sha256(symbol["path"]) != symbol["sha256"]:
                    raise ValueError("qualified symbol ELF changed before decode")
                provenance = symbol.get("qualification_report") if symbol else None
                if provenance and sha256(provenance["path"]) != provenance["sha256"]:
                    raise ValueError("symbol qualification provenance changed before decode")
                self.command(role, "attributes.txt", ["evlist", "-v", "-i", str(data)])
                errors.extend(validate_attributes((role["directory"] / "attributes.txt").read_text()))
                counts = self.command(role, "record-types.txt", ["script", "-D", "-i", str(data)], raw_records=True)
                role["report"]["record_types"] = counts
                if any(counts.get(name, 0) for name in ("PERF_RECORD_LOST", "PERF_RECORD_LOST_SAMPLES", "PERF_RECORD_THROTTLE", "PERF_RECORD_UNTHROTTLE")):
                    errors.append("lost or throttled samples")
                self.command(role, "buildids.txt", ["buildid-list", "-i", str(data)])
                for line in (role["directory"] / "buildids.txt").read_text().splitlines():
                    fields = line.split(None, 1)
                    if len(fields) == 2 and fields[1].startswith("/"):
                        retained = role["mappings"].get(fields[1])
                        if not retained or fields[0].lower() != retained["build_id"]:
                            errors.append("recorded DSO has no matching retained ELF/build ID: " + fields[1])
                self.command(role, "leaf-events-all.txt", ["script", "-i", str(data), "--symfs", str(role["directory"] / "symfs"),
                    "--no-inline", "--ns", "--show-lost-events", "-F", "comm,pid,tid,time,event,ip,sym,dso"])
                decoded = parse_leaves((role["directory"] / "leaf-events-all.txt").read_text(), role["container"]["pid"],
                                       begin_monotonic, end_monotonic, role["mappings"])
                if counts.get("PERF_RECORD_SAMPLE", 0) != decoded["all_capture_sample_count"]:
                    errors.append("raw and decoded leaf sample counts disagree")
                if decoded["foreign_pid_samples"] or decoded["malformed_samples"]:
                    errors.append("foreign PID or malformed leaf samples")
                if not decoded["measurement_sample_count"] or decoded["known_leaf_fraction"] < KNOWN_FRACTION:
                    errors.append("fewer than 80% known measurement leaves")
                events = decoded.pop("events")
                lines = decoded.pop("raw_window_lines")
                (role["directory"] / "leaf-events-window.txt").write_text("\n".join(lines) + "\n")
                with (role["directory"] / "leaf-events-window.jsonl").open("w") as output:
                    for event in events:
                        output.write(json.dumps(event, allow_nan=False) + "\n")
                role["report"].update(decoded, measurement_begin_monotonic=begin_monotonic,
                    measurement_end_monotonic=end_monotonic, perf_data_sha256=sha256(data))
            except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                errors.append(f"decode: {type(error).__name__}: {error}")
            role["report"]["valid"] = not errors
        self.report["valid"] = len(self.roles) == 2 and not self.report["errors"] and all(role["report"].get("valid") for role in self.roles)
        self.persist()
        return self.report
