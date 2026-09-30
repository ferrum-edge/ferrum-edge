"""Passive Linux H3 observations. No subprocess, descriptor injection or argv execution.

INET_DIAG_SKMEMINFO exposes the kernel SO_RCVBUF/SO_SNDBUF values directly.
See https://man7.org/linux/man-pages/man7/sock_diag.7.html. Socket cookies
prevent inode reuse from being mistaken for a counter delta.
"""

import json
import re
import socket
import struct
import time
import urllib.request
from pathlib import Path


def parse_snmp(text):
    lines = text.splitlines()
    result = {}
    for header, values in zip(lines[::2], lines[1::2]):
        keys, numbers = header.split(), values.split()
        if keys[0] == numbers[0] == "Udp:":
            result.update(zip(keys[1:], map(int, numbers[1:])))
    if not result:
        raise ValueError("missing UDP counters")
    return result


def parse_udp(text):
    result = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 13:
            raise ValueError("short /proc/net/udp row")
        result[int(fields[9])] = dict(proc_drops=int(fields[12]),
                                      proc_tx_queue=int(fields[4].split(":")[0], 16),
                                      proc_rx_queue=int(fields[4].split(":")[1], 16))
    return result


def parse_diag(payload):
    if len(payload) < 72:
        raise ValueError("short inet_diag_msg")
    family = payload[0]
    address_size = 4 if family == socket.AF_INET else 16
    row = dict(family=family, local_port=struct.unpack_from("!H", payload, 4)[0],
               peer_port=struct.unpack_from("!H", payload, 6)[0],
               local_address=socket.inet_ntop(family, payload[8:8 + address_size]),
               peer_address=socket.inet_ntop(family, payload[24:24 + address_size]),
               cookie=list(struct.unpack_from("=II", payload, 44)),
               uid=struct.unpack_from("=I", payload, 64)[0],
               inode=struct.unpack_from("=I", payload, 68)[0])
    offset = 72
    while offset + 4 <= len(payload):
        length, kind = struct.unpack_from("=HH", payload, offset)
        if length < 4 or offset + length > len(payload):
            raise ValueError("invalid inet_diag attribute")
        if kind == 7:  # INET_DIAG_SKMEMINFO
            if length < 40:
                raise ValueError("short SKMEMINFO")
            values = struct.unpack_from("=9I", payload, offset + 4)
            row.update(so_rcvbuf=values[1], so_sndbuf=values[3], socket_drops=values[8],
                       rmem_alloc=values[0], wmem_alloc=values[2])
        offset += (length + 3) & ~3
    return row


def udp_sockets():
    result = []
    for family in (socket.AF_INET, socket.AF_INET6):
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as netlink:
            netlink.settimeout(0.2)
            # inet_diag_req_v2: all UDP states, SKMEMINFO extension, no cookie filter.
            request = struct.pack("=BBBBI", family, socket.IPPROTO_UDP, 1 << 6, 0, 0xFFFFFFFF)
            request += bytes(40) + struct.pack("=II", 0xFFFFFFFF, 0xFFFFFFFF)
            netlink.sendto(struct.pack("=IHHII", 16 + len(request), 20, 0x301, 1, 0)
                           + request, (0, 0))
            done = False
            while not done:
                data, _, flags, _ = netlink.recvmsg(1048576)
                if flags & socket.MSG_TRUNC:
                    raise ValueError("truncated socket diagnostic dump")
                offset = 0
                while offset + 16 <= len(data):
                    length, kind, flags, seq, _ = struct.unpack_from("=IHHII", data, offset)
                    if length < 16 or offset + length > len(data) or seq != 1:
                        raise ValueError("invalid netlink reply")
                    if flags & 0x10:  # NLM_F_DUMP_INTR
                        raise ValueError("interrupted socket diagnostic dump")
                    payload = data[offset + 16:offset + length]
                    if kind == 3:
                        done = True
                    elif kind == 2:
                        raise OSError(f"socket diagnostic error {struct.unpack_from('=i', payload)[0]}")
                    elif kind == 20:
                        result.append(parse_diag(payload))
                    offset += (length + 3) & ~3
    return result


def snapshot(envoy=False):
    result = dict(unix_secs=time.time(), errors=[])
    try:
        result["udp_snmp"] = parse_snmp(Path("/proc/net/snmp").read_text())
        proc = parse_udp(Path("/proc/net/udp").read_text())
        proc.update(parse_udp(Path("/proc/net/udp6").read_text()))
        result["sockets"] = [dict(row, **proc.get(row["inode"], {})) for row in udp_sockets()]
    except (OSError, ValueError) as error:
        result["errors"].append(str(error))
    if envoy:
        try:
            with urllib.request.urlopen("http://127.0.0.1:15000/stats?format=json", timeout=0.2) as response:
                document = json.load(response)
                result["envoy_stats"] = parse_envoy_stats(document)
                result["envoy_histograms"] = [row for row in document["stats"] if "histograms" in row]
        except (OSError, ValueError, KeyError) as error:
            result["errors"].append(f"envoy stats: {error}")
    result["capture_secs"] = time.time() - result["unix_secs"]
    return result


def parse_envoy_stats(document):
    counters = {}
    for row in document["stats"]:
        if "name" in row and "value" in row:
            counters[row["name"]] = row["value"]
        elif "histograms" not in row:
            raise ValueError("unknown Envoy stats record")
    if not counters:
        raise ValueError("missing Envoy scalar counters")
    return counters


def counter_delta(left, right):
    """Never turn a reset or missing counter into zero loss."""
    return {key: right[key] - value if right.get(key, -1) >= value else None
            for key, value in left.items()}


def bracket(values, start, end):
    before = [row for row in values if row["unix_secs"] <= start]
    after = [row for row in values if row["unix_secs"] >= end]
    return (before[-1], after[0]) if before and after else None


def envoy_counter_provenance(image=None):
    if image and image.endswith("@sha256:be87c8b52663c1164a5bdf3c5419017a269cb3d8c74be1ec93638a71f1ffbd4b"):
        return dict(semantics="corrected_cumulative_SO_RXQ_OVFL_assignment",
                    source="b579d07d3ad7ee11d32b105e91a5a39ad24718d7",
                    kernel_socket_deltas_independent=True, exact_kernel_loss_claim=False)
    if image and "1.33.5" in image:
        return dict(semantics="historical_inflated_SO_RXQ_OVFL_totals_38652", exact_kernel_loss_claim=False)
    return dict(semantics="unverified_image_source", exact_kernel_loss_claim=False)


def summarize_transport(timeline, phases):
    start = phases.get("measurement_start_unix_secs")
    if start is None:
        return dict(complete_bracket=False, reason="measurement never started")
    end = start + phases["measurement_secs"]
    values = [row["transport"] for row in timeline if "transport" in row]
    bounds = bracket(values, start, end)
    if bounds is None:
        return dict(complete_bracket=False, reason="missing transport boundary")
    left, right = bounds
    result = dict(complete_bracket=not any(row["errors"] for row in values
                                         if left["unix_secs"] <= row["unix_secs"] <= right["unix_secs"]),
                  boundary_slack_secs=start - left["unix_secs"] + right["unix_secs"] - end,
                  kernel_scope="shared host network namespace; includes client/backend",
                  udp_snmp_delta=counter_delta(left.get("udp_snmp", {}), right.get("udp_snmp", {})),
                  envoy_counter_provenance=envoy_counter_provenance(),
                  envoy_delta=counter_delta(left.get("envoy_stats", {}), right.get("envoy_stats", {})))
    sockets = []
    for first in left.get("sockets", []):
        last = next((row for row in right.get("sockets", [])
                     if row["inode"] == first["inode"] and row["cookie"] == first["cookie"]), None)
        sockets.append(dict(first, complete_bracket=last is not None,
                            end_so_rcvbuf=(last or {}).get("so_rcvbuf"),
                            end_so_sndbuf=(last or {}).get("so_sndbuf"),
                            delta=counter_delta({key: first[key] for key in ("socket_drops", "proc_drops")
                                                 if key in first}, last or {})))
    result["sockets"] = sockets
    initial_cookies = {tuple(row["cookie"]) for row in sockets}
    new_sockets = {}
    for observation in values:
        if left["unix_secs"] <= observation["unix_secs"] <= right["unix_secs"]:
            for row in observation.get("sockets", []):
                cookie = tuple(row["cookie"])
                if cookie not in initial_cookies:
                    new_sockets[cookie] = dict(row, complete_bracket=False)
    result["new_or_retired_sockets"] = list(new_sockets.values())
    return result


def thread_snapshot(pid, ticks, parse_stat):
    result = []
    try:
        for path in Path(f"/proc/{pid}/task").iterdir():
            try:
                contents = (path / "stat").read_text()
                record = parse_stat(contents, ticks, 1)
                # RSS belongs to the process, not each thread. Keep its byte
                # accounting in the existing process sampler only.
                record.pop("rss_bytes", None)
                result.append(dict(record, tid=int(path.name), pid=pid,
                                   name=contents[contents.find("(") + 1:contents.rfind(")")]))
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        pass
    return result


def measurement_threads(timeline, phases):
    start = phases.get("measurement_start_unix_secs")
    if start is None:
        return []
    identities = {}
    for snapshot in timeline:
        for thread in snapshot.get("threads", []):
            key = (thread["pid"], thread["tid"], thread["start_ticks"])
            identities.setdefault(key, []).append(dict(thread, unix_secs=snapshot["unix_secs"]))
    result = []
    for rows in identities.values():
        bounds = bracket(rows, start, start + phases["measurement_secs"])
        record = dict(rows[0], complete_bracket=bounds is not None)
        if bounds:
            left, right = bounds
            record.update(cpu_seconds=right["cpu_seconds"] - left["cpu_seconds"],
                          bracket_secs=right["unix_secs"] - left["unix_secs"])
        else:
            record.pop("cpu_seconds", None)
        result.append(record)
    return result


def backend_distribution(path, phases):
    connections = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith("H3_PROFILE "):
            row = json.loads(line.removeprefix("H3_PROFILE "))
            connections.setdefault(row["connection_id"], []).append(row)
    start = phases.get("measurement_start_unix_secs")
    result = []
    for rows in connections.values():
        bounds = bracket(rows, start, start + phases["measurement_secs"]) if start else None
        record = dict(connection_id=rows[0]["connection_id"], peer=rows[0]["peer"],
                      complete_bracket=bounds is not None)
        if bounds:
            left, right = bounds
            record.update(delta=counter_delta({key: left[key] for key in
                                               ("accepted", "completed", "bytes")}, right),
                          boundary_slack_secs=start - left["unix_secs"] + right["unix_secs"]
                          - start - phases["measurement_secs"])
        result.append(record)
    return result


def annotate_experiment(sample, path, usage_path):
    from h3_experiment import load_experiment, topology

    manifest = Path(path).parent.parent.parent / "h3_experiment.json"
    if not manifest.exists():
        return
    plan = load_experiment(manifest)
    gateway = sample["gateway"]
    limit = 4 if gateway == "envoy-limit-4" else 100
    sample["h3_experiment"] = dict(plan, topology=topology(sample["effective_concurrency"], limit),
                                   topology_limit_applies=gateway.startswith("envoy"))
    diagnostics = sample.get("transport_diagnostics", {})
    if gateway != "direct":
        startup = Path(usage_path).parent / f"{gateway}_startup.log"
        try:
            lines = startup.read_text().splitlines()
            diagnostics["startup_transport_messages"] = [line for line in lines
                if re.search(r"\b(bpf|gro|gso|reuseport)\b", line, re.IGNORECASE)]
            diagnostics["optimized_path"] = "unverified; warnings alone cannot prove use"
        except OSError as error:
            diagnostics["startup_capture_error"] = str(error)
    try:
        backend_log = str(usage_path).replace("_process_usage.json", "_backend.log")
        distribution = backend_distribution(backend_log, sample.get("phases") or {})
        diagnostics["backend_connections"] = distribution
        upstream_ports = {int(row["peer"].rsplit(":", 1)[1]) for row in distribution}
        relevant = []
        all_sockets = diagnostics.get("sockets", []) + diagnostics.get("new_or_retired_sockets", [])
        for row in all_sockets:
            port = row["local_port"]
            if port in (8443, 3445) or port in upstream_ports:
                row["role"] = ("backend" if port == 3445 else "gateway_downstream"
                               if port == 8443 else "client" if gateway == "direct"
                               else "gateway_upstream")
                relevant.append(row)
        diagnostics["identified_sockets"] = relevant
        expected_roles = {"backend", "client"} if gateway == "direct" else {
            "backend", "gateway_downstream", "gateway_upstream"}
        diagnostics["equal_socket_budget_verified"] = (
            expected_roles <= {row["role"] for row in relevant}
            and all(row.get("so_rcvbuf") == row.get("so_sndbuf")
                    == row.get("end_so_rcvbuf") == row.get("end_so_sndbuf")
                    == plan["socket_buffer_bytes"]
                    and row["complete_bracket"] for row in relevant))
    except (OSError, ValueError, KeyError) as error:
        diagnostics["profile_error"] = str(error)
        diagnostics["equal_socket_budget_verified"] = False
    sample["transport_diagnostics"] = diagnostics
