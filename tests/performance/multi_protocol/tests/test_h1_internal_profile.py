import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import h1_internal_profile as profile


def values():
    result = dict.fromkeys(profile.FIELDS, 0)
    result.update(schema=1, pid=1, allocator_installed=1, slot_capacity=128, registered_slots=2)
    return result


def owned_gateway():
    return dict(container_id="a" * 64, host_pid=31, start_ticks=100,
                network_mode="host", metrics_endpoint=profile.METRICS_ENDPOINT)


def binding(identity=None):
    identity = owned_gateway() if identity is None else identity
    endpoint = dict(host_pid=identity["host_pid"], start_ticks=identity["start_ticks"],
                    namespace_pids=[identity["host_pid"], 1], listener_inode=1234)
    return dict(container_id=identity["container_id"], endpoint=profile.METRICS_ENDPOINT,
                before=endpoint, after=copy.deepcopy(endpoint))


def capture(duration=1, times=None, identity=None):
    identity = owned_gateway() if identity is None else identity
    rows = []
    times = times if times is not None else [9.75 + index * 0.5 for index in range(duration * 2 + 2)]
    for index, time in enumerate(times):
        counters = values()
        counters["alloc_process_alloc_calls"] = 100 + index * 10
        # The real producer counts each DATA poll at reqwest input and ProxyBody
        # output. Metrics rendering itself registers/publishes a thread slot.
        for boundary in ("body_reqwest_direct", "body_proxy_output_all"):
            counters[boundary + "_polls"] = 100 + index * 10
            counters[boundary + "_data_frames"] = 100 + index * 10
            counters[boundary + "_data_bytes"] = (100 + index * 10) * 10240
            counters[boundary + "_size_1025_16384"] = 100 + index * 10
        rows.append(dict(unix_secs=time - 0.001,
                         processes=[dict(pid=identity["host_pid"], start_ticks=identity["start_ticks"], role="gateway")],
                         h1_profile=dict(sample_id=index, unix_secs=time, monotonic_secs=time + 100,
                                         capture_secs=0.01, sampler_cpu_secs=0.001,
                                         counters=counters, gateway_binding=binding(identity))))
    return dict(capture_complete=True, timeline=rows, h1_gateway=identity)


def bracket(data, phases=None, **kwargs):
    phases = phases if phases is not None else dict(measurement_start_unix_secs=10, measurement_secs=1)
    return profile.profile_bracket(data, phases, owned_gateway=owned_gateway(),
                                   successful_responses=100, **kwargs)


def traffic_sample(gateway, pair, size, gateway_pid=31):
    workers = profile.MANIFEST["scaled_workers"][profile.MANIFEST["payload_sizes"].index(size)]
    roles = ["client", "backend"] + ([] if gateway == "direct" else ["gateway"])
    processes = [dict(pid={"client": 32, "backend": 30, "gateway": gateway_pid}[role],
                      role=role, complete_bracket=True, cpu_seconds=1) for role in roles]
    observed = {name: dict(min=0, max=workers, mean=workers / 2) for name in (
        "active_workers", "active_connections", "active_streams", "queued_requests")}
    observed.update(samples=1500, workers_at_barrier=workers, workers_retired_before_deadline=0)
    return dict(sample_schema=2, gateway=gateway, pair=pair, host_id="campaign-host",
                protocol="HTTP/1.1+TLS", duration_secs=15, concurrency=workers,
                effective_concurrency=workers, payload_size=size, total_requests=100,
                total_errors=0, total_bytes=size * 100, rps=100 / 15, warmup_requests=workers,
                phases=dict(measurement_start_unix_secs=10, measurement_secs=15.0,
                            measurement_elapsed_secs=15.001, timed_out=False),
                observed=observed, process_usage=dict(processes=processes, measurement=processes))


REVISION = "f73e1d2299ed61612bc5dd95315e3df901b150fa"


def docker_inspect(config, gateway="ferrum", pair=1, mode="cutoff"):
    # Actual Dockerfile.release + start_ferrum shape, independently enumerated
    # so producer/consumer changes cannot silently update a mirrored fixture.
    observer = "off" if mode == "diagnostic" or (mode == "calibration" and gateway == "ferrum-baseline") else "on"
    labels = {"org.opencontainers.image.revision": REVISION, "ferrum.h1-profile": observer,
              "org.opencontainers.image.title": "Ferrum Edge"}
    environment = [
        "PATH=/app:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
        "FERRUM_MODE=file", "FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml",
        "FERRUM_PROXY_HTTP_PORT=8000", "FERRUM_PROXY_HTTPS_PORT=8443",
        "FERRUM_ADMIN_HTTP_PORT=9000", "FERRUM_ADMIN_HTTPS_PORT=9443",
        "FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1", "FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32",
        "FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/tls/cert.pem",
        "FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/tls/key.pem",
        "FERRUM_DTLS_CERT_PATH=/etc/ferrum/tls/cert.pem", "FERRUM_DTLS_KEY_PATH=/etc/ferrum/tls/key.pem",
        "FERRUM_LOG_LEVEL=error", "FERRUM_ADD_VIA_HEADER=false", "FERRUM_ADD_FORWARDED_HEADER=false",
        "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0", "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0",
        "FERRUM_MAX_GRPC_RECV_SIZE_BYTES=0", "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0",
        "FERRUM_MAX_CONNECTIONS=0", "FERRUM_POOL_MAX_IDLE_PER_HOST=200",
        "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true", "FERRUM_POOL_WARMUP_ENABLED=true",
        "FERRUM_WEBSOCKET_TUNNEL_MODE=true", "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608",
        "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432",
        "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=false", "FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576",
        "FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000", "FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST=16",
        "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000", "FERRUM_UDP_MAX_SESSIONS=10000",
        "FERRUM_UDP_RECVMMSG_BATCH_SIZE=64", "FERRUM_TCP_IDLE_TIMEOUT_SECONDS=30",
        "FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS=30",
        "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=" + ("1" if gateway == "ferrum-exp-cutoff-one" else "0"),
    ]
    image_id = "sha256:" + ("b" if observer == "off" else "c") * 64
    ordinal = (pair - 1) * 3 + ("ferrum", "ferrum-baseline", "ferrum-exp-cutoff-one").index(gateway)
    container = dict(Id="a" * 64 if ordinal == 0 else f"{ordinal:064x}", Image=image_id,
                     # Synthetic wall clock matches the measurement starting at 10.
                     State=dict(Pid=31 + ordinal * 10, StartedAt="1970-01-01T00:00:01.123456789Z", Running=True),
                     HostConfig=dict(NetworkMode="host"),
                     Config=dict(Env=environment, Labels=labels, Entrypoint=["/app/ferrum-edge"],
                                 Cmd=["run"], WorkingDir="/app"),
                     Mounts=[dict(Type="bind", Source=str(config.resolve()),
                                  Destination="/etc/ferrum/config.yaml", RW=False),
                             dict(Type="bind", Source="/tmp/campaign/tls",
                                  Destination="/etc/ferrum/tls", RW=False)])
    return container, dict(Id=image_id, Config=dict(Labels=copy.deepcopy(labels)))


def retain_fixture(path, config, gateway="ferrum", pair=1, mode="cutoff"):
    container, image = docker_inspect(config, gateway, pair, mode)
    with patch.object(profile, "process_start_ticks", return_value=100), \
            patch.object(profile.subprocess, "run", return_value=MagicMock(stdout=json.dumps(image))):
        profile.retain_runtime(path, container, config, pair, gateway, "campaign-host", mode)
    return json.loads(path.read_text())


def campaign(root, mode="cutoff"):
    gateways = ["direct"] + list(profile.MANIFEST["campaigns"][mode])
    manifest = dict(pairs=4, gateways=gateways, payload_sizes=profile.MANIFEST["payload_sizes"],
                    host_id="campaign-host", sample_schema=2, protocol="http1-tls", duration=15,
                    offered_workers=200, h1_profile_mode=mode, h1_revision=REVISION)
    (root / "manifest.json").write_text(json.dumps(manifest))
    for pair in range(1, 5):
        folder = root / "pairs" / f"pair_{pair:03d}"
        (folder / "diagnostics").mkdir(parents=True)
        for gateway in gateways:
            identity = None
            if gateway != "direct":
                config = folder / "diagnostics" / f"{gateway}_config.yaml"
                config.write_text((profile.ROOT / "configs/http1_tls_e2e_perf.yaml").read_text().replace(
                    "CA_PATH", "/etc/ferrum/tls/ca.pem"))
                runtime = retain_fixture(folder / "diagnostics" / f"{gateway}_runtime.json",
                                         config, gateway, pair, mode)
                identity = {key: runtime[key] for key in owned_gateway()}
            for size in profile.MANIFEST["payload_sizes"]:
                (folder / f"{gateway}_http1-tls_{size}.json").write_text(
                    json.dumps(traffic_sample(gateway, pair, size, identity["host_pid"] if identity else 31)))
                if gateway != "direct":
                    usage = capture(duration=15, identity=identity)
                    if mode == "calibration" and gateway == "ferrum-baseline":
                        for row in usage["timeline"]:
                            row["h1_profile"].pop("counters")
                            row["h1_profile"]["error"] = "ValueError"
                    (folder / "diagnostics" / f"{gateway}_{size}_process_usage.json").write_text(
                        json.dumps(usage))
    return root / "pairs/pair_001/ferrum_http1-tls_10240.json", \
        root / "pairs/pair_001/diagnostics/ferrum_10240_process_usage.json"


def external_capture(root, pair, gateway, size=10240, selected_mode="syscalls"):
    """Producer-shaped retained syscall/off capture, through actual receipt writers.

    Kernel events are fixed data here; hosted C fixtures independently exercise
    collection. No report/admission validator is mocked by these regressions.
    """
    import h1_trace as trace
    from h1_trace_contract import BOUNDS, COUNTERS, LOSSES, syscall_coverage, fd_lifetimes
    folder = root / 'pairs' / f'pair_{pair:03d}'
    out = folder / 'traces' / f'{gateway}_{size}'; out.mkdir(parents=True)
    runtime_path = folder / 'diagnostics' / f'{gateway}_runtime.json'
    runtime = json.loads(runtime_path.read_text())
    config = folder / 'diagnostics' / f'{gateway}_config.yaml'
    sample_path = folder / f'{gateway}_http1-tls_{size}.json'
    raw_path = folder / 'diagnostics' / f'{gateway}_{size}_client.raw.json'
    exit_path = folder / 'diagnostics' / f'{gateway}_{size}_client.exit'
    sample = json.loads(sample_path.read_text())
    sample['phases'].update(stalled_workers=[], transport_close_timed_out=False, drain_secs=0.2,
        drain_start_monotonic_secs=17.01, measurement_start_host_clock=dict(
            clock='CLOCK_MONOTONIC', before_ns=2_000_000_000, after_ns=2_000_000_001))
    trace.write(sample_path, sample)
    trace.write(raw_path, dict(phases=sample['phases']))
    exit_path.write_text('0\n')
    trace.write_binding(out, runtime=str(runtime_path), config=str(config), sample=str(sample_path),
                        raw_sample=str(raw_path), client_exit=str(exit_path), arm=gateway, pair=pair, payload=size)
    binding = json.loads((out / 'bind.json').read_text())
    binary = root.parent / 'builds/on/ferrum-edge'; binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b'\x7fELFsynthetic retained release twin')
    owner = dict(pid=runtime['host_pid'], start_ticks=runtime['start_ticks'],
                 cgroup='/system.slice/docker-' + runtime['container_id'] + '.scope', cgroup_id=42,
                 boot_id='campaign-host', executable_sha256=trace.digest(binary),
                 namespaces={name: 1 for name in ('pid', 'mnt', 'net', 'time', 'user')})
    def at(ns):
        return dict(kind='clock_receipt', clock='CLOCK_MONOTONIC', boot_id='campaign-host', time_namespace=1,
                    before_ns=ns, after_ns=ns + 1, unix_ns=8_000_000_000 + ns)
    enabled = gateway != 'ferrum-baseline'
    ready = dict(status='supported' if enabled else 'off', at=at(1_000_000_000), owner=owner,
                 session=f'{pair:016x}' + ('a' if enabled else 'b') * 16,
                 binding_sha256=trace.digest(out / 'bind.json'), deadline_monotonic=300)
    for name, value in (('identity.json', owner), ('ready.json', ready),
                        ('initial-sockets.json', dict(errors=[], joins_authoritative=False)), ('build-mappings.json', {})):
        trace.write(out / name, value)
    request = dict(at=at(18_000_000_000), owner=owner, session=ready['session'],
                   binding_sha256=ready['binding_sha256'], evidence=trace.completion_evidence(binding))
    trace.write(out / 'teardown-request.json', request)
    collector = MagicMock(ready={'status': 'supported'})
    collector.process.poll.return_value = None
    lifecycle = trace.CaptureLifecycle(out, owner, binding, ready, {('observer' if selected_mode == 'syscalls' else 'cpu'): collector} if enabled else {})
    with patch.object(trace, 'clock', return_value=at(19_000_000_000)), \
            patch.object(trace, 'identity', return_value=owner), patch.object(trace, 'target_alive', return_value=True):
        lifecycle.authorize_teardown()
    with patch.object(trace, 'clock', return_value=at(20_000_000_000)), \
            patch.object(trace, 'target_alive', return_value=False):
        lifecycle.poll()
        if enabled:
            lifecycle.reaped('observer' if selected_mode == 'syscalls' else 'cpu', dict(returncode=0, forced=False))
    timeline = [dict(clock=ready['at'], ready=True), dict(clock=at(20_000_000_000), terminal=True)]
    boundaries = trace.boundary_report(sample, timeline, 1_000_000_000, 20_000_000_000, owner)
    claim = dict(schema=1, mode=selected_mode if enabled else 'none', selected_mode=selected_mode, external_enabled=enabled,
                 capture_complete=True, complete=False, fully_profiled=False, issues=[], stop_requested=True, bounds=BOUNDS,
                 identity=owner, runtime=runtime, matching_elf='on/ferrum-edge', binding=binding,
                 input_hashes=dict(binding=trace.digest(out / 'bind.json'), runtime=trace.digest(runtime_path),
                                   config=trace.digest(config)), ready={'status': ready['status']},
                 timeline=timeline, boundaries=boundaries, lifecycle=lifecycle.report(),
                 dependency_provenance=trace.DEPENDENCY_PROVENANCE)
    capability = dict(source_hashes={name: 'd' * 64 for name in ('h1_trace.py', 'h1_trace_contract.py', 'h1_syscalls.bpf.h', 'h1_loader.h')},
                      object_hashes={name: 'e' * 64 for name in ('observer', 'observer.bpf.o', 'perf', 'h1_trace_fixture')},
                      runner={'GITHUB_SHA': REVISION}, dependency_provenance=trace.DEPENDENCY_PROVENANCE,
                      capture_complete=True, discovered=True, loaded=enabled and selected_mode == 'syscalls', attached=enabled)
    trace.write(out / 'capabilities.json', capability)
    if enabled and selected_mode == 'syscalls':
        total = dict.fromkeys(COUNTERS, 0)
        total.update(id=1, attempts=2, exits=2, positive=2, offered=24, offered_known=2,
                     accepted_bytes=24, accepted_known=2, return_sum=24, min_return=12, max_return=12)
        rows = [dict(phase='ready', status='supported'),
                dict(phase='bound', pid=owner['pid'], start_ticks=owner['start_ticks'], cgroup=42, netns=1, at_ns=900_000_000),
                dict(phase='final', before_ns=21_000_000_000, after_ns=21_000_000_001, pending=0,
                     map_read_failures=0, losses=[0] * len(LOSSES), totals=[total], census={'1': 2},
                     rows=[dict(total, attempts=0, pid=owner['pid'], process_ns=owner['start_ticks'] * 10_000_000,
                                cgroup=42, cookie=55, netns=1, role=1, outcome=1, direction=1)]),
                dict(phase='termination', requested_stop=True, bound=True, at_ns=22_000_000_000,
                     snapshot_failures=0, lifecycle_omitted=0, checkpoints_omitted=0)]
        (out / 'syscalls.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (out / 'loader.stderr').write_text('')
        # The real producer consumer computes role_totals from raw kernel rows.
        observer = object.__new__(trace.Observer)
        observer.out, observer.offset, observer.pending, observer.rows = out, 0, b'', []
        observer.poll()
        claim['syscalls'] = syscall_coverage(observer.rows, owner, boundaries)
        claim['observer_exit'] = dict(returncode=0, forced=False, partial_record=False)
        trace.write(out / 'syscalls.json', claim['syscalls'])
        trace.write(out / 'fd-lifetimes.json', fd_lifetimes(observer.rows))
    elif enabled:
        from h1_trace_contract import decode_cpu, cpu_phases
        # Real retained evlist producer text, with a deliberately partial sample.
        attributes = (profile.ROOT / 'tests/fixtures/h1-perf-evlist-6.8.0-139.txt').read_text()
        stacks = (f"ferrum {owner['pid']}/{owner['pid']} 3.000000001: cpu-clock:uS:\n"
                  "        1234 forwarding (/app/ferrum-edge)\n"
                  "        0000 [unknown] ([unknown])\n\n")
        statuses = {}
        for name, text in (('perf-attributes.txt', attributes), ('stacks.txt', stacks),
                           ('perf-buildids.txt', 'abcdef12 /app/ferrum-edge\n'), ('perf-header.txt', 'header\n')):
            (out / name).write_text(text); (out / (name + '.stderr')).write_text('')
            statuses[name] = dict(returncode=0, forced=False, incomplete=None,
                                  stdout_sha256=trace.digest(out / name), stderr_sha256=trace.digest(out / (name + '.stderr')))
            trace.write(out / (name + '.status.json'), statuses[name])
        raw_records = ['PERF_RECORD_SAMPLE', 'PERF_RECORD_MMAP2', 'PERF_RECORD_COMM']
        raw_status = dict(returncode=0, forced=False)
        trace.write(out / 'perf-records.json', dict(records=raw_records, status=raw_status, incomplete=None))
        (out / 'perf.data').write_bytes(b'synthetic raw artifact for retained-report binding tests')
        (out / 'perf.stderr').write_text('')
        decoded = decode_cpu(stacks, '\n'.join(raw_records), {owner['pid']})
        attributes_check = trace.read_cpu_attributes(out / 'perf-attributes.txt', statuses['perf-attributes.txt'])
        coverage = {k: v for k, v in decoded.items() if k not in ('callchains', 'folded')}
        coverage.update(issues=['missing matching ELF/build IDs/CFI', 'partial unwinding/unresolved samples'],
                        samples_complete=False, unwind_complete=False, attributes_verified=attributes_check['verified'],
                        attribute_validation=attributes_check, decoder_status=statuses['stacks.txt'],
                        header_status=statuses['perf-header.txt'], buildid_status=statuses['perf-buildids.txt'],
                        attributes_status=statuses['perf-attributes.txt'], raw_decoder_status=raw_status)
        trace.write(out / 'cpu-coverage.json', coverage)
        mapped = binary.parent / 'symfs/app/ferrum-edge'; mapped.parent.mkdir(parents=True, exist_ok=True)
        mapped.write_bytes(binary.read_bytes())
        metadata = mapped.with_name(mapped.name + '.elf-test.txt')
        metadata.write_text('Build ID: abcdef12\n.eh_frame\n')
        errors = metadata.with_name(metadata.name + '.stderr'); errors.write_text('')
        decoder = dict(returncode=0, forced=False, incomplete=None,
                       stdout_sha256=trace.digest(metadata), stderr_sha256=trace.digest(errors))
        trace.write(metadata.with_name(metadata.name + '.status.json'), decoder)
        trace.write(out / 'build-mappings.json', dict(complete=False, errors=['anonymous mapping'], dsos=[
            dict(path='/app/ferrum-edge', device_major=0, device_minor=1, inode=123, bytes=mapped.stat().st_size,
                 sha256=trace.digest(mapped), build_id_lines=['Build ID: abcdef12'], eh_frame=True, debug_frame=False,
                 metadata_path='/app/ferrum-edge.elf-test.txt', decoder=decoder)]))
        (out / 'stacks.folded').write_text(''.join(f'{key} {count}\n' for key, count in decoded['folded'].items()))
        claim['cpu'] = dict(coverage, phases=cpu_phases(decoded['callchains'], boundaries['measurement']))
        claim['perf_exit'] = raw_status
    claim['artifacts'] = {str(p.relative_to(out)): dict(sha256=trace.digest(p), bytes=p.stat().st_size)
                          for p in out.iterdir() if p.is_file()}
    trace.write(out / 'trace-manifest.json', claim)
    return out / 'trace-manifest.json'


def diagnostic_state(pid):
    # Exact serialized Report/WorkerState/RequestState/ConnectionState shape.
    # Real Rust H1/TLS output also crosses this validator in metrics_tests.
    from h1_diagnostic_evidence import CLOCK

    def at(t, phase="measurement"):
        start = {"setup": 0, "measurement": 1_000_000, "drain": 31_000_000,
                 "driver_retirement": 31_100_000}[phase]
        relative = 29_999_990 + t if phase == "measurement" else t
        return dict(session_us=start + relative, phase=phase, phase_us=relative)

    workers, connections = [], []
    for index in range(50):
        request = dict(id=index + 101, offered=at(1), body_first_poll=at(2), body_bytes=5242880,
                       body_last_progress=at(3), body_end=at(4), body_end_signal="end_stream_after_frame",
                       headers=at(5), status=200, version="HTTP/1.1", content_length=5242880,
                       content_length_present=True, transfer_encoding_present=False, chunked=False,
                       connection_close=False, response_bytes=5242880, response_last_progress=at(6),
                       response_end=at(7), response_end_signal="end_stream_after_frame", error_class=None,
                       error_at=None, validated=True, completion=at(8))
        workers.append(dict(id=index, connection_id=index + 1, stage="next_request", stage_since=at(9),
                            lifecycle="returned", requests_offered=3, bodies_admitted=3, completions=3,
                            errors=0, request=request))
        connections.append(dict(id=index + 1, worker_id=index, local=f"127.0.0.1:{20000 + index}",
                                peer="127.0.0.1:8443", socket_at=at(0, "setup"), driver="completed_ok",
                                driver_at=at(10, "drain"), error_class=None))
    loss = dict(workers=0, connections=0, updates=0, snapshots=0, poisoned_locks=0)
    snapshots = [dict(clock_domain=CLOCK, pid=pid, reason=reason, at=at(t, phase),
                      workers=copy.deepcopy(workers), connections=copy.deepcopy(connections), loss=loss.copy())
                 for reason, t, phase in (("request_drain_complete", 11, "drain"),
                                          ("driver_retirement_finished", 12, "driver_retirement"))]
    return dict(schema=1, clock_domain=CLOCK, pid=pid, worker_capacity=256, connection_capacity=512,
                snapshot_capacity=4, loss=loss, snapshots=snapshots,
                retirement=dict(started=50, completed_ok=50, completed_error=0, cancelled=0, panicked=0,
                                capacity_rejections=0, pending_at_request_drain=0, abort_requested=0,
                                unreaped_after_abort=0, abort_reap_bound_secs=0.0, timed_out=False,
                                elapsed_secs=0.001, bound_secs=5.0))


def diagnostic_campaign(root):
    from benchmark_plan import stamp_sample
    from h1_diagnostic_evidence import ARMS
    (root / "manifest.json").write_text(json.dumps(dict(
        sample_schema=2, pairs=1, gateways=ARMS, payload_sizes=[5242880], host_id="campaign-host",
        protocol="http1-tls", duration=30, offered_workers=200, h1_revision=REVISION,
        h1_profile_mode="diagnostic", h1_diagnostic_enabled=True, h2_observation_enabled=False)))
    (root / "diagnostic_termination.json").write_text(json.dumps(dict(
        schema=1, status="completed", campaign_exit_code=0, cleanup_complete=True,
        budget_secs=900, elapsed_secs=120)))
    folder = root / "pairs/pair_001"
    (folder / "diagnostics").mkdir(parents=True)
    for position, gateway in enumerate(ARMS, 1):
        identity = None
        if gateway != "direct":
            config = folder / "diagnostics" / f"{gateway}_config.yaml"
            config.write_text((profile.ROOT / "configs/http1_tls_e2e_perf.yaml").read_text().replace(
                "CA_PATH", "/etc/ferrum/tls/ca.pem"))
            runtime = retain_fixture(folder / "diagnostics" / f"{gateway}_runtime.json",
                                     config, gateway, mode="diagnostic")
            identity = profile.gateway_identity(runtime)
        sample = traffic_sample(gateway, 1, 5242880, identity["host_pid"] if identity else 31)
        client = dict(pid=1000 + position, role="client", complete_bracket=True, cpu_seconds=1.0,
                      peak_rss_bytes=1024, rss_scope="process lifetime high-water mark at measurement end",
                      bracket_secs=30.001, boundary_slack_secs=0.001)
        sample.update(duration_secs=30, rps=100 / 30, drain_requests=0)
        sample["phases"].update(measurement_secs=30.0, measurement_elapsed_secs=30.001,
                                preflight_bound_secs=70.0, stalled_workers=[], client_usage=client,
                                h1_diagnostic=diagnostic_state(client["pid"]))
        usage = capture(duration=30, identity=identity)
        for row in usage["timeline"]:
            if gateway == "direct":
                row["processes"].clear()
                row.pop("h1_profile")
            else:
                row["h1_profile"].pop("counters")
                row["h1_profile"]["error"] = "ValueError"  # both gateways are OFF
            row["processes"].extend([dict(pid=client["pid"], role="client", start_ticks=100),
                                      dict(pid=2000 + position, role="backend", start_ticks=100)])
            for process in row["processes"]:
                process.update(cpu_seconds=row["unix_secs"], rss_bytes=1024)
        usage["processes"] = copy.deepcopy(usage["timeline"][0]["processes"])
        usage_path = folder / "diagnostics" / f"{gateway}_5242880_process_usage.json"
        usage_path.write_text(json.dumps(usage))
        path = folder / f"{gateway}_http1-tls_5242880.json"
        path.write_text(json.dumps(sample))
        # Exercise actual measurement_usage + stamping, including client self
        # accounting and passive process ownership, not a hand-built admission.
        stamp_sample(path, gateway, 5242880, 50, 1, position, "campaign-host", usage_path, " ".join(ARMS))
    return folder / "ferrum_http1-tls_5242880.json"


class H1InternalProfileTests(unittest.TestCase):
    def test_literal_rust_and_sampler_schema_match(self):
        root = Path(__file__).resolve().parents[4]
        source = (root / "src/h1_profile/schema.rs").read_text()
        names = re.findall(r'^    "([a-z0-9_]+)",$', source, re.M)
        self.assertEqual(names, profile.SCHEMA["counters"])
        self.assertEqual(len(set(names)), 206)
        self.assertEqual(len(profile.FIELDS), 214)
        store = (root / "src/h1_profile/store.rs").read_text()
        self.assertIn(f"pub const THREAD_SLOTS: usize = {profile.SLOT_CAPACITY};", store)

    def test_metrics_require_every_fixed_field_and_integer(self):
        text = "\n".join(f"{profile.PREFIX}{key} {value}" for key, value in values().items())
        self.assertEqual(profile.parse_metrics(text), values())
        for malformed in [text + "\n" + text, text.replace("schema 1", "schema NaN"),
                          text.replace("schema 1", "schema 2"), "", text + "\nferrum_h1_profile_secret 1"]:
            with self.assertRaises(ValueError):
                profile.parse_metrics(malformed)

    def test_missing_resets_identity_overflow_and_thread_tails_are_explicit(self):
        phases = dict(measurement_start_unix_secs=10, measurement_secs=1)
        self.assertTrue(bracket(capture(), phases)["complete"])
        mutations = [
            lambda c: c["timeline"][1].pop("h1_profile"),
            lambda c: c["timeline"][1]["processes"].clear(),
            lambda c: c["timeline"][1]["processes"][0].update(start_ticks=101),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(alloc_process_alloc_calls=0),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(counter_overflow=1),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(missing_slots=1),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(lost_events=1),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(unpublished_events=1),
            lambda c: c.update(capture_complete=False),
            lambda c: c.update(timeline=None),
            lambda c: c["timeline"][1].update(h1_profile=[]),
            lambda c: c["timeline"][1]["h1_profile"].update(counters=[]),
            lambda c: c["timeline"][1]["h1_profile"]["counters"].update(alloc_process_alloc_calls=True),
            lambda c: c["timeline"][1]["h1_profile"].update(capture_secs=float("nan")),
            lambda c: c["timeline"][1].update(unix_secs=1),
        ]
        for mutate in mutations:
            data = copy.deepcopy(capture())
            mutate(data)
            result = bracket(data, phases)
            self.assertFalse(result["complete"])
            self.assertTrue(result["issues"])
        for invalid in (None, [], dict(measurement_start_unix_secs=float("nan"), measurement_secs=1),
                        dict(measurement_start_unix_secs=10, measurement_secs=-1)):
            self.assertFalse(profile.profile_bracket(capture(), invalid)["complete"])

    def test_selection_preserves_declared_policy_and_h2_manifest(self):
        args = ["cutoff", "http1-tls", "4", "15", "200", "ferrum", "10240 5242880", "", ""]
        profile.validate_selection(*args)
        for index, replacement in [(1, "http2"), (2, "2"), (3, "60"), (4, "100"),
                                   (5, "ferrum envoy"), (6, "1024"), (7, "other-image"),
                                   (8, "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)

    def assert_matrix(self, root, *, eligible=False, mode="cutoff"):
        result = profile.report(root, mode)
        written = json.loads((root / "h1_profile_report.json").read_text())
        self.assertEqual(len(written["observations"]), 60)
        self.assertEqual(result["internal_comparison_eligible"], eligible)
        self.assertEqual(written["internal_comparison_eligible"], eligible)
        self.assertFalse(result["fully_measured_comparison_eligible"])
        self.assertFalse(written["fully_measured_comparison_eligible"])
        self.assertEqual({(row["pair"], row["gateway"], row["payload"]) for row in written["observations"]},
                         {(pair, gateway, size) for pair in range(1, 5)
                          for gateway in ["direct"] + list(profile.MANIFEST["campaigns"][mode])
                          for size in profile.MANIFEST["payload_sizes"]})
        return next(row for row in result["observations"]
                    if (row["pair"], row["gateway"], row["payload"]) == (1, "ferrum", 10240))

    def test_real_producer_shape_accepts_all_sizes_in_both_campaigns(self):
        self.assertEqual(profile.MANIFEST["scaled_workers"], [200, 200, 200, 100, 50])
        for mode in ("calibration", "cutoff"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                campaign(root, mode)
                row = self.assert_matrix(root, eligible=True, mode=mode)
                self.assertFalse(row["traffic_issues"])
                self.assertFalse(row["runtime_issues"])
                self.assertTrue(row["profile"]["complete"])
                self.assertGreater(row["profile"]["published_delta"]["body_proxy_output_all_data_bytes"], 0)
                written = json.loads((root / "h1_profile_report.json").read_text())
                self.assertTrue(written["runtime_complete"])
                ids = {r["runtime"]["image_id"] for r in written["observations"] if "runtime" in r}
                self.assertEqual(len(ids), 2 if mode == "calibration" else 1)

    def trace_campaign(self, root, selected_mode="syscalls"):
        campaign(root, 'trace-calibration')
        manifest_path = root / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest.update(payload_sizes=[10240], h1_trace_mode=selected_mode)
        manifest_path.write_text(json.dumps(manifest))
        for pair in range(1, 5):
            for gateway in ('ferrum', 'ferrum-baseline'):
                external_capture(root, pair, gateway, selected_mode=selected_mode)

    def test_trace_calibration_full_report_accepts_same_on_image_and_bound_producer_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'campaign'; root.mkdir()
            self.trace_campaign(root)
            result = profile.report(root, 'trace-calibration')
            self.assertTrue(result['internal_comparison_eligible'], result)
            self.assertTrue(result['external_traces_complete'], result)
            self.assertTrue(result['trace_comparison_eligible'], result)
            self.assertFalse(result['fully_measured_comparison_eligible'])
            self.assertEqual(len(result['observations']), 12)
            for row in result['observations']:
                if row['gateway'] != 'direct':
                    self.assertTrue(row['profile']['complete'])
                    self.assertTrue(row['external_trace']['validation_complete'], row['external_trace'])
                    self.assertEqual(row['runtime']['image_labels'][profile.OBSERVER_LABEL], 'on')

    def test_cpu_report_validates_partial_capture_without_promoting_unwind_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'campaign'; root.mkdir()
            self.trace_campaign(root, 'cpu')
            result = profile.report(root, 'trace-calibration')
            self.assertTrue(result['trace_comparison_eligible'], result)
            for row in result['observations']:
                if row['gateway'] == 'ferrum':
                    cpu = row['external_trace']['cpu']
                    self.assertFalse(cpu['samples_complete'])
                    self.assertFalse(cpu['unwind_complete'])
            artifact = root / 'pairs/pair_001/traces/ferrum_10240/perf.data'
            artifact.write_bytes(artifact.read_bytes() + b'changed')
            self.assertFalse(profile.report(root, 'trace-calibration')['external_traces_complete'])

    def test_trace_calibration_rejects_wrong_build_and_cross_arm_image_substitution(self):
        for mutation in ('wrong_observer', 'cross_arm_image'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'campaign'; root.mkdir()
                self.trace_campaign(root)
                for path in root.glob('pairs/*/diagnostics/ferrum-baseline_runtime.json'):
                    runtime = json.loads(path.read_text())
                    if mutation == 'wrong_observer':
                        for label in ('image_labels', 'container_labels'):
                            runtime[label][profile.OBSERVER_LABEL] = 'off'
                    else:
                        runtime['image_id'] = 'sha256:' + 'd' * 64
                    path.write_text(json.dumps(runtime))
                result = profile.report(root, 'trace-calibration')
                self.assertFalse(result['runtime_complete'])
                self.assertFalse(result['traffic_complete'])
                self.assertFalse(result['internal_comparison_eligible'])
                self.assertFalse(result['trace_comparison_eligible'])
                self.assertEqual(len(result['observations']), 12)

    def test_external_report_rejects_cross_arm_pair_mutation_and_missing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'campaign'; root.mkdir()
            self.trace_campaign(root)
            path = root / 'pairs/pair_001/traces/ferrum_10240/trace-manifest.json'
            original = path.read_text()
            variants = [json.loads((root / relative).read_text()) for relative in (
                'pairs/pair_001/traces/ferrum-baseline_10240/trace-manifest.json',
                'pairs/pair_002/traces/ferrum_10240/trace-manifest.json')]
            variants.append(dict(schema=1, mode='cpu', capture_complete=True))
            for field in ('input_hashes', 'identity', 'boundaries', 'ready', 'lifecycle', 'artifacts', 'selected_mode'):
                claim = json.loads(original); claim.pop(field); variants.append(claim)
            for field, value in (('pair', 2), ('pair', True), ('payload', 71680), ('arm', 'ferrum-baseline')):
                claim = json.loads(original); claim['binding'][field] = value; variants.append(claim)
            for field, value in (('schema', True), ('capture_complete', 1), ('external_enabled', 'true'),
                                 ('stop_requested', 1), ('selected_mode', 'cpu')):
                claim = json.loads(original); claim[field] = value; variants.append(claim)
            for claim in variants:
                path.write_text(json.dumps(claim))
                result = profile.report(root, 'trace-calibration')
                row = next(r for r in result['observations'] if (r['pair'], r['gateway']) == (1, 'ferrum'))
                self.assertFalse(row['external_trace']['capture_complete'])
                self.assertFalse(row['external_trace']['validation_complete'])
                self.assertEqual(row['external_trace']['producer_claim'], claim)
                self.assertFalse(result['external_traces_complete'])
                self.assertFalse(result['trace_comparison_eligible'])
            path.write_text(original)
            # Actual retained bytes, including still-valid traffic JSON, bind the
            # claim. Neither a copied filename nor capture_complete can repair it.
            for evidence in ('pairs/pair_001/ferrum_http1-tls_10240.json',
                             'pairs/pair_001/traces/ferrum_10240/syscalls.jsonl',
                             'pairs/pair_001/traces/ferrum_10240/teardown-ready.json'):
                target = root / evidence; before = target.read_bytes()
                target.write_bytes(before + b'\n')
                result = profile.report(root, 'trace-calibration')
                self.assertFalse(result['external_traces_complete'], evidence)
                target.write_bytes(before)
            for evidence in ('syscalls.jsonl', 'ready.json', 'capabilities.json', 'bind.json'):
                target = path.parent / evidence; before = target.read_bytes(); target.unlink()
                result = profile.report(root, 'trace-calibration')
                self.assertFalse(result['external_traces_complete'], evidence)
                target.write_bytes(before)
            self.assertTrue(profile.report(root, 'trace-calibration')['trace_comparison_eligible'])

    def assert_runtime_failure(self, root, mode, gateway, pair=1):
        self.assert_matrix(root, mode=mode)
        report = json.loads((root / "h1_profile_report.json").read_text())
        for key in ("runtime_complete", "traffic_complete", "profiles_complete"):
            self.assertFalse(report[key], key)
        rows = [row for row in report["observations"] if row["gateway"] == gateway and row["pair"] == pair]
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row["runtime_issues"] for row in rows))
        return rows

    def test_every_arm_requires_typed_runtime_revision_image_observer_and_environment(self):
        for mode in ("calibration", "cutoff"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                campaign(root, mode)
                for gateway in profile.MANIFEST["campaigns"][mode]:
                    path = root / "pairs/pair_001/diagnostics" / f"{gateway}_runtime.json"
                    original = json.loads(path.read_text())
                    cases = [None, [], "invalid", {}]
                    for key, value in (
                            ("runtime_schema", True), ("pair", 2), ("gateway", "direct"),
                            ("host_id", "other-host"), ("h1_profile_mode", "diagnostic"),
                            ("capture_issues", None), ("capture_issues", ["failed"]),
                            ("running", False), ("running", 1), ("started_at", "time"),
                            ("started_at", "2026-99-18T10:00:00Z"), ("started_at", []),
                            ("started_at", "1970-01-01T00:00:11Z"),
                            ("container_id", "a"), ("host_pid", True), ("start_ticks", 0),
                            ("network_mode", "bridge"), ("identity_error", "unavailable"),
                            ("metrics_endpoint", "http://127.0.0.1:9001/metrics"),
                            ("image_id", "ferrum-h1:on"), ("image_id", []),
                            ("config_sha256", True), ("other_environment_sha256", None),
                            ("other_mounts_sha256", "bad"), ("environment", []),
                            ("environment", {}), ("config_mount", []), ("command", None)):
                        cases.append(dict(original, **{key: value}))
                    for key in ("image_id", "image_labels", "container_labels", "environment",
                                "config_sha256", "config_mount", "other_environment_sha256"):
                        missing = copy.deepcopy(original)
                        missing.pop(key)
                        cases.append(missing)
                    for key in ("image_labels", "container_labels"):
                        for value in (None, [], {}, {profile.REVISION_LABEL: REVISION}):
                            cases.append(dict(original, **{key: value}))
                        for label, value in (
                                (profile.REVISION_LABEL, None), (profile.REVISION_LABEL, REVISION[:12]),
                                (profile.REVISION_LABEL, "d" * 40), (profile.REVISION_LABEL, []),
                                (profile.OBSERVER_LABEL, None), (profile.OBSERVER_LABEL, True),
                                (profile.OBSERVER_LABEL, "on" if gateway == "ferrum-baseline" else "off")):
                            bad = copy.deepcopy(original)
                            bad[key][label] = value
                            cases.append(bad)
                    for key, value in ((profile.CUTOFF_ENV, "0" if gateway == "ferrum-exp-cutoff-one" else "1"),
                                       ("FERRUM_MODE", "database"), ("FERRUM_FILE_CONFIG_PATH", "/tmp/other"),
                                       ("FERRUM_METRICS_ALLOWED_CIDRS", "0.0.0.0/0"),
                                       ("FERRUM_POOL_MAX_IDLE_PER_HOST", "1"),
                                       ("FERRUM_PROXY_HTTP_PORT", True), ("FERRUM_LOG_LEVEL", {})):
                        bad = copy.deepcopy(original)
                        bad["environment"][key] = value
                        cases.append(bad)
                    for key, value in (("source", None), ("source", "relative.yaml"),
                                       ("destination", "/tmp/config.yaml"), ("read_only", 1), ("type", "volume")):
                        bad = copy.deepcopy(original)
                        bad["config_mount"][key] = value
                        cases.append(bad)
                    path.unlink()
                    self.assert_runtime_failure(root, mode, gateway)
                    for serialized in ("{bad", *[json.dumps(case) for case in cases]):
                        with self.subTest(mode=mode, gateway=gateway, case=serialized[:120]):
                            path.write_text(serialized)
                            self.assert_runtime_failure(root, mode, gateway)
                    path.write_text(json.dumps(original))
                self.assert_matrix(root, eligible=True, mode=mode)

    def test_pairing_across_all_pairs_and_actual_config_bytes(self):
        for mode in ("calibration", "cutoff"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                campaign(root, mode)
                for gateway in profile.MANIFEST["campaigns"][mode]:
                    folder = root / "pairs/pair_004/diagnostics"
                    path, config = folder / f"{gateway}_runtime.json", folder / f"{gateway}_config.yaml"
                    original, content = json.loads(path.read_text()), config.read_bytes()
                    for key in ("image_id", "other_environment_sha256", "other_mounts_sha256"):
                        with self.subTest(mode=mode, gateway=gateway, key=key):
                            value = ("sha256:" if key == "image_id" else "") + "e" * 64
                            path.write_text(json.dumps(dict(original, **{key: value})))
                            rows = self.assert_runtime_failure(root, mode, gateway, pair=4)
                            self.assertTrue(any("pairing mismatch" in issue for issue in rows[0]["runtime_issues"]))
                            path.write_text(json.dumps(original))
                    changed = copy.deepcopy(original)
                    changed["environment"]["FERRUM_LOG_LEVEL"] = "warn"  # valid alone, unequal in campaign
                    path.write_text(json.dumps(changed))
                    self.assert_runtime_failure(root, mode, gateway, pair=4)
                    path.write_text(json.dumps(original))
                    config.unlink()
                    self.assert_runtime_failure(root, mode, gateway, pair=4)
                    changed_content = content.replace(b"backend_read_timeout_ms: 30000", b"backend_read_timeout_ms: 30001")
                    self.assertNotEqual(content, changed_content)
                    config.write_bytes(changed_content)
                    self.assert_runtime_failure(root, mode, gateway, pair=4)  # retained hash was stale
                    changed = dict(original, config_sha256=hashlib.sha256(changed_content).hexdigest())
                    path.write_text(json.dumps(changed))
                    rows = self.assert_runtime_failure(root, mode, gateway, pair=4)  # hash alone is not pairing
                    self.assertIn("campaign config pairing mismatch", rows[0]["runtime_issues"])
                    path.write_text(json.dumps(original))
                    config.write_bytes(content)
                self.assert_matrix(root, eligible=True, mode=mode)
                manifest_path = root / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                for revision in (None, True, [], REVISION[:12], "d" * 40):
                    manifest_path.write_text(json.dumps(dict(manifest, h1_revision=revision)))
                    self.assert_runtime_failure(root, mode, "ferrum")

    def test_calibration_cannot_relabel_one_image_as_both_observers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign(root, "calibration")
            for path in root.glob("pairs/*/diagnostics/ferrum-baseline_runtime.json"):
                runtime = json.loads(path.read_text())
                runtime["image_id"] = "sha256:" + "c" * 64
                path.write_text(json.dumps(runtime))
            self.assert_runtime_failure(root, "calibration", "ferrum-baseline")

    def test_observer_off_control_requires_its_owned_process_through_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign(root, "calibration")
            path = root / "pairs/pair_001/diagnostics/ferrum-baseline_10240_process_usage.json"
            original = json.loads(path.read_text())
            cases = [None, [], {}, dict(original, capture_complete=False), dict(original, timeline=[])]
            for mutate in (
                    lambda u: u.pop("h1_gateway"),
                    lambda u: u["h1_gateway"].update(container_id="d" * 64),
                    lambda u: u["timeline"][1]["processes"].clear(),
                    lambda u: u["timeline"][1]["processes"][0].update(start_ticks=101),
                    lambda u: u["timeline"][1]["processes"].append(dict(pid=32, start_ticks=100, role="gateway"))):
                invalid = copy.deepcopy(original)
                mutate(invalid)
                cases.append(invalid)
            for usage in cases:
                path.write_text(json.dumps(usage))
                self.assert_matrix(root, mode="calibration")
                result = json.loads((root / "h1_profile_report.json").read_text())
                row = next(r for r in result["observations"] if (r["pair"], r["gateway"], r["payload"]) ==
                           (1, "ferrum-baseline", 10240))
                self.assertIn("missing/mismatched owned runtime process bracket", row["runtime_issues"])
                self.assertFalse(row["profile"]["expected"])
                self.assertFalse(result["runtime_complete"])
            path.write_text(json.dumps(original))
            sample_path = root / "pairs/pair_001/ferrum-baseline_http1-tls_10240.json"
            sample = json.loads(sample_path.read_text())
            sample["process_usage"]["measurement"][-1]["pid"] = 999
            sample_path.write_text(json.dumps(sample))
            self.assert_matrix(root, mode="calibration")

    def test_campaign_rejects_legacy_and_substituted_samples_without_losing_rows(self):
        from benchmark_validity import sample_issues
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample_path, _ = campaign(root)
            original = json.loads(sample_path.read_text())
            legacy = dict(total_requests=100, total_errors=0, rps=100,
                          payload_size=10240, total_bytes=1024000)
            self.assertEqual(sample_issues(legacy), [])  # the inherited false positive
            cases = [legacy]
            for key, value in (("sample_schema", 1), ("sample_schema", 2.0), ("pair", 2),
                               ("pair", True), ("gateway", "ferrum-exp-cutoff-one"),
                               ("payload_size", 71680), ("host_id", "other-host"),
                               ("host_id", ""), ("protocol", "http1-tls"), ("protocol", "HTTP/2"),
                               ("duration_secs", 30), ("effective_concurrency", 50),
                               ("concurrency", 50)):
                cases.append(dict(original, **{key: value}))
            bad_phase = copy.deepcopy(original)
            bad_phase["phases"]["measurement_secs"] = 30
            cases.append(bad_phase)
            diagnostic = copy.deepcopy(original)
            diagnostic["phases"]["h1_diagnostic"] = {}
            cases.append(diagnostic)
            for sample in cases:
                with self.subTest(sample=sample.get("protocol"), fields=sample.keys()):
                    sample_path.write_text(json.dumps(sample))
                    row = self.assert_matrix(root)
                    self.assertTrue(row["traffic_issues"])
                    self.assertEqual(row["sample"], sample)

    def test_manifest_requires_host_and_declared_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign(root)
            path = root / "manifest.json"
            original = json.loads(path.read_text())
            for key, value in (("host_id", None), ("host_id", "  "), ("sample_schema", 1),
                               ("protocol", "http2"), ("duration", 30), ("offered_workers", 50),
                               ("pairs", 2), ("h1_profile_mode", "diagnostic"),
                               ("h1_diagnostic_enabled", True),
                               ("gateways", ["direct"]), ("payload_sizes", [True])):
                with self.subTest(key=key):
                    path.write_text(json.dumps(dict(original, **{key: value})))
                    self.assert_matrix(root)
                    self.assertTrue(json.loads((root / "h1_profile_report.json").read_text())["manifest_issues"])
            path.write_text("{}")
            self.assert_matrix(root)

    def test_time_bounds_gaps_integer_ids_and_clocks_retain_partial_deltas(self):
        self.assertTrue(bracket(capture())["complete"])
        oversized = capture(times=[0, 60])
        result = bracket(oversized, dict(measurement_start_unix_secs=10, measurement_secs=15))
        self.assertFalse(result["complete"])
        self.assertGreater(result["boundary_slack_secs"], 2)
        self.assertIn("published_delta", result)
        cases = []
        gap = capture(duration=15)
        del gap["timeline"][5:10]
        cases.append((gap, "gap"))
        # Consecutive IDs cannot hide an actual scheduling pause either.
        paused = copy.deepcopy(gap)
        for index, row in enumerate(paused["timeline"]):
            row["h1_profile"]["sample_id"] = index
        cases.append((paused, "sampling gap"))
        for key, value in (("sample_id", 1.5), ("sample_id", True), ("sample_id", -1),
                           ("sample_id", 0), ("sample_id", float("nan")),
                           ("monotonic_secs", None), ("monotonic_secs", 109),
                           ("monotonic_secs", float("inf")), ("unix_secs", 10.35)):
            data = capture(duration=15)
            data["timeline"][1]["h1_profile"][key] = value
            cases.append((data, key))
        drift = capture(duration=15)
        for index, row in enumerate(drift["timeline"]):
            row["h1_profile"]["monotonic_secs"] += index * 0.01
        cases.append((drift, "clock discontinuity"))
        negative_clock = capture(duration=15)
        for row in negative_clock["timeline"]:
            row["h1_profile"]["monotonic_secs"] -= 1000
        # Preserve cadence and wall/monotonic deltas: negativity itself must fail.
        negative_result = bracket(negative_clock, dict(measurement_start_unix_secs=10, measurement_secs=15))
        self.assertIn("missing, negative or non-increasing capture monotonic_secs", negative_result["issues"])
        self.assertIn("published_delta", negative_result)
        cases.append((negative_clock, "negative monotonic clock"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, usage_path = campaign(root)
            for data, label in cases + [(oversized, "slack")]:
                with self.subTest(label=label):
                    usage_path.write_text(json.dumps(data))
                    row = self.assert_matrix(root)
                    self.assertFalse(row["profile"]["complete"])
                    self.assertTrue(row["profile"]["issues"])
                    self.assertIn("published_delta", row["profile"])

    def test_owned_binding_required_for_every_row_and_stable_unrelated_pids_fail(self):
        cases = []
        unrelated = capture(duration=15)
        for row in unrelated["timeline"]:
            row["h1_profile"]["counters"]["pid"] = 2
        cases.append(unrelated)
        for mutate in (
                lambda p: p.pop("gateway_binding"),
                lambda p: p.update(identity_error="unavailable"),
                lambda p: p["gateway_binding"].update(container_id="b" * 64),
                lambda p: p["gateway_binding"].update(endpoint="http://127.0.0.1:9001/metrics"),
                lambda p: p["gateway_binding"]["before"].update(start_ticks=101),
                lambda p: p["gateway_binding"]["after"].update(start_ticks=101),
                lambda p: p["gateway_binding"]["after"].update(listener_inode=1235),
                lambda p: p["gateway_binding"]["after"].update(namespace_pids=[31, True]),
                lambda p: p["gateway_binding"].update(before=[], after=[])):
            data = capture(duration=15)
            mutate(data["timeline"][1]["h1_profile"])
            cases.append(data)
        for processes in ([], [dict(pid=31, start_ticks=101, role="gateway")],
                          [dict(pid=31, start_ticks=100, role="gateway")] * 2,
                          [dict(pid=31, start_ticks=100, role="gateway"),
                           dict(pid=32, start_ticks=100, role="gateway")]):
            data = capture(duration=15)
            data["timeline"][1]["processes"] = processes
            cases.append(data)
        stale = capture(duration=15)
        stale["h1_gateway"]["container_id"] = "b" * 64
        cases.append(stale)
        missing = capture(duration=15)
        missing.pop("h1_gateway")
        cases.append(missing)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, usage_path = campaign(root)
            for index, data in enumerate(cases):
                with self.subTest(case=index):
                    usage_path.write_text(json.dumps(data))
                    row = self.assert_matrix(root)
                    self.assertFalse(row["profile"]["complete"])
                    self.assertTrue(row["profile"]["issues"])
                    self.assertIn("published_delta", row["profile"])
            usage_path.write_text(json.dumps(capture(duration=15)))
            runtime_path = usage_path.parent / "ferrum_runtime.json"
            for runtime in (None, dict(owned_gateway(), start_ticks=101),
                            dict(owned_gateway(), identity_error="unavailable")):
                runtime_path.write_text(json.dumps(runtime))
                row = self.assert_matrix(root)
                self.assertIn("published_delta", row["profile"])
                self.assertFalse(row["profile"]["complete"])

    def test_semantic_metadata_and_guaranteed_response_work(self):
        cases = []
        for fields in (dict(pid=0), dict(slot_capacity=127), dict(registered_slots=0),
                       dict(registered_slots=129)):
            data = capture(duration=15)
            for row in data["timeline"]:
                row["h1_profile"]["counters"].update(fields)
            cases.append(data)
        decreasing = capture(duration=15)
        decreasing["timeline"][0]["h1_profile"]["counters"]["registered_slots"] = 3
        cases.append(decreasing)
        for zero_all in (False, True):
            data = capture(duration=15)
            for row in data["timeline"]:
                counters = row["h1_profile"]["counters"]
                if zero_all:
                    counters.update(dict.fromkeys(profile.SCHEMA["counters"], 0))
                else:
                    counters["body_proxy_output_all_data_bytes"] = 1024  # stale positive total
            cases.append(data)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, usage_path = campaign(root)
            for index, data in enumerate(cases):
                with self.subTest(case=index):
                    usage_path.write_text(json.dumps(data))
                    row = self.assert_matrix(root)
                    self.assertFalse(row["profile"]["complete"])
                    self.assertTrue(row["profile"]["issues"])
        # Optional coalescing/copy/write-vector counters may remain zero.
        valid = capture()
        self.assertEqual(valid["timeline"][-1]["h1_profile"]["counters"]["body_reqwest_coalesced_data_bytes"], 0)
        self.assertTrue(bracket(valid)["complete"])
        for index, row in enumerate(valid["timeline"]):
            row["h1_profile"]["counters"]["registered_slots"] = 125 + index
        self.assertTrue(bracket(valid)["complete"])

    def test_cpu_malformed_values_never_abort_or_zero_fill_the_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, usage_path = campaign(root)
            for value in (None, "0.1", [], {}, -0.1, True, float("nan"), float("inf"),
                          float("-inf"), "missing"):
                with self.subTest(value=value):
                    data = capture(duration=15)
                    row = data["timeline"][1]["h1_profile"]
                    if value == "missing":
                        row.pop("sampler_cpu_secs")
                    else:
                        row["sampler_cpu_secs"] = value
                    usage_path.write_text(json.dumps(data))
                    result = self.assert_matrix(root)["profile"]
                    self.assertIn("missing/invalid sampler CPU evidence", result["issues"])
                    self.assertIsNone(result["sampler_cpu_secs"])
                    self.assertIn("published_delta", result)
            for value in (0, 0.001):
                data = capture(duration=15)
                for row in data["timeline"]:
                    row["h1_profile"]["sampler_cpu_secs"] = value
                usage_path.write_text(json.dumps(data))
                result = self.assert_matrix(root, eligible=True)["profile"]
                self.assertAlmostEqual(result["sampler_cpu_secs"], value * len(data["timeline"]))

    def test_capture_reads_namespace_start_time_and_unique_owned_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "31"
            (proc / "net").mkdir(parents=True)
            (proc / "fd").mkdir()
            fields = ["0"] * 22
            fields[19] = "100"
            stat = "31 (ferrum (edge)) " + " ".join(fields)
            status = "Name:\tferrum-edge\nNSpid:\t31\t1\n"
            listener = "0: 0100007F:2328 00000000:0000 0A 0:0 0:0 0 0 0 1234\n"
            (proc / "stat").write_text(stat)
            (proc / "status").write_text(status)
            (proc / "net/tcp").write_text("header\n" + listener)
            (proc / "fd/7").symlink_to("socket:[1234]")
            processes = [dict(pid=31, start_ticks=100, role="gateway")]
            self.assertEqual(profile.gateway_binding(owned_gateway(), processes, root), binding()["before"])
            for path, malformed in (("stat", stat.replace("100", "101")),
                                    ("status", "NSpid:\t32\t1\n"), ("status", "Name: missing\n"),
                                    ("status", "NSpid:\t31\t0\n"),
                                    ("net/tcp", "header\n" + listener.replace("1234", "4321")),
                                    ("net/tcp", "header\n" + listener * 2),
                                    ("net/tcp", "header\n" + listener.replace("2328", "2329"))):
                with self.subTest(path=path, malformed=malformed):
                    original = (proc / path).read_text()
                    (proc / path).write_text(malformed)
                    with self.assertRaises(ValueError):
                        profile.gateway_binding(owned_gateway(), processes, root)
                    (proc / path).write_text(original)
            with patch.object(profile, "process_start_ticks", side_effect=[100, 101]):
                with self.assertRaisesRegex(ValueError, "changed during"):
                    profile.gateway_binding(owned_gateway(), processes, root)
            for records in ([], processes * 2, [dict(processes[0], start_ticks=101)]):
                with self.assertRaises(ValueError):
                    profile.gateway_binding(owned_gateway(), records, root)

    def test_snapshot_retains_binding_before_and_after_actual_scrape_call(self):
        text = "\n".join(f"{profile.PREFIX}{key} {value}" for key, value in values().items())
        events = []
        processes = [dict(pid=31, start_ticks=100, role="gateway")]

        def bind(runtime, observed):
            self.assertEqual(runtime, owned_gateway())
            self.assertEqual(observed, processes)
            events.append("binding")
            return binding()["before"]

        def read(limit):
            self.assertEqual(limit, 2 * 1024 * 1024 + 1)
            events.append("metrics")
            return text.encode()

        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.side_effect = read
        with patch.object(profile, "gateway_binding", side_effect=bind), \
                patch.object(profile.urllib.request, "build_opener", return_value=opener):
            result = profile.snapshot(7, processes, owned_gateway())
        self.assertEqual(events, ["binding", "metrics", "binding"])
        self.assertEqual(result["gateway_binding"], binding())
        self.assertEqual(result["counters"], values())
        self.assertEqual(result["sample_id"], 7)
        self.assertNotIn("identity_error", result)
        self.assertGreaterEqual(result["capture_secs"], 0)
        self.assertGreaterEqual(result["sampler_cpu_secs"], 0)
        opener.open.assert_called_once_with(profile.METRICS_ENDPOINT, timeout=0.2)
        for error in (ValueError("reused process"), OSError("unavailable")):
            with patch.object(profile, "gateway_binding", side_effect=[binding()["before"], error]), \
                    patch.object(profile.urllib.request, "build_opener", return_value=opener):
                result = profile.snapshot(8, processes, owned_gateway())
            self.assertIn("identity_error", result)
            self.assertIn("counters", result)  # preserve partial metrics
            self.assertNotIn("after", result["gateway_binding"])

    def test_runtime_captures_actual_image_and_container_labels_by_immutable_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = root / "config.yaml", root / "runtime.json"
            config.write_text("proxies: []\n")
            for gateway in ("ferrum", "ferrum-baseline", "ferrum-exp-cutoff-one"):
                mode = "calibration" if gateway == "ferrum-baseline" else "cutoff"
                container, image = docker_inspect(config, gateway, mode=mode)
                with patch.object(profile, "process_start_ticks", return_value=100), \
                        patch.object(profile.subprocess, "run", return_value=MagicMock(stdout=json.dumps(image))) as inspect:
                    profile.retain_runtime(path, container, config, 1, gateway, "campaign-host", mode)
                inspect.assert_called_once_with(
                    ["bash", "tests/performance/multi_protocol/h1_runtime_image.sh"],
                    cwd=profile.ROOT.parents[2],
                    env=dict(profile.os.environ, FERRUM_H1_IMAGE_ID=container["Image"]),
                    check=True, capture_output=True, text=True, timeout=10)
                runtime = json.loads(path.read_text())
                for key in ("image_labels", "container_labels"):
                    self.assertEqual(runtime[key], {profile.REVISION_LABEL: REVISION,
                                                   profile.OBSERVER_LABEL: "off" if gateway == "ferrum-baseline" else "on"})
                self.assertEqual(runtime["config_sha256"], hashlib.sha256(config.read_bytes()).hexdigest())
                self.assertEqual(profile.runtime_issues(runtime, config, 1, gateway,
                                                        dict(host_id="campaign-host", h1_revision=REVISION), mode), [])

    def test_runtime_capture_failures_remain_safe_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = root / "config.yaml", root / "runtime.json"
            config.write_text("proxies: []\n")
            original_container, original_image = docker_inspect(config)
            for image_id in ("mutable:tag", "--help", "sha256:" + "a" * 63,
                             "sha256:" + "A" * 64, "sha256:" + "a" * 64 + "\n",
                             "$(touch do-not-retain-this)"):
                container = copy.deepcopy(original_container)
                container["Image"] = image_id
                with self.subTest(image_id=image_id), \
                        patch.object(profile, "process_start_ticks", return_value=100), \
                        patch.object(profile.subprocess, "run") as inspect:
                    profile.retain_runtime(path, container, config, 1, "ferrum", "campaign-host", "cutoff")
                inspect.assert_not_called()
                self.assertIn("immutable image/container label capture unavailable",
                              json.loads(path.read_text())["capture_issues"])
            failures = [(None, original_image), ([], original_image), ({}, original_image),
                        (original_container, None), (original_container, []), (original_container, {})]
            for mutate in (
                    lambda c: c.update(Image="mutable:tag"),
                    lambda c: c["Config"].update(Labels=None),
                    lambda c: c["Config"]["Labels"].update({profile.REVISION_LABEL: "d" * 40}),
                    lambda c: c["Config"]["Labels"].update({profile.OBSERVER_LABEL: "off"}),
                    lambda c: c["Config"].update(Env=None),
                    lambda c: c["Config"]["Env"].append("FERRUM_MODE=file"),
                    lambda c: c["Config"]["Env"].append("FERRUM_ADMIN_JWT_SECRET=do-not-retain-this"),
                    lambda c: c["Config"]["Env"].append("FERRUM_FILE_CONFIG_PATH_FILE=do-not-retain-this"),
                    lambda c: c["Config"]["Env"].append(None),
                    lambda c: c["Config"]["Env"].append("no-equals"),
                    lambda c: c["Config"]["Env"].append("HOSTNAME=foreign-override"),
                    lambda c: c["Config"].update(Cmd=["run", "--settings", "do-not-retain-this"]),
                    lambda c: c["State"].update(Running=False),
                    lambda c: c["Mounts"][0].update(RW=True),
                    lambda c: c["Mounts"][0].update(Source=str(root / "missing.yaml")),
                    lambda c: c["Mounts"][0].update(Destination="/etc/ferrum/other.yaml"),
                    lambda c: c["Mounts"].append(copy.deepcopy(c["Mounts"][0])),
                    lambda c: c.update(Mounts=None)):
                container = copy.deepcopy(original_container)
                mutate(container)
                failures.append((container, original_image))
            for mutate in (
                    lambda i: i.update(Id="sha256:" + "e" * 64),
                    lambda i: i["Config"].update(Labels=[]),
                    lambda i: i["Config"]["Labels"].pop(profile.REVISION_LABEL),
                    lambda i: i["Config"]["Labels"].update({profile.REVISION_LABEL: REVISION[:12]}),
                    lambda i: i["Config"]["Labels"].update({profile.OBSERVER_LABEL: True})):
                image = copy.deepcopy(original_image)
                mutate(image)
                failures.append((original_container, image))
            for index, (container, image) in enumerate(failures):
                with self.subTest(index=index), \
                        patch.object(profile, "process_start_ticks", return_value=100), \
                        patch.object(profile.subprocess, "run", return_value=MagicMock(stdout=json.dumps(image))):
                    profile.retain_runtime(path, container, config, 1, "ferrum", "campaign-host", "cutoff")
                runtime = json.loads(path.read_text())
                self.assertTrue(profile.runtime_issues(runtime, config, 1, "ferrum",
                                                       dict(host_id="campaign-host", h1_revision=REVISION), "cutoff"))
                self.assertNotIn("do-not-retain-this", path.read_text())
            for output in ("not-json", ""):
                with patch.object(profile, "process_start_ticks", return_value=100), \
                        patch.object(profile.subprocess, "run", return_value=MagicMock(stdout=output)):
                    profile.retain_runtime(path, original_container, config, 1, "ferrum", "campaign-host", "cutoff")
                self.assertIn("immutable image/container label capture unavailable",
                              json.loads(path.read_text())["capture_issues"])
            for error in (OSError("unavailable"), profile.subprocess.TimeoutExpired("docker", 10)):
                with patch.object(profile, "process_start_ticks", return_value=100), \
                        patch.object(profile.subprocess, "run", side_effect=error):
                    profile.retain_runtime(path, original_container, config, 1, "ferrum", "campaign-host", "cutoff")
                self.assertTrue(json.loads(path.read_text())["capture_issues"])

    def test_environment_hash_retains_hidden_differences_and_ignores_only_generated_hostname(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = root / "config.yaml", root / "runtime.json"
            config.write_text("proxies: []\n")
            original = retain_fixture(path, config)
            container, image = docker_inspect(config)
            container["Config"]["Env"].reverse()  # map order cannot change pairing
            container["Config"]["Env"].append("HOSTNAME=" + "a" * 12)
            for changed in (False, True):
                if changed:
                    container["Config"]["Env"].append("LD_PRELOAD=do-not-retain-this")
                with patch.object(profile, "process_start_ticks", return_value=100), \
                        patch.object(profile.subprocess, "run", return_value=MagicMock(stdout=json.dumps(image))):
                    profile.retain_runtime(path, container, config, 1, "ferrum", "campaign-host", "cutoff")
                runtime = json.loads(path.read_text())
                self.assertEqual(runtime["capture_issues"], [])
                self.assertEqual(runtime["other_environment_sha256"] == original["other_environment_sha256"], not changed)
                self.assertNotIn("do-not-retain-this", path.read_text())

    def test_runtime_and_sampler_bind_the_selected_container_not_a_stable_foreign_pid(self):
        from process_usage import sample_processes
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, config = root / "runtime.json", root / "config.yaml"
            config.write_text("proxies: []\n")
            retain_fixture(runtime, config)
            self.assertEqual(profile.gateway_identity(json.loads(runtime.read_text())), owned_gateway())
            stop, output = root / "stop", root / "usage.json"
            stop.touch()
            for selected in ("a" * 64, "b" * 64):
                calls = []

                def snap(sample_id, processes, owned):
                    calls.append((sample_id, processes, owned))
                    return dict(counters=values())

                with patch("process_usage.signal.signal"), \
                        patch("process_usage.os.sysconf", return_value=100), \
                        patch("process_usage.client_pids", return_value=[]), \
                        patch("process_usage.capture", return_value=dict(
                            start_ticks=100, cpu_seconds=1, rss_bytes=1024)), \
                        patch.object(profile, "snapshot", side_effect=snap):
                    sample_processes(30, [31], output, 0.5, parent_pid=42, stop_file=stop,
                                     h1_profile=True, h1_runtime=runtime, h1_container_id=selected)
                result = json.loads(output.read_text())
                self.assertEqual([call[0] for call in calls], [0, 1])
                for _, processes, owned in calls:
                    self.assertEqual([p["pid"] for p in processes if p["role"] == "gateway"], [31])
                    self.assertEqual(owned, owned_gateway() if selected == "a" * 64 else None)
                self.assertEqual(result["h1_gateway"], owned_gateway() if selected == "a" * 64 else None)
                if selected != "a" * 64:
                    self.assertTrue(all(row["h1_profile"]["identity_error"] for row in result["timeline"]))
            container, image = docker_inspect(config)
            container["HostConfig"]["NetworkMode"] = "bridge"
            with patch.object(profile.subprocess, "run", return_value=MagicMock(stdout=json.dumps(image))):
                profile.retain_runtime(runtime, container, config, 1, "ferrum", "campaign-host", "cutoff")
            self.assertIn("identity_error", json.loads(runtime.read_text()))

    def test_diagnostic_slice_cannot_change_bounds_or_enter_full_comparisons(self):
        args = ["diagnostic", "http1-tls", "1", "30", "200", "ferrum", "5242880", "", ""]
        profile.validate_selection(*args)
        for index, replacement in [(1, "http3"), (2, "2"), (3, "31"), (4, "100"),
                                   (5, "ferrum envoy"), (6, "1048576"), (7, "image"),
                                   (8, "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)
        with tempfile.TemporaryDirectory() as directory:
            result = profile.report_diagnostic(directory)
            self.assertEqual(len(result["observations"]), 3)
            self.assertFalse(result["complete"])
            self.assertFalse(result["comparison_eligible"])
            self.assertTrue(all(row["issues"] for row in result["observations"]))

    def test_diagnostic_success_and_retained_failures_always_leave_cause_unproven(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = diagnostic_campaign(root)
            original = json.loads(path.read_text())
            result = profile.report_diagnostic(root)
            self.assertTrue(result["complete"], result)
            self.assertFalse(result["comparison_eligible"])
            self.assertIn("unproven", result["cause"])
            for mutate in (
                    lambda s: s.update(error="retained drain failure"),
                    lambda s: s.update(sample_schema=1),
                    lambda s: s.update(gateway="direct"),
                    lambda s: s.update(pair=True),
                    lambda s: s.update(host_id="copied-host"),
                    lambda s: s.update(payload_size=1),
                    lambda s: s.update(duration_secs=15),
                    lambda s: s.update(concurrency=1),
                    lambda s: s.update(order_position=3),
                    lambda s: s.update(samples=[]),
                    lambda s: s["phases"].update(timed_out=True),
                    lambda s: s["phases"]["h1_diagnostic"].update(pid=30),
                    lambda s: s["phases"]["h1_diagnostic"].update(schema=True),
                    lambda s: s["phases"]["h1_diagnostic"]["loss"].clear(),
                    lambda s: s["phases"]["h1_diagnostic"]["loss"].update(updates=1),
                    lambda s: s["phases"]["h1_diagnostic"]["loss"].update(workers=False),
                    lambda s: s["phases"]["h1_diagnostic"]["retirement"].pop("elapsed_secs"),
                    lambda s: s["phases"]["h1_diagnostic"]["retirement"].update(completed_ok=49),
                    lambda s: s["phases"]["h1_diagnostic"]["retirement"].update(cancelled=1),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"].clear(),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1].update(reason="request_drain_complete"),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1].update(workers=[{}] * 50),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["workers"][0].update(id=1),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["workers"][0].pop("request"),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["workers"][0].update(lifecycle="running"),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["workers"][0]["request"].update(body_end=None),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["connections"].clear(),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["connections"][0].update(worker_id=1),
                    lambda s: s["phases"]["h1_diagnostic"]["snapshots"][-1]["connections"][0].update(driver="running")):
                sample = copy.deepcopy(original)
                mutate(sample)
                path.write_text(json.dumps(sample))
                result = profile.report_diagnostic(root)
                self.assertFalse(result["complete"], sample)
                self.assertFalse(result["comparison_eligible"])
                self.assertIn("unproven", result["cause"])
                self.assertEqual(len(result["observations"]), 3)
                self.assertTrue(result["observations"][1]["issues"])
                self.assertEqual(result, json.loads((root / "h1_diagnostic_report.json").read_text()))

    def test_diagnostic_manifest_runtime_and_copy_rejection(self):
        for target, mutate in (
                ("manifest.json", lambda v: v.update(h1_revision="wrong")),
                ("manifest.json", lambda v: v.update(h1_diagnostic_enabled=False)),
                ("manifest.json", lambda v: v.update(pairs=4)),
                ("manifest.json", lambda v: v.update(duration=15)),
                ("manifest.json", lambda v: v.update(offered_workers=50)),
                ("manifest.json", lambda v: v.update(payload_sizes=[1])),
                ("manifest.json", lambda v: v.update(gateways=["direct"])),
                ("diagnostic_termination.json", lambda v: v.update(status="budget_exhausted")),
                ("diagnostic_termination.json", lambda v: v.update(cleanup_complete=False)),
                ("pairs/pair_001/diagnostics/ferrum_runtime.json", lambda v: v["image_labels"].update({profile.OBSERVER_LABEL: "on"})),
                ("pairs/pair_001/diagnostics/ferrum_runtime.json", lambda v: v["container_labels"].update({profile.REVISION_LABEL: "d" * 40})),
                ("pairs/pair_001/diagnostics/ferrum_runtime.json", lambda v: v.update(config_sha256="a" * 64)),
                ("pairs/pair_001/diagnostics/ferrum-exp-cutoff-one_runtime.json", lambda v: v.update(image_id="sha256:" + "f" * 64)),
                ("pairs/pair_001/diagnostics/ferrum_runtime.json", lambda v: v["environment"].update({profile.CUTOFF_ENV: "1"})),
                ("pairs/pair_001/diagnostics/ferrum_5242880_process_usage.json", lambda v: v.update(h1_gateway=None))):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                diagnostic_campaign(root)
                path = root / target
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value))
                result = profile.report_diagnostic(root)
                self.assertFalse(result["complete"])
                self.assertEqual(len(result["observations"]), 3)
        for absent in ("manifest.json", "diagnostic_termination.json",
                       "pairs/pair_001/diagnostics/ferrum_runtime.json",
                       "pairs/pair_001/diagnostics/ferrum_config.yaml"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                diagnostic_campaign(root)
                (root / absent).unlink()
                self.assertFalse(profile.report_diagnostic(root)["complete"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = diagnostic_campaign(root)
            copied = path.read_text()
            for arm in ("direct", "ferrum-exp-cutoff-one"):
                (path.parent / f"{arm}_http1-tls_5242880.json").write_text(copied)
            self.assertTrue(all(r["issues"] for r in profile.report_diagnostic(root)["observations"]))

    def test_off_and_on_share_temporal_gate_and_preserve_partial_cpu(self):
        for gateway in ("ferrum-baseline", "ferrum"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                campaign(root, "calibration")
                path = root / f"pairs/pair_001/diagnostics/{gateway}_10240_process_usage.json"
                original = json.loads(path.read_text())
                for mutate in (
                        lambda u: u.update(timeline=[u["timeline"][0], u["timeline"][-1]]),
                        lambda u: u["timeline"][-1]["h1_profile"].update(unix_secs=40, monotonic_secs=140),
                        lambda u: u["timeline"][2]["h1_profile"].update(monotonic_secs=200),
                        lambda u: u["timeline"][2]["h1_profile"].update(capture_secs=2),
                        lambda u: u["timeline"][2]["h1_profile"].update(sample_id=99),
                        lambda u: u["timeline"][2].pop("h1_profile"),
                        lambda u: u["timeline"][2]["h1_profile"].update(sampler_cpu_secs=True),
                        lambda u: u["timeline"][2]["h1_profile"]["gateway_binding"]["after"].update(listener_inode=999)):
                    usage = copy.deepcopy(original)
                    mutate(usage)
                    path.write_text(json.dumps(usage))
                    result = profile.report(root, "calibration")
                    self.assertFalse(result["runtime_complete"])
                    self.assertFalse(result["fully_measured_comparison_eligible"])
                    row = next(r for r in result["observations"] if r["gateway"] == gateway and r["pair"] == 1)
                    self.assertTrue(row["runtime_issues"])
                    self.assertEqual(row["sample"]["process_usage"]["measurement"][-1]["cpu_seconds"], 1)
                    self.assertEqual(len(result["observations"]), 60)

    def test_h1_diagnostic_is_registered_without_changing_cadence_or_retry_policy(self):
        root = Path(__file__).resolve().parents[4]
        workflow = (root / ".github/workflows/h1-internal-profile.yml").read_text()
        self.assertIn("--test metrics_tests h1_diagnostic_tests", workflow)
        self.assertIn("--duration 30 --concurrency 200 --pairs 1 --payload-sizes 5242880", workflow)
        self.assertLess(workflow.index("id: diagnostic"), workflow.index("id: calibration"))
        self.assertIn("--test functional_tests h1_cadence_tests::", workflow)
        runner = (root / "tests/performance/multi_protocol/run_gateway_protocol_bench.sh").read_text()
        self.assertIn('extra_args+=(--h1-diagnostic)', runner)
        self.assertIn('> "$diagnostics/${gateway}_${payload}_client.raw.json"', runner)
        self.assertIn("One pass only: never pair, extend, rerun", runner)

    @unittest.skipUnless(sys.platform == "linux", "hosted Linux session ownership")
    def test_diagnostic_supervisor_bounds_actual_children_and_retains_all_rows(self):
        import h1_diagnostic_campaign as campaign_runner
        # Exercise the real deadline/termination/report producer. Only the
        # expensive gateway workload and Docker cleanup dispatch are replaced;
        # actual child sessions include a TERM-resistant, separate process group.
        for scenario in ("completed", "startup_stall", "reader_stall", "cleanup_stall",
                         "cleanup_timeout", "report_timeout"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stalled = scenario.endswith("stall") or scenario == "cleanup_timeout"
                if stalled:
                    child = subprocess.Popen(
                        ["python3", "-c", "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); child=os.fork(); os.setpgid(0,0) if child==0 else None; time.sleep(60)"],
                        start_new_session=True)
                else:
                    child = subprocess.Popen(["python3", "-c", "import time; time.sleep(0.15)"],
                                             start_new_session=True)
                identity = campaign_runner.process_identity(child.pid)
                calls = []

                def launch(command, **kwargs):
                    self.assertEqual(command, ["bash", "tests/performance/multi_protocol/h1_diagnostic_campaign.sh"])
                    self.assertTrue(kwargs["start_new_session"])
                    self.assertTrue((root / "h1_diagnostic_report.json").exists())
                    diagnostic_campaign(root)
                    (root / "retained.raw.json").write_text('{"partial":')
                    return child

                def dispatch(command, **kwargs):
                    calls.append(command[-1])
                    self.assertGreater(kwargs["timeout"], 0)
                    if command[-1].endswith("cleanup.sh"):
                        if scenario == "cleanup_timeout":
                            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
                        result = campaign_runner.terminate_session(
                            child.pid, identity["start_ticks"], time.monotonic() + 0.3)
                        return subprocess.CompletedProcess(command, 0 if result["complete"] else 1)
                    self.assertEqual(command, ["bash", "tests/performance/multi_protocol/h1_diagnostic_report.sh"])
                    if scenario == "report_timeout":
                        raise subprocess.TimeoutExpired(command, kwargs["timeout"])
                    report = profile.report_diagnostic(root)
                    return subprocess.CompletedProcess(command, 0 if report["complete"] else 1)

                try:
                    started = time.monotonic()
                    with patch.object(campaign_runner.subprocess, "Popen", side_effect=launch), \
                            patch.object(campaign_runner.subprocess, "run", side_effect=dispatch):
                        code = campaign_runner.supervise(root, 2)
                    elapsed = time.monotonic() - started
                    self.assertLess(elapsed, 2.5)  # scheduling tolerance, not an enlarged policy budget
                    state = json.loads((root / "diagnostic_termination.json").read_text())
                    report = json.loads((root / "h1_diagnostic_report.json").read_text())
                    self.assertEqual(len(report["observations"]), 3)
                    self.assertFalse(report["comparison_eligible"])
                    self.assertEqual((root / "retained.raw.json").read_text(), '{"partial":')
                    self.assertEqual(code == 0, scenario == "completed", state)
                    self.assertEqual(report["complete"], scenario == "completed", report)
                    self.assertTrue(any(path.endswith("cleanup.sh") for path in calls))
                    if stalled:
                        self.assertEqual(state["status"], "budget_exhausted")
                    if scenario == "cleanup_timeout":
                        self.assertFalse(state["cleanup_complete"])
                    child.wait(timeout=1)
                    self.assertEqual(campaign_runner.session_processes(child.pid, identity["start_ticks"]), [])
                finally:
                    campaign_runner.terminate_session(child.pid, identity["start_ticks"], time.monotonic() + 1)
                    child.wait(timeout=1)

    def test_diagnostic_supervisor_launch_failure_preserves_seeded_failed_report(self):
        import h1_diagnostic_campaign as campaign_runner
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(campaign_runner.subprocess, "Popen", side_effect=OSError("startup failed")), \
                patch.object(campaign_runner.subprocess, "run", side_effect=OSError("cleanup unavailable")):
            root = Path(directory)
            self.assertEqual(campaign_runner.supervise(root, 2), 1)
            report = json.loads((root / "h1_diagnostic_report.json").read_text())
            self.assertEqual(len(report["observations"]), 3)
            self.assertTrue(all(row["issues"] for row in report["observations"]))
            self.assertFalse(report["complete"])
            self.assertFalse(report["termination"]["cleanup_complete"])

    def test_reports_retain_failed_and_missing_five_mib_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps(dict(
                pairs=4, gateways=["direct", "ferrum", "ferrum-exp-cutoff-one"], payload_sizes=[5242880])))
            malformed = root / "pairs/pair_001/direct_http1-tls_5242880.json"
            malformed.parent.mkdir(parents=True)
            malformed.write_text("[]")
            result = profile.report(root, "cutoff")
            self.assertEqual(len(result["observations"]), 12)
            self.assertFalse(result["traffic_complete"])
            self.assertFalse(result["profiles_complete"])
            self.assertFalse(result["fully_measured_comparison_eligible"])
            self.assertTrue(all(row["traffic_issues"] for row in result["observations"]))


if __name__ == "__main__":
    unittest.main()
