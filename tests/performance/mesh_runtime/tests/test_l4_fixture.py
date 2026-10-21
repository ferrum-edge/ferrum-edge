"""Cheap captured-L4 contracts: no real Docker, namespaces, or benchmark load."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

DIRECTORY = Path(__file__).resolve().parents[1]
ROOT = DIRECTORY.parents[2]
spec = importlib.util.spec_from_file_location("mesh_l4_fixture", DIRECTORY / "mesh_l4_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
shell = (DIRECTORY / "mesh_l4_fixture.sh").read_text()


class CapturedL4Fixture(unittest.TestCase):
    def test_tcp_vip_and_destination_only_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fixture.render(directory, "172.25.0.1", "192.0.2.50", 18080, 18082)
            source = json.loads((directory / "source.json").read_text())["mesh"]
            allow = json.loads((directory / "destination-allow.json").read_text())["mesh"]
            deny = json.loads((directory / "destination-deny.json").read_text())["mesh"]
            self.assertEqual(source["services"][0]["cluster_ips"], ["192.0.2.50"])
            self.assertEqual([p["protocol"] for p in source["services"][0]["ports"]], ["tcp", "tcp"])
            self.assertNotIn("mesh_policies", source)
            self.assertEqual(allow["mesh_policies"][0]["rules"][0]["action"], "allow")
            self.assertEqual(deny["mesh_policies"][-1]["rules"][0]["action"], "deny")
            self.assertEqual(deny["mesh_policies"][-1]["rules"][0]["from"][0]["spiffe_id_pattern"], fixture.SOURCE)
            svc = json.loads((directory / "consul-svc.json").read_text())
            raw = json.loads((directory / "consul-svc-raw.json").read_text())
            self.assertEqual(svc["service"]["connect"]["sidecar_service"]["port"], 21000)
            self.assertEqual(raw["service"]["connect"]["sidecar_service"]["port"], 21000)
            self.assertEqual(raw["service"]["connect"]["sidecar_service"]["proxy"]["local_service_port"], 18082)
            self.assertEqual(raw["service"]["connect"]["sidecar_service"]["proxy"]["local_service_address"], "172.25.0.1")
            self.assertEqual(svc["service"]["connect"]["sidecar_service"]["proxy"]["local_service_port"], 18080)

    def test_bootstrap_changes_only_agent_endpoint_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bootstrap.json"
            doc = {"static_resources": {"clusters": [
                {"name": "local_agent", "load_assignment": {"endpoints": [{"lb_endpoints": [
                    {"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 8502}}}}]}]}},
                {"name": "data", "transport_socket": {"name": "envoy.transport_sockets.tls"}}]}}
            path.write_text(json.dumps(doc))
            expected = copy.deepcopy(doc)
            expected["static_resources"]["clusters"][0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]["address"] = "172.25.0.1"
            fixture.adapt_bootstrap(path, "172.25.0.1")
            self.assertEqual(json.loads(path.read_text()), expected)
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError, "one Consul"):
                fixture.adapt_bootstrap(path, "172.25.0.1")

    def test_private_material_is_removed_before_config_artifact(self):
        doc = {"private_key": {"inline_bytes": "sensitive"}, "nested": [{"privateKey": "sensitive"},
               {"inline_string": "-----BEGIN PRIVATE KEY-----sensitive"}], "require_client_certificate": True}
        public = fixture.public_config(doc)
        self.assertNotIn("sensitive", json.dumps(public))
        self.assertIs(public["require_client_certificate"], True)
        self.assertEqual(doc["private_key"]["inline_bytes"], "sensitive")
        self.assertNotIn('/config_dump \\', shell)
        self.assertEqual(shell.count('config_dump?resource=dynamic_listeners'), 2)
        self.assertEqual(shell.count('public-config >'), 2)

    def ferrum_evidence(self, directory):
        fixture.render(directory / "l4-fixture-configs", "172.25.0.1", "192.0.2.50", 18080, 18082)
        passed = {"ok": True, "peer": ["192.0.2.50", 18082], "connections": 1,
                  "exchanges": 5, "payload_bytes": 272, "byte_exact": True, "half_close": True,
                  "whole_exchange_timeout_secs": 2}
        refused = {"ok": False, "kind": "ConnectionResetError", "error": "Connection reset by peer"}
        for phase, rows in (("allowed", [passed]), ("restored", [passed]),
                            ("denied", [passed, refused, refused]), ("bypass-blocked", [refused]),
                            ("raw-direct", [dict(passed, peer=["172.25.0.1", 18082])])):
            (directory / f"l4-{phase}.jsonl").write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (directory / "auth_probes.log").write_text(''.join(f"[auth-probe] ok: {proof}\n" for proof in (
            "plaintext refused", "valid client certificate handshake", "no-client-cert refused",
            "rogue-CA client certificate refused")))
        for phase, count in (("allowed", 2), ("denied", 2), ("restored", 3)):
            snapshot = directory / f"l4-{phase}"
            snapshot.mkdir()
            (snapshot / "source.metrics").write_text(
                f'ferrum_mesh_tcp_egress_connections_total{{transport="mtls",result="success"}} {count}\n')
            (snapshot / "destination.metrics").write_text('')

    def test_shipping_transport_pass_preserves_telemetry_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.ferrum_evidence(directory)
            result = fixture.verify_ferrum(directory)
            self.assertTrue(result["accepted"])
            self.assertTrue(result["transport_auth_qualified"])
            self.assertFalse(result["workload_telemetry_qualified"])
            self.assertEqual(result["restored_minus_denied_mtls_successes"], 1)
            self.assertEqual(len(result["workload_telemetry_findings"]), 8)
            self.assertEqual(len(result["workload_telemetry_reasons"]), 3)
            self.assertIn('verify-ferrum "$OUTPUT_DIR/logs"', shell)
            self.assertIn('workload telemetry UNQUALIFIED', shell)

    def test_positive_binary_proof_requires_exact_peer_payload_and_half_close(self):
        for field, value in (("exchanges", 4), ("payload_bytes", 271), ("byte_exact", False),
                             ("half_close", False), ("connections", 2), ("whole_exchange_timeout_secs", 60),
                             ("peer", ["172.25.0.1", 18082])):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.ferrum_evidence(directory)
                path = directory / "l4-restored.jsonl"
                row = json.loads(path.read_text())
                row[field] = value
                path.write_text(json.dumps(row) + '\n')
                self.assertFalse(fixture.verify_ferrum(directory)["accepted"])

    def test_negative_probes_require_real_refusals_and_two_denied_records(self):
        for phase, records in (("denied", [{"ok": False, "kind": "ConnectionResetError"}]),
                               ("denied", [{"ok": False, "kind": "timeout"}] * 2),
                               ("denied", [{"ok": False, "kind": "ConnectionError", "error": "binary echo mismatch"}] * 2),
                               ("bypass-blocked", [{"ok": False, "kind": "timeout"}]),
                               ("bypass-blocked", [{"ok": False, "kind": "OSError"}])):
            with self.subTest(phase=phase, records=records), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.ferrum_evidence(directory)
                (directory / f"l4-{phase}.jsonl").write_text(''.join(json.dumps(row) + '\n' for row in records))
                self.assertFalse(fixture.verify_ferrum(directory)["accepted"])

    def test_mtls_counter_requires_matching_transport_and_positive_restore_delta(self):
        for value in ('transport="hbone",result="success"} 3', 'transport="mtls",result="error"} 3',
                      'transport="mtls",result="success"} 2', 'transport="mtls",result="success"} 1',
                      'transport="mtls",result="success"} NaN', 'transport="mtls",result="success"} 3.5'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.ferrum_evidence(directory)
                (directory / 'l4-restored/source.metrics').write_text('ferrum_mesh_tcp_egress_connections_total{' + value + '\n')
                self.assertFalse(fixture.verify_ferrum(directory)["accepted"])

    def test_missing_or_malformed_probe_and_auth_evidence_fails_closed(self):
        for filename, contents in (("l4-allowed.jsonl", ''), ("l4-denied.jsonl", 'not json'),
                                   ("l4-bypass-blocked.jsonl", '[]'), ("auth_probes.log", ''),
                                   ("l4-fixture-configs/topology.json", '[]')):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.ferrum_evidence(directory)
                (directory / filename).write_text(contents)
                result = fixture.verify_ferrum(directory)
                self.assertFalse(result["accepted"])
                self.assertFalse(result["transport_auth_qualified"])
                self.assertFalse(result["workload_telemetry_qualified"])

    def counter_body(self, count):
        return f'ferrum_mesh_tcp_egress_connections_total{{transport="mtls",result="success"}} {count}\n'.encode()

    def settling_evidence(self, directory):
        self.ferrum_evidence(directory)
        (directory / "l4-restored/source.metrics").write_bytes(self.counter_body(2))

    class Clock:
        def __init__(self):
            self.now, self.waits = 100.0, []

        def __call__(self):
            return self.now

        def wait(self, seconds):
            self.waits.append(seconds)
            self.now += seconds

    def test_counter_already_published_preserves_initial_snapshots_without_poll(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.ferrum_evidence(directory)
            clock = self.Clock()
            def forbidden(_):
                self.fail("already-published counter must not fetch")
            result = fixture.settle_ferrum_counter(directory, fetch=forbidden, clock=clock, wait=clock.wait)
            self.assertTrue(result["accepted"])
            self.assertEqual(result["attempts"], [])
            self.assertEqual(clock.waits, [])
            saved = directory / "l4-counter-settling"
            for role in ("source", "destination"):
                self.assertEqual((saved / f"initial-{role}.metrics").read_bytes(),
                                 (directory / f"l4-restored/{role}.metrics").read_bytes())
            self.assertEqual(json.loads((saved / "receipt.json").read_text()), result)

    def test_counter_cached_until_5_5_seconds_keeps_all_raw_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.settling_evidence(directory)
            clock, calls = self.Clock(), []
            def fetch(timeout):
                calls.append((clock(), timeout))
                return self.counter_body(3 if clock() >= 105.5 else 2)
            result = fixture.settle_ferrum_counter(directory, fetch=fetch, clock=clock, wait=clock.wait)
            self.assertTrue(result["accepted"], result)
            self.assertEqual(result["end_monotonic"] - result["begin_monotonic"], 5.5)
            self.assertEqual(len(result["attempts"]), 12)
            self.assertEqual(result["pinned_source_defaults"]["render_cache_ttl_seconds"], 5)
            self.assertTrue(all(0 < timeout <= 0.5 for _, timeout in calls))
            self.assertTrue(all(seconds == 0.5 for seconds in clock.waits))
            saved = directory / "l4-counter-settling"
            self.assertEqual((saved / "initial-source.metrics").read_bytes(), self.counter_body(2))
            for attempt in result["attempts"]:
                self.assertEqual((saved / attempt["raw_path"]).read_bytes(), self.counter_body(attempt["counter"]))
                self.assertLessEqual(attempt["begin_monotonic"], attempt["end_monotonic"])
            self.assertEqual((directory / "l4-restored/source.metrics").read_bytes(), self.counter_body(3))
            self.assertTrue(fixture.verify_ferrum(directory)["accepted"])
            with self.assertRaises(FileExistsError):
                fixture.settle_ferrum_counter(directory, fetch=fetch, clock=clock, wait=clock.wait)

    def test_counter_never_progresses_fails_within_wall_and_attempt_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.settling_evidence(directory)
            clock = self.Clock()
            result = fixture.settle_ferrum_counter(directory, fetch=lambda _: self.counter_body(2), clock=clock, wait=clock.wait)
            self.assertFalse(result["accepted"])
            self.assertLessEqual(len(result["attempts"]), 15)
            self.assertEqual(clock() - 100, 6.5)
            self.assertIn("bound exhausted", result["errors"][0])
            self.assertEqual((directory / "l4-restored/source.metrics").read_bytes(), self.counter_body(2))

    def test_counter_regression_malformed_read_error_and_body_limit_fail_closed(self):
        cases = (self.counter_body(1), self.counter_body("NaN"), self.counter_body(3) * 2,
                 self.counter_body("3.5"), self.counter_body(2).replace(b'transport="mtls"', b'transport="hbone"'),
                 self.counter_body(3) + b"x" * fixture.METRICS_BODY_LIMIT, OSError("DO NOT DISPLAY remote body"))
        for body in cases:
            with self.subTest(case=type(body).__name__), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.settling_evidence(directory)
                clock, calls = self.Clock(), []
                def fetch(timeout):
                    calls.append(timeout)
                    if isinstance(body, Exception):
                        raise body
                    return body
                result = fixture.settle_ferrum_counter(directory, fetch=fetch, clock=clock, wait=clock.wait)
                self.assertFalse(result["accepted"])
                self.assertEqual(len(calls), 1)
                self.assertEqual(clock.waits, [])
                self.assertNotIn("DO NOT DISPLAY", json.dumps(result))
                raw = directory / "l4-counter-settling/poll-01.metrics"
                self.assertLessEqual(raw.stat().st_size, 4 * 1024 * 1024)
                self.assertEqual((directory / "l4-restored/source.metrics").read_bytes(), self.counter_body(2))

    def test_counter_unrelated_auth_or_binary_fault_never_polls(self):
        for filename in ("auth_probes.log", "l4-restored.jsonl"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.settling_evidence(directory)
                (directory / filename).write_text("")
                clock = self.Clock()
                def forbidden(_):
                    self.fail("unrelated proof fault must not fetch")
                result = fixture.settle_ferrum_counter(directory, fetch=forbidden, clock=clock, wait=clock.wait)
                self.assertFalse(result["accepted"])
                self.assertEqual(result["attempts"], [])
                self.assertEqual(clock.waits, [])

    def test_counter_fetch_cannot_qualify_a_response_after_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.settling_evidence(directory)
            clock = self.Clock()
            def late(_):
                clock.now += 6.6
                return self.counter_body(3)
            result = fixture.settle_ferrum_counter(directory, fetch=late, clock=clock, wait=clock.wait)
            self.assertFalse(result["accepted"])
            self.assertIn("deadline exceeded", result["errors"][0])
            self.assertEqual((directory / "l4-counter-settling/poll-01.metrics").read_bytes(), self.counter_body(3))
            self.assertEqual((directory / "l4-restored/source.metrics").read_bytes(), self.counter_body(2))

    def test_fixed_loopback_fetch_disables_proxies_and_reads_completed_body_once(self):
        response = mock.MagicMock()
        body = self.counter_body(3)
        response.status, response.length = 200, len(body)
        response.read1.side_effect = [body]
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(fixture.urllib.request, "build_opener", return_value=opener) as build, mock.patch.object(fixture.time, "monotonic", return_value=100):
            self.assertEqual(fixture.fetch_source_metrics(0.5), body)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsNone(build.call_args.args[1].redirect_request(None, None, None, None, None, None))
        opener.open.assert_called_once_with("http://127.0.0.1:15120/metrics", timeout=0.5)
        response.fp.raw._sock.settimeout.assert_called_once_with(0.5)
        response.read1.assert_called_once()

    def test_fixed_loopback_fetch_retains_partial_read_failure_without_exception_display(self):
        response = mock.MagicMock()
        response.status, response.length = 200, None
        response.read1.side_effect = [b"partial metrics", TimeoutError("SECRET REMOTE DATA")]
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(fixture.urllib.request, "build_opener", return_value=opener), mock.patch.object(fixture.time, "monotonic", return_value=100):
            with self.assertRaises(fixture.MetricsReadFailure) as error:
                fixture.fetch_source_metrics(0.5)
        self.assertEqual(error.exception.body, b"partial metrics")
        self.assertNotIn("SECRET", str(error.exception))

    def test_counter_attempt_cap_holds_even_if_injected_wait_does_not_advance_clock(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.settling_evidence(directory)
            clock = self.Clock()
            result = fixture.settle_ferrum_counter(directory, fetch=lambda _: self.counter_body(2), clock=clock, wait=lambda _: None)
            self.assertFalse(result["accepted"])
            self.assertEqual(len(result["attempts"]), 15)

    def test_settling_shell_only_polls_fixed_loopback_after_restored_snapshot(self):
        body = re.search(r'(?ms)^mesh_l4_prove\(\) \{.*?^\}', shell).group()
        probe = body.index('mesh_l4_wait_binary 0 restored')
        snapshot = body.index('mesh_l4_snapshot restored', probe)
        settling = body.index('mesh_l4_ns python3 "$SCRIPT_DIR/mesh_l4_fixture.py" settle-ferrum-counter', snapshot)
        verify = body.index('verify-ferrum "$OUTPUT_DIR/logs"', settling)
        self.assertLess(snapshot, settling)
        self.assertLess(settling, verify)
        self.assertNotIn('mesh_l4_probe', body[snapshot:settling])
        source = (DIRECTORY / "mesh_l4_fixture.py").read_text()
        helper = source[source.index('def settle_ferrum_counter('):source.index('def public_config(')]
        self.assertNotIn('probe(', helper)
        self.assertNotIn('socket.', helper)
        self.assertIn('urllib.request.ProxyHandler({})', source)
        self.assertEqual(fixture.METRICS_URL, "http://127.0.0.1:15120/metrics")

    def consul_evidence(self, directory):
        topology = directory / "topology.json"
        topology.write_text(json.dumps({"endpoint": "172.18.0.1"}))
        # Minimal sanitized shape from smoke39654641860: source has plaintext
        # loopback upstream; B binds the declared bridge with alias "tls".
        for role, host, port, service in (("source", "127.0.0.1", 15101, "client"),
                                          ("destination", "172.18.0.1", 21000, "svc")):
            chain = {"filters": [{"name": "envoy.filters.network.tcp_proxy"}]}
            if role == "destination":
                chain["filters"].insert(0, {"name": "envoy.filters.network.rbac"})
                chain["transport_socket"] = {"name": "tls", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                    "common_tls_context": {"validation_context": {"trusted_ca": {"inline_string": "public CA certificate"}}},
                    "require_client_certificate": True}}
            listener = {"address": {"socket_address": {"address": host, "port_value": port}}, "filter_chains": [chain]}
            (directory / f"{role}-config.json").write_text(json.dumps({"configs": [{
                "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump.DynamicListener",
                "active_state": {"listener": listener}}]}))
            (directory / f"{role}.metrics").write_text('cluster.svc.ssl.handshake: 2\n')
            (directory / f"{role}-certs.json").write_text(json.dumps({"uri": f"spiffe://trust.consul/ns/default/dc/dc1/svc/{service}"}))
        return topology

    def test_consul_real_sanitized_shape_accepts_both_tls_names_at_declared_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            topology = self.consul_evidence(directory)
            result = fixture.verify_consul(directory, topology)
            self.assertTrue(result["accepted"], result)
            self.assertEqual(result["measured_addresses"], [["127.0.0.1"], ["172.18.0.1"]])
            path = directory / "destination-config.json"
            path.write_text(path.read_text().replace('"name": "tls"', '"name": "envoy.transport_sockets.tls"'))
            self.assertTrue(fixture.verify_consul(directory, topology)["accepted"])
            (directory / "source.metrics").write_text('cluster.svc.ssl.handshake: 0\n')
            self.assertFalse(fixture.verify_consul(directory, topology)["accepted"])
            self.assertIn('--topology "$OUTPUT_DIR/logs/l4-fixture-configs/topology.json"', shell)

    def test_consul_rejects_wrong_address_warming_duplicate_or_unprotected_chain(self):
        for mutation in ("address", "source-address", "warming", "duplicate", "cleartext-chain", "cleartext-default"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                topology = self.consul_evidence(directory)
                path = directory / ("source-config.json" if mutation == "source-address" else "destination-config.json")
                doc = json.loads(path.read_text())
                state = doc["configs"][0]
                listener = state["active_state"]["listener"]
                if mutation in ("address", "source-address"):
                    listener["address"]["socket_address"]["address"] = "0.0.0.0"
                elif mutation == "warming":
                    state["warming_state"] = state.pop("active_state")
                elif mutation == "duplicate":
                    doc["configs"].append(copy.deepcopy(state))
                else:
                    cleartext = {"filters": [{"name": "envoy.filters.network.tcp_proxy"}]}
                    if mutation == "cleartext-chain":
                        listener["filter_chains"].append(cleartext)
                    else:
                        listener["default_filter_chain"] = cleartext
                path.write_text(json.dumps(doc))
                self.assertFalse(fixture.verify_consul(directory, topology)["accepted"])

    def test_consul_tls_alias_requires_exact_context_trusted_ca_and_client_certificate(self):
        for mutation in ("name", "type", "client-certificate", "ca", "empty-ca", "untrusted", "custom-validator"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                topology = self.consul_evidence(directory)
                path = directory / "destination-config.json"
                doc = json.loads(path.read_text())
                transport = doc["configs"][0]["active_state"]["listener"]["filter_chains"][0]["transport_socket"]
                context = transport["typed_config"]
                validation = context["common_tls_context"]["validation_context"]
                if mutation == "name":
                    transport["name"] = "raw_buffer"
                elif mutation == "type":
                    context["@type"] = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"
                elif mutation == "client-certificate":
                    context["require_client_certificate"] = False
                elif mutation == "ca":
                    del validation["trusted_ca"]
                elif mutation == "empty-ca":
                    validation["trusted_ca"] = {"inline_string": " "}
                elif mutation == "untrusted":
                    validation["trust_chain_verification"] = "ACCEPT_UNTRUSTED"
                else:
                    validation["custom_validator_config"] = {"name": "unknown"}
                path.write_text(json.dumps(doc))
                self.assertFalse(fixture.verify_consul(directory, topology)["accepted"])

    def test_consul_measured_transport_is_snapshotted_after_http_restore(self):
        body = re.search(r'(?ms)^mesh_l4_prove\(\) \{.*?^\}', shell).group()
        restore = body.index('consul services register /tmp/consul-svc.json')
        ready = body.index('wait_ready "$TARGET_URL" consul-captured-http-restored', restore)
        snapshot = body.index('mesh_l4_snapshot measured', ready)
        verify = body.index('verify-consul "$OUTPUT_DIR/logs/l4-measured"', snapshot)
        self.assertLess(restore, ready)
        self.assertLess(ready, snapshot)
        self.assertLess(snapshot, verify)
        self.assertIn('l4-measured-http-readiness.json', body[ready:snapshot])
        self.assertIn('l4-measured-transport-proof.json" || return 1', body[verify:])
        self.assertNotIn('READINESS_DEADLINE=', body)

    def test_capture_matches_production_order_and_uid_is_separate(self):
        production = (ROOT / "src/capture/mod.rs").read_text()
        local = production.index('"-m addrtype --dst-type LOCAL -j RETURN"')
        owner = production.index('"-m owner --uid-owner {uid} -j RETURN"', local)
        redirect = production.index('-p tcp -d {cidr} -j REDIRECT --to-ports', owner)
        self.assertLess(local, owner)
        self.assertLess(owner, redirect)
        self.assertLess(shell.index('--dst-type LOCAL -j RETURN'), shell.index('--uid-owner "$proxy_uid" -j RETURN'))
        self.assertLess(shell.index('--uid-owner "$proxy_uid" -j RETURN'), shell.index('-d "$vip/32" -j REDIRECT'))
        self.assertIn('L4_APP_UID=65531', shell)
        self.assertIn('L4_PROXY_UID=65532', shell)
        self.assertIn('mesh_l4_ns ip route add "$L4_VIP/32" via "$L4_GATEWAY"', shell)
        outside = re.sub(r"<<'RULES'\n.*?\nRULES", "", shell, flags=re.S)
        self.assertNotRegex(outside, r'(?m)^\s*(?:sudo[^\n]* )?iptables ')
        # iptables exists only inside the mesh_l4_ns sh heredoc.
        rules = re.search(r"<<'RULES'\n(.*?)\nRULES", shell, re.S).group(1)
        self.assertIn('--dports "$backend_port,$raw_port" -j REJECT', rules)

    def test_unprivileged_probes_read_public_script_from_parent_stdin(self):
        for name in ("mesh_l4_probe", "mesh_l4_prove"):
            body = re.search(rf'(?ms)^{name}\(\) \{{.*?^\}}', shell).group()
            dropped = body[body.index("setpriv"):]
            self.assertIn('python3 - probe', dropped)
            self.assertIn('< "$SCRIPT_DIR/mesh_l4_fixture.py"', dropped)
        self.assertNotIn('chmod', shell)

    def test_nonroot_workers_private_mounts_and_owned_cleanup(self):
        for name in ("start_ferrum_l4", "start_consul_l4"):
            body = re.search(rf'(?ms)^{name}\(\) \{{.*?^\}}', shell).group()
            self.assertEqual(body.count('--user 65532:65532'), 2)
            self.assertEqual(body.count('${BENCH_WORKERS:-4}'), 2)
            for mount in re.findall(r'-v "([^"]+)"', body):
                self.assertTrue(mount.endswith(':ro'))
        cleanup = re.search(r'(?ms)^mesh_l4_cleanup\(\) \{.*?^\}', shell).group()
        self.assertEqual(cleanup.count('[ "$owner" = "$L4_OWNER" ]'), 2)
        self.assertNotIn('prune', cleanup)
        self.assertIn('"$pid" = "$L4_NETNS_PID"', shell)
        self.assertNotIn('sysctl', re.sub(r'(?m)^#.*$', '', shell))


if __name__ == "__main__":
    unittest.main()
