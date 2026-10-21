"""Cheap captured-L4 contracts: no real Docker, namespaces, or benchmark load."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

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

    def test_consul_requires_active_tcp_mutual_tls_and_issued_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for role, port, service in (("source", 15101, "client"), ("destination", 21000, "svc")):
                listener = {"address": {"socket_address": {"address": "0.0.0.0", "port_value": port}},
                            "filter_chains": [{"filters": [{"name": "envoy.filters.network.tcp_proxy"}],
                                "transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {"require_client_certificate": True}}}]}
                (directory / f"{role}-config.json").write_text(json.dumps({"configs": [{"dynamic_listeners": [{"active_state": {"listener": listener}}]}]}))
                (directory / f"{role}.metrics").write_text('cluster.svc.ssl.handshake: 2\n')
                (directory / f"{role}-certs.json").write_text(json.dumps({"uri": f"spiffe://trust.consul/ns/default/dc/dc1/svc/{service}"}))
            self.assertTrue(fixture.verify_consul(directory)["accepted"])
            path = directory / "destination-config.json"
            path.write_text(path.read_text().replace('"require_client_certificate": true', '"require_client_certificate": false'))
            self.assertFalse(fixture.verify_consul(directory)["accepted"])
            (directory / "source.metrics").write_text('cluster.svc.ssl.handshake: 0\n')
            self.assertFalse(fixture.verify_consul(directory)["accepted"])

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
