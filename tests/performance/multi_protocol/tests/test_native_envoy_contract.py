"""Static contract: native --envoy comparison legs do equivalent work.

For each protocol selected by `envoy_compare_protocol` in
run_protocol_test.sh, the Ferrum config, Envoy config, bench target, and
direct-backend baseline must agree on the route and on the upstream
transport (port and whether TLS is originated). Admin readiness alone
cannot prove that: an Envoy route pinned away from the bench path, or a
frontend-only Ferrum config paired with a TLS-originating Envoy config,
would still start cleanly while measuring different work.
"""

import re
import unittest
from pathlib import Path
from urllib.parse import urlparse

MULTI_PROTOCOL_DIR = Path(__file__).resolve().parents[1]
RUNNER = MULTI_PROTOCOL_DIR / "run_protocol_test.sh"

def selected_legs(proto):
    text = RUNNER.read_text()
    match = re.search(
        rf"^\s*{re.escape(proto)}\)\n(?P<body>.*?)^\s*;;",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"envoy_compare_protocol has no {proto} branch"
    body = match.group("body")

    def grab(var):
        found = re.search(rf'^\s*{var}="?(?P<value>[^\n"]+)"?$', body, re.MULTILINE)
        assert found, f"{proto}: {var} not set in envoy_compare_protocol"
        return found.group("value").strip()

    legs = {
        "bench_target": grab("bench_target"),
        "direct_target": grab("direct_target"),
        "ferrum_config": Path(grab("ferrum_config").replace("$SCRIPT_DIR", str(MULTI_PROTOCOL_DIR))),
        "envoy_config": Path(grab("envoy_config").replace("$SCRIPT_DIR", str(MULTI_PROTOCOL_DIR))),
    }
    extra = re.search(r'^\s*bench_extra="(?P<value>[^"]*)"', body, re.MULTILINE)
    legs["bench_extra"] = extra.group("value") if extra else ""
    return legs


def first_ferrum_upstream(config_path):
    text = config_path.read_text()
    scheme = re.search(r"backend_scheme:\s*(\S+)", text).group(1)
    port = int(re.search(r"backend_port:\s*(\d+)", text).group(1))
    listen_path = re.search(r'listen_path:\s*"([^"]+)"', text)
    return scheme, port, listen_path.group(1) if listen_path else None


def envoy_upstream(config_path):
    text = config_path.read_text()
    # The cluster endpoint is the last socket_address port (after admin/listener).
    ports = re.findall(r"port_value:\s*(\d+)\s*\}", text)
    prefixes = re.findall(r'match:\s*\{\s*prefix:\s*"([^"]+)"\s*\}', text)
    return int(ports[-1]), "UpstreamTlsContext" in text, prefixes


class NativeEnvoyContractTests(unittest.TestCase):
    def check_upstream_parity(self, proto):
        legs = selected_legs(proto)
        scheme, ferrum_port, listen_path = first_ferrum_upstream(legs["ferrum_config"])
        envoy_port, envoy_tls, prefixes = envoy_upstream(legs["envoy_config"])
        ferrum_tls = scheme in {"https", "tcps"}
        self.assertEqual(ferrum_port, envoy_port, f"{proto}: upstream port mismatch")
        self.assertEqual(
            ferrum_tls,
            envoy_tls,
            f"{proto}: Ferrum scheme {scheme!r} and Envoy upstream TLS={envoy_tls} "
            "do different upstream transport work",
        )
        return legs, listen_path, prefixes, ferrum_tls, envoy_port

    def check_http_route(self, proto):
        legs, listen_path, prefixes, upstream_tls, upstream_port = self.check_upstream_parity(proto)
        bench = urlparse(legs["bench_target"])
        direct = urlparse(legs["direct_target"])
        self.assertEqual(listen_path, bench.path, f"{proto}: Ferrum listen_path misses bench path")
        self.assertTrue(
            any(bench.path.startswith(prefix) for prefix in prefixes),
            f"{proto}: no Envoy route prefix in {prefixes} matches bench path {bench.path!r}",
        )
        self.assertEqual(direct.port, upstream_port, f"{proto}: direct baseline port mismatch")
        self.assertEqual(
            direct.scheme == "https",
            upstream_tls,
            f"{proto}: direct baseline scheme {direct.scheme!r} vs upstream TLS={upstream_tls}",
        )
        self.assertEqual(direct.path, bench.path, f"{proto}: direct baseline path mismatch")

    def test_http1_route_and_plain_upstream_match(self):
        self.check_http_route("http1")

    def test_http1_tls_is_end_to_end_on_every_leg(self):
        self.check_http_route("http1-tls")

    def test_tcp_tls_is_end_to_end_on_every_leg(self):
        legs, _listen_path, _prefixes, upstream_tls, upstream_port = self.check_upstream_parity(
            "tcp-tls"
        )
        self.assertTrue(upstream_tls, "tcp-tls: upstream must originate TLS")
        direct_port = int(legs["direct_target"].rsplit(":", 1)[1])
        self.assertEqual(direct_port, upstream_port, "tcp-tls: direct baseline port mismatch")
        self.assertIn("--tls", legs["bench_extra"], "tcp-tls: bench/direct legs need --tls")


if __name__ == "__main__":
    unittest.main()
