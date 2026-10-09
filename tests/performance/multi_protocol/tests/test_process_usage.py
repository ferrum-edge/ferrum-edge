import json
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_plan import stamp_sample
from process_usage import (IO_FIELDS, capture_scheduler, client_pids, measurement_usage,
                           parse_context_switches, parse_io, sample_processes)


class PassiveUsageTests(unittest.TestCase):
    def test_context_switches_include_workers_and_preserve_thread_generations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for tid, generation, voluntary in ((42, 100, 2), (43, 200, 17)):
                task = root / "42" / "task" / str(tid)
                task.mkdir(parents=True)
                fields = ["0"] * 22
                fields[0], fields[19] = "S", str(generation)
                (task / "stat").write_text(f"{tid} (worker thread) " + " ".join(fields))
                (task / "status").write_text(
                    f"Name:\tworker\nvoluntary_ctxt_switches:\t{voluntary}\n"
                    "nonvoluntary_ctxt_switches:\t3\n")
            result = capture_scheduler(42, 100, 4096, root)
            self.assertEqual(set(result), {"42", "43"})
            self.assertEqual(result["43"]["start_ticks"], 200)
            self.assertEqual(result["43"]["voluntary_ctxt_switches"], 17)
            (root / "42/task/43/status").unlink()
            with self.assertRaises(OSError):
                capture_scheduler(42, 100, 4096, root)

    def test_context_switch_parser_rejects_missing_or_negative_counters(self):
        text = "voluntary_ctxt_switches: 0\nnonvoluntary_ctxt_switches: 3\n"
        self.assertEqual(parse_context_switches(text)["voluntary_ctxt_switches"], 0)
        with self.assertRaises(KeyError):
            parse_context_switches("voluntary_ctxt_switches: 0")
        with self.assertRaises(ValueError):
            parse_context_switches(text.replace(": 0", ": -1"))

    def test_scheduler_delta_rejects_worker_churn_reuse_and_counter_regression(self):
        timeline = [dict(unix_secs=t, processes=[dict(
            pid=42, role="gateway", start_ticks=1, cpu_seconds=t * 3, rss_bytes=1024,
            user_cpu_seconds=t * 2, system_cpu_seconds=t,
            scheduler_threads={str(tid): dict(start_ticks=tid,
                voluntary_ctxt_switches=n * tid, nonvoluntary_ctxt_switches=n)
                for tid in (42, 43)})]) for n, t in enumerate((0.9, 1.5, 2.1))]
        phases = dict(measurement_start_unix_secs=1, measurement_secs=1)
        row = measurement_usage(dict(timeline=timeline), phases)[0]
        self.assertAlmostEqual(row["user_cpu_seconds"], 2.4)
        self.assertAlmostEqual(row["system_cpu_seconds"], 1.2)
        self.assertEqual(row["context_switches"], dict(scope="all process threads",
            voluntary_ctxt_switches=170, nonvoluntary_ctxt_switches=4))
        for failure in ("missing_sample", "retired_worker", "reused_tid", "decreased_counter"):
            with self.subTest(failure=failure):
                changed = json.loads(json.dumps(timeline))
                middle = changed[1]["processes"][0]
                if failure == "missing_sample":
                    del middle["scheduler_threads"]
                elif failure == "retired_worker":
                    del middle["scheduler_threads"]["43"]
                elif failure == "reused_tid":
                    middle["scheduler_threads"]["43"]["start_ticks"] = 900
                else:
                    middle["scheduler_threads"]["43"]["voluntary_ctxt_switches"] = 900
                row = measurement_usage(dict(timeline=changed), phases)[0]
                self.assertNotIn("context_switches", row)
                self.assertIn("scheduler_error", row)

    def test_io_parser_requires_every_counter_and_preserves_zero(self):
        text = "\n".join(f"{key}: {index}" for index, key in enumerate(IO_FIELDS))
        self.assertEqual(parse_io(text), dict(zip(IO_FIELDS, range(len(IO_FIELDS)))))
        with self.assertRaises(KeyError):
            parse_io("rchar: 0")
        with self.assertRaises(ValueError):
            parse_io(text.replace("rchar: 0", "rchar: -1"))

    def test_io_delta_requires_continuous_monotonic_bracket(self):
        timeline = [dict(unix_secs=t, processes=[dict(
            pid=42, role="gateway", start_ticks=1, cpu_seconds=t, rss_bytes=1024,
            io={key: n * 100 for key in IO_FIELDS})]) for n, t in enumerate((0.9, 1.5, 2.1))]
        phases = dict(measurement_start_unix_secs=1, measurement_secs=1)
        row = measurement_usage(dict(timeline=timeline), phases)[0]
        self.assertEqual(row["io"], {key: 200 for key in IO_FIELDS})
        timeline[1]["processes"][0]["io"]["syscw"] = 201
        self.assertIn("io_error", measurement_usage(dict(timeline=timeline), phases)[0])
        del timeline[1]["processes"][0]["io"]
        row = measurement_usage(dict(timeline=timeline), phases)[0]
        self.assertNotIn("io", row)
        self.assertIn("io_error", row)

    def test_privileged_reader_stop_file_preserves_optional_h3_observations(self):
        for http3 in (False, True):
            with self.subTest(http3=http3), tempfile.TemporaryDirectory() as directory:
                output, stop = Path(directory) / "usage.json", Path(directory) / "stop"
                stop.touch()
                with patch("process_usage.signal.signal"), \
                        patch("process_usage.os.sysconf", return_value=100), \
                        patch("process_usage.client_pids", return_value=[]) as discover, \
                        patch("process_usage.capture", return_value=None), \
                        patch("process_usage.thread_snapshot", return_value=[{"tid": 7}]), \
                        patch("process_usage.transport_snapshot", return_value={"observed": True}) as transport:
                    sample_processes(1, [2], output, 0.5, parent_pid=42, stop_file=stop,
                                     http3=http3, envoy=True)
                report = json.loads(output.read_text())
                self.assertTrue(report["capture_complete"])
                discover.assert_called_with(42)
                self.assertEqual(len(report["timeline"]), 2)
                for snapshot in report["timeline"]:
                    if http3:
                        self.assertEqual(snapshot["transport"], {"observed": True})
                        self.assertEqual({row["role"] for row in snapshot["threads"]},
                                         {"gateway", "backend"})
                    else:
                        self.assertNotIn("transport", snapshot)
                        self.assertNotIn("threads", snapshot)
                if http3:
                    transport.assert_called_with(True)
                else:
                    transport.assert_not_called()

    def test_client_boundary_capture_replaces_a_missing_passive_endpoint(self):
        phases = dict(measurement_start_unix_secs=1, measurement_secs=1,
                      client_usage=dict(pid=3, role="client", complete_bracket=True,
                                        cpu_seconds=0.4, peak_rss_bytes=4096))
        timeline = [dict(unix_secs=0.9, processes=[dict(
            pid=3, role="client", start_ticks=1, cpu_seconds=0, rss_bytes=1024)])]
        rows = measurement_usage(dict(timeline=timeline), phases)
        self.assertEqual(rows, [phases["client_usage"]])
        del phases["client_usage"]
        self.assertEqual(measurement_usage(dict(timeline=timeline), phases), [])

    def test_process_must_remain_observable_for_the_entire_window(self):
        process = dict(pid=42, role="gateway", start_ticks=1, cpu_seconds=1, rss_bytes=1024)
        timeline = [dict(unix_secs=t, processes=[dict(process)]) for t in (0.9, 1.5, 2.1)]
        phases = dict(measurement_start_unix_secs=1, measurement_secs=1)
        self.assertTrue(measurement_usage(dict(timeline=timeline), phases)[0]["complete_bracket"])
        timeline[1]["processes"] = []
        self.assertFalse(measurement_usage(dict(timeline=timeline), phases)[0]["complete_bracket"])

    def test_unavailable_process_capture_is_preserved_for_diagnostic_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            path, usage_path = Path(directory) / "sample.json", Path(directory) / "usage.json"
            path.write_text('{}')
            unavailable = dict(available=False, error="process usage unavailable or disabled")
            usage_path.write_text(json.dumps(unavailable))
            stamp_sample(path, "direct", "64", "2", "1", "1", "host", usage_path, "direct")
            self.assertEqual(json.loads(path.read_text())["process_usage"], unavailable)

    def test_discovers_direct_and_timeout_clients_without_unrelated_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid, children in ((10, "11 12 13 14 15"), (12, "16"), (13, "17"), (14, "18")):
                path = root / str(pid) / "task" / str(pid) / "children"
                path.parent.mkdir(parents=True)
                path.write_text(children)
            for pid, name in ((11, "proto_bench"), (12, "timeout"), (13, "gtimeout"),
                              (14, "proto_backend"), (16, "proto_bench"),
                              (17, "proto_bench"), (18, "proto_bench")):
                path = root / str(pid) / "cmdline"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"/tools/{name}\0http2\0".encode())
            self.assertEqual(sorted(client_pids(10, root)), [11, 16, 17])
            self.assertEqual(client_pids(99, root), [])

    def test_signal_finalizes_usage_after_readiness_even_with_inherited_sigint_ignore(self):
        handlers = {}
        captures = {}

        def register(sig, handler):
            previous = handlers.get(sig, signal.SIG_IGN)
            handlers[sig] = handler
            return previous

        def capture(pid, ticks, page_size):
            captures[pid] = captures.get(pid, 0) + 1
            return dict(start_ticks=pid, cpu_seconds=captures[pid], rss_bytes=pid * 1024)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "usage.json"

            def stop_after_ready(interval):
                self.assertEqual(interval, 0.5)
                self.assertFalse(json.loads(output.read_text())["capture_complete"])
                handlers[signal.SIGINT](signal.SIGINT, None)

            with patch("process_usage.signal.signal", side_effect=register), \
                    patch("process_usage.os.getppid", return_value=10), \
                    patch("process_usage.os.sysconf", return_value=100), \
                    patch("process_usage.client_pids", return_value=[3]), \
                    patch("process_usage.capture", side_effect=capture), \
                    patch("process_usage.time.sleep", side_effect=stop_after_ready):
                sample_processes(1, [2], output, 0.5)
            report = json.loads(output.read_text())
            self.assertTrue(report["capture_complete"])
            self.assertEqual(report["interval_ms"], 500)
            self.assertEqual(report["missing_pids"], [])
            self.assertEqual({row["role"] for row in report["processes"]},
                             {"backend", "gateway", "client"})
            self.assertEqual(report["client_cpu_seconds"], 2)
            self.assertEqual(report["client_peak_rss_bytes"], 3072)
            self.assertEqual(len(report["timeline"]), 3)
            self.assertEqual(handlers[signal.SIGINT], signal.SIG_IGN)
            self.assertEqual(handlers[signal.SIGTERM], signal.SIG_IGN)

    def test_parent_exit_finishes_without_claiming_complete_capture_or_client_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "usage.json"
            with patch("process_usage.signal.signal"), \
                    patch("process_usage.os.getppid", side_effect=[10, 1]), \
                    patch("process_usage.os.sysconf", return_value=100), \
                    patch("process_usage.client_pids", return_value=[]), \
                    patch("process_usage.capture", return_value=None):
                sample_processes(1, [2], output, 0.5)
            report = json.loads(output.read_text())
            self.assertFalse(report["capture_complete"])
            self.assertEqual(report["missing_pids"], [1, 2])
            self.assertIsNone(report["client_cpu_seconds"])
            self.assertIsNone(report["client_peak_rss_bytes"])

    def test_rejects_unbounded_or_nonpositive_sampling_interval(self):
        for interval in (0, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                sample_processes(1, [], "unused.json", interval)

    def test_stamping_preserves_raw_series_and_rejects_incomplete_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path, usage_path = Path(directory) / "sample.json", Path(directory) / "usage.json"
            path.write_text(json.dumps(dict(phases=dict(
                measurement_start_unix_secs=1, measurement_secs=1))))
            timeline = [dict(unix_secs=t, processes=[dict(
                pid=1, start_ticks=1, role="backend", cpu_seconds=t, rss_bytes=1024)])
                for t in (0.5, 1.5, 2.5)]
            usage_path.write_text(json.dumps(dict(capture_complete=True, timeline=timeline)))
            stamp_sample(path, "direct", "64", "2", "1", "2", "host", usage_path, "envoy direct")
            sample = json.loads(path.read_text())
            self.assertEqual(sample["gateway_order"], ["envoy", "direct"])
            self.assertEqual(sample["pair"], 1)
            self.assertEqual(sample["effective_concurrency"], 2)
            self.assertTrue(sample["process_usage"]["measurement"][0]["complete_bracket"])
            self.assertNotIn("timeline", sample["process_usage"])
            self.assertEqual(json.loads(usage_path.read_text())["timeline"], timeline)
            usage_path.write_text('{"capture_complete": false}\n')
            stamp_sample(path, "direct", "64", "2", "1", "2", "host", usage_path, "envoy direct")
            self.assertIn("error", json.loads(path.read_text())["process_usage"])


if __name__ == "__main__":
    unittest.main()
