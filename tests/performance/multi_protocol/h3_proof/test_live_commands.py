"""Hosted launcher regressions; subprocesses are replaced with owned-child doubles."""
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import live


class CommandOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / 'command'
        self.child = Mock(pid=1234, stdin=None)
        self.child.wait.return_value = 0

    def test_tls_path_data_is_recorded_before_spawn_for_every_mode(self):
        for mode in ('certificates', 'backend', 'request'):
            with self.subTest(mode=mode):
                cgroup = Path('/sys/fs/cgroup/h3live123.slice') / ('client' if mode == 'request' else 'backend')

                def launch(action, out, err, **data):
                    status = json.loads(self.output.with_suffix('.json').read_text())
                    self.assertIsNone(status['returncode'])
                    self.assertEqual(status['data'], dict(mode=mode, cgroup=str(cgroup), cpus=4))
                    self.assertEqual(status['data'], data)
                    self.assertEqual(live.environment(action, **data)['H3_LIVE_CGROUP'], str(cgroup))
                    out.write(b'{"captured": true}\n')
                    return self.child

                with patch.object(live, 'launch', side_effect=launch):
                    response = live.command('tls-fixture', self.output, mode=mode, cgroup=cgroup, cpus=4)
                self.assertEqual(json.loads(response), dict(captured=True))
                status = json.loads(self.output.with_suffix('.json').read_text())
                self.assertEqual(status['returncode'], 0)
                self.assertGreaterEqual(status['end_ns'], status['start_ns'])

    def test_invalid_json_or_initial_artifact_failure_never_launches(self):
        with patch.object(live, 'launch') as launch:
            with self.assertRaises(TypeError):
                live.command('tls-fixture', self.output, cgroup=object())
            with patch.object(live, 'write', side_effect=OSError('artifact write failed')):
                with self.assertRaises(OSError):
                    live.command('tls-fixture', self.output, cgroup=Path('/owned'))
            launch.assert_not_called()

    def test_timeout_kills_and_reaps_owned_group_before_final_record(self):
        self.child.wait.side_effect = [subprocess.TimeoutExpired('fixture', 1), -signal.SIGKILL]
        with patch.object(live, 'launch', return_value=self.child), patch.object(live.os, 'killpg') as kill:
            with self.assertRaises(RuntimeError):
                live.command('tls-fixture', self.output, timeout=1, cgroup=Path('/owned'))
        kill.assert_called_once_with(self.child.pid, signal.SIGKILL)
        self.assertEqual(self.child.wait.call_count, 2)
        self.child.wait.assert_called_with(timeout=5)
        status = json.loads(self.output.with_suffix('.json').read_text())
        self.assertTrue(status['timeout'])
        self.assertEqual(status['returncode'], -signal.SIGKILL)

    def test_wait_error_and_cancellation_reap_before_output_files_close(self):
        for error in (OSError('wait failed'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                streams = []

                def launch(action, out, err, **data):
                    streams.extend((out, err))
                    return self.child

                def wait(**kwargs):
                    self.assertTrue(all(not stream.closed for stream in streams))
                    if kwargs['timeout'] == 30:
                        raise error
                    return -signal.SIGKILL

                self.child.wait.side_effect = wait
                with patch.object(live, 'launch', side_effect=launch), patch.object(live.os, 'killpg') as kill:
                    with self.assertRaises(type(error)):
                        live.command('tls-fixture', self.output, cgroup=Path('/owned'))
                kill.assert_called_once_with(self.child.pid, signal.SIGKILL)
                self.assertTrue(all(stream.closed for stream in streams))

    def test_final_metadata_error_occurs_only_after_reap(self):
        write = live.write

        def fail_final(path, status):
            if status['returncode'] is not None:
                self.child.wait.assert_called_once_with(timeout=30)
                raise OSError('final artifact failed')
            write(path, status)

        with patch.object(live, 'launch', return_value=self.child), patch.object(live, 'write', side_effect=fail_final):
            with self.assertRaises(OSError):
                live.command('tls-fixture', self.output, cgroup=Path('/owned'))

    def test_long_lived_child_stop_closes_stdin_and_handles_exit_race(self):
        self.child.stdin = Mock()
        self.child.poll.return_value = None
        with patch.object(live.os, 'killpg', side_effect=ProcessLookupError):
            self.assertFalse(live.stop_process(self.child, timeout=5))
        self.child.wait.assert_called_once_with(timeout=5)
        self.child.stdin.close.assert_called_once_with()

    def test_long_lived_child_timeout_or_wait_error_still_kills_and_reaps(self):
        for error in (subprocess.TimeoutExpired('fixture', 1), OSError('wait failed')):
            with self.subTest(error=type(error).__name__):
                child = Mock(pid=1234, stdin=Mock())
                child.poll.return_value = None
                child.wait.side_effect = [error, -signal.SIGKILL]
                with patch.object(live.os, 'killpg') as kill:
                    if isinstance(error, subprocess.TimeoutExpired):
                        self.assertTrue(live.stop_process(child, timeout=1))
                    else:
                        with self.assertRaises(OSError): live.stop_process(child, timeout=1)
                self.assertEqual([call.args for call in kill.call_args_list],
                                 [(child.pid, signal.SIGTERM), (child.pid, signal.SIGKILL)])
                child.wait.assert_called_with(timeout=5)
                child.stdin.close.assert_called_once_with()


class BackendSelectionTests(unittest.TestCase):
    def test_proof_launcher_selects_bounded_mode_without_ambient_tuning(self):
        here = Path(__file__).resolve().parent
        commands = (here / 'live_commands.sh').read_text()
        self.assertIn('/tmp/ferrum-h3-live/build/proto_backend --h3-only', commands)
        source = (here.parent / 'proto_backend.rs').read_text()
        self.assertIn('[] => false,', source)
        self.assertIn('[flag] if flag == "--h3-only" => true,', source)
        isolated, ordinary = source.split('    if h3_only {', 1)[1].split('    println!("Multi-Protocol Backend Server");', 1)
        self.assertIn('return tokio::select!', isolated)
        self.assertIn('run_http1_health_server("127.0.0.1:3010"', isolated)
        self.assertIn('run_h3_server("127.0.0.1:3445"', isolated)
        self.assertIn('tokio::signal::ctrl_c()', isolated)
        for server in ('run_udp_echo', 'run_dtls_echo', 'run_http1_server', 'run_h2c_server'):
            self.assertNotIn(server + '(', isolated)
            self.assertIn(server + '(', ordinary)
        self.assertLess(source.index('tls_utils::generate_self_signed_certs'), source.index('    if h3_only {'))
        # Ordinary and historical H3 runs still invoke the multi-protocol default.
        runner = (here.parent / 'run_gateway_protocol_bench.sh').read_text()
        self.assertIn('./target/release/proto_backend >', runner)
        self.assertNotIn('--h3-only', runner)
        self.assertIn('h3_proof/live.py', runner)
        with patch.dict(live.os.environ, {'H3_PROFILE': '0', 'PROTO_BACKEND_MODE': 'all'}):
            env = live.environment('backend', cgroup=Path('/sys/fs/cgroup/h3live123.slice/backend'))
        self.assertNotIn('H3_PROFILE', env)
        self.assertNotIn('PROTO_BACKEND_MODE', env)
        with self.assertRaises(ValueError): live.environment('backend', command='arbitrary')


if __name__ == '__main__':
    unittest.main()
