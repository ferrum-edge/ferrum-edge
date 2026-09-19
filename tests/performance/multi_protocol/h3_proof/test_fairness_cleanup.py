"""Hosted fault injection for TLS fixture ownership and unchanged admission rules.

These doubles test orchestration, not TLS. The real three-arm hosted fixture
remains the behavioral certificate gate.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import fairness
import live


class TlsFixtureCleanupTests(unittest.TestCase):
    def run_fixture(self, *, failure=None, wrong_events=None, valid_sni='localhost'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_root = root / 'cgroups'; scope_root.mkdir()
            stage = root / 'stage'
            certs = stage / 'runtime/certs'; certs.mkdir(parents=True)
            for name in ('ca.pem', 'valid.pem', 'wrong.pem'):
                (certs / name).write_text('public fixture material: ' + name)
            out = root / 'result'
            child = Mock(pid=1234, stdin=Mock())
            child.poll.return_value = None
            child.wait.return_value = 0
            if failure == 'backend_wait':
                child.wait.side_effect = [OSError('backend wait failed'), 0]
            actions, logs = [], []

            def launch(action, stdout, stderr, **data):
                self.assertEqual((action, data['mode']), ('tls-fixture', 'backend'))
                logs.append(stdout)
                return child

            def command(action, output, **data):
                actions.append(action)
                if action == 'create' and failure == 'create_metadata':
                    raise OSError('create metadata failed after container creation')
                if action == 'logs' and failure == 'cleanup_logs':
                    raise OSError('logs artifact failed')
                if action == 'inspect':
                    return json.dumps([dict(Image='qualified', State=dict(Running=True, Pid=5678))])
                if action == 'tls-fixture' and data['mode'] == 'request':
                    identity = 'wrong' if 'wrong' in output.name else 'valid'
                    if identity == 'valid':
                        events = [dict(event='handshake', identity='valid', sni=valid_sni),
                                  dict(event='echo', identity='valid', bytes=10240)]
                    else:
                        events = wrong_events if wrong_events is not None else [
                            dict(event='handshake_rejected', identity='wrong', crypto_close=True)]
                    with (out / 'backend.jsonl').open('a') as stream:
                        for event in events: stream.write(json.dumps(event) + '\n')
                    return json.dumps(dict(status=200 if identity == 'valid' else 502,
                                           exact_body=identity == 'valid', bytes=10240 if identity == 'valid' else 0,
                                           protocol='h3', offered_requests=1, offered_bytes=10240, retries=0))
                return ''

            # Only redirect the provisioner's cgroup root; no privileged paths or
            # real subprocesses are touched by this semantic regression.
            with (patch.object(fairness, 'Path', side_effect=lambda value: scope_root if value == '/sys/fs/cgroup' else Path(value)),
                  patch.object(live, 'STAGE', stage), patch.object(live, 'launch', side_effect=launch),
                  patch.object(live, 'command', side_effect=command),
                  patch.object(live, 'owner', return_value=dict(pid=1234)),
                  patch.object(fairness, 'wait_event'), patch.object(fairness.time, 'sleep'),
                  patch.object(live.os, 'killpg') as kill):
                result = fairness.tls_fixture(out, 'ferrum', dict(images=dict(ferrum=dict(Id='qualified'))))
            self.assertEqual(json.loads((out / 'result.json').read_text()), result)
            self.assertEqual(list(scope_root.iterdir()), [])
            self.assertTrue(all(log.closed for log in logs))
            child.stdin.close.assert_called_once_with()
            if failure == 'backend_wait':
                self.assertEqual(child.wait.call_count, 2)
                self.assertEqual([call.args for call in kill.call_args_list],
                                 [(child.pid, live.signal.SIGTERM), (child.pid, live.signal.SIGKILL)])
            else:
                child.wait.assert_called_once_with(timeout=5)
                kill.assert_called_once_with(child.pid, live.signal.SIGTERM)
            self.assertEqual(actions[-4:], ['logs', 'stop', 'inspect', 'remove'])
            return result

    def test_both_identity_cases_are_required_before_success(self):
        result = self.run_fixture()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual([(c['identity'], c['accepted']) for c in result['cases']], [('valid', True), ('wrong', True)])

    def test_post_create_artifact_error_still_reaps_child_and_removes_container(self):
        result = self.run_fixture(failure='create_metadata')
        self.assertEqual(result['status'], 'error')
        self.assertIn('create metadata failed', result['error'])
        self.assertTrue(all(c['status'] == 'not_run' for c in result['cases']))

    def test_cleanup_artifact_error_does_not_skip_stop_inspect_remove_or_cgroups(self):
        result = self.run_fixture(failure='cleanup_logs')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['cleanup_errors'], ['logs artifact failed'])

    def test_backend_wait_error_does_not_skip_remaining_cleanup(self):
        result = self.run_fixture(failure='backend_wait')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['cleanup_errors'], ['backend wait failed'])

    def test_wrong_certificate_requires_crypto_rejection_without_fallback_or_echo(self):
        rejected = dict(event='handshake_rejected', identity='wrong', crypto_close=True)
        for events in ([], [dict(rejected, crypto_close=False)], [dict(rejected, identity='valid')],
                       [rejected, dict(event='echo', bytes=10240)], [rejected, dict(event='tcp_fallback')]):
            with self.subTest(events=events):
                result = self.run_fixture(wrong_events=events)
                self.assertEqual(result['status'], 'error')
                self.assertFalse(result['cases'][1]['accepted'])

    def test_connect_ip_does_not_replace_exact_localhost_sni(self):
        result = self.run_fixture(valid_sni='127.0.0.1')
        self.assertEqual(result['status'], 'error')
        self.assertFalse(result['cases'][0]['accepted'])
        self.assertEqual(result['cases'][1]['status'], 'not_run')


if __name__ == '__main__':
    unittest.main()
