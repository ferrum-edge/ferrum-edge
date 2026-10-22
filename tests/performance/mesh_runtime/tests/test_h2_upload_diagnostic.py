"""No-runtime tests of diagnostic admission, epochs and conservation failures."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests/performance/mesh_runtime'))
import h2_upload_observer as observer
import mesh_h2_upload_diagnostic as controller
import mesh_gap_candidate as ranking


def values(**changes):
    result = dict.fromkeys(observer.FIELDS, 0)
    result.update(schema=2, pid=1, native_state_present=1, native_status200_present=1,
                  native_finalized_total=100, native_status200_total=100, post_pending_total=100)
    result.update(changes)
    return result


def body(record):
    return '\n'.join(observer.PREFIX + k + ' ' + str(v) for k, v in record.items()) + '\n'


def rows():
    result = []
    for i, role in enumerate(('source', 'destination')):
        identity = dict(name=role, container_id=role, image_id='image', host_pid=100+i,
                        starttime=50, namespace_pid=1, started_at='time', restart_count=0)
        result.append(dict(role=role, identity_before=identity, identity_after=identity,
                           values=values(post_pending_total=100 if i == 0 else 0)))
    return result


def receipt(items=None):
    return dict(accepted=True, errors=[], rows=items or rows())


def load():
    return dict(warmup_requests=2, cohort_requests=8, total_requests=5, drained_requests=3,
                total_errors=0, warmup_errors=0, admitted_errors=0,
                total_bytes=5*1024, drained_bytes=3*1024)


def completed():
    result = rows()
    for i, row in enumerate(result):
        row['values']['native_finalized_total'] += 10
        row['values']['native_status200_total'] += 10
        if i == 0:
            row['values']['post_pending_total'] += 10
    return receipt(result)


class ParserTests(unittest.TestCase):
    def test_exact_schema_and_all_four_branches(self):
        self.assertEqual(observer.parse(body(values())), values())
        self.assertEqual(set(observer.BRANCHES), {'post_eos_total', 'post_ready_ok_total', 'post_ready_err_total', 'post_pending_total'})

    def test_missing_is_not_zero(self):
        for name in observer.FIELDS:
            v = values(); del v[name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                observer.parse(body(v))

    def test_duplicate_unknown_noninteger_and_overflow_reject(self):
        samples = [body(values()) + observer.PREFIX + 'schema 2\n',
                   body(values()) + observer.PREFIX + 'unknown 0\n',
                   body(values()).replace('schema 2', 'schema 2.0'),
                   body(values()).replace('schema 2', 'schema -2'),
                   body(values(post_pending_total=2**64)), body(values(counter_overflow=1)),
                   body(values(schema=1)), body(values(native_state_present=0)),
                   body(values(native_status200_present=0)), body(values(pid=0))]
        for sample in samples:
            with self.subTest(sample=sample[-50:]), self.assertRaises(ValueError):
                observer.parse(sample)

    def test_body_bound(self):
        with self.assertRaises(ValueError):
            observer.parse('x' * (observer.MAX_BODY + 1))


class ConservationTests(unittest.TestCase):
    def qualify(self, before=None, after=None, report=None, status=0):
        return observer.qualify(before or receipt(), after or completed(), report or load(), 1024, status)

    def test_warmup_cohort_and_drains_are_conserved(self):
        result = self.qualify()
        self.assertTrue(result['accepted'], result)
        self.assertEqual(result['population'], 10)
        self.assertEqual(result['source_deltas']['post_pending_total'], 10)
        self.assertEqual(result['source_fractions']['post_pending_total'], 1)
        self.assertFalse(result['performance_eligible'])

    def test_mixed_ready_pending_kept_separate(self):
        after = completed(); after['rows'][0]['values']['post_pending_total'] -= 3
        after['rows'][0]['values']['post_ready_ok_total'] += 3
        result = self.qualify(after=after)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['source_fractions']['post_ready_ok_total'], .3)

    def test_every_identity_change_rejects(self):
        for key in rows()[0]['identity_before']:
            after = completed(); after['rows'][0]['identity_before'] = dict(after['rows'][0]['identity_before'], **{key: 'changed'})
            with self.subTest(key=key):
                self.assertFalse(self.qualify(after=after)['accepted'])

    def test_native_missing_stale_and_extra_traffic_reject(self):
        for role in range(2):
            for key in observer.TOTALS:
                after = completed(); after['rows'][role]['values'][key] += 1
                with self.subTest(role=role, key=key):
                    self.assertFalse(self.qualify(after=after)['accepted'])
        self.assertFalse(self.qualify(after=receipt())['accepted'])
        after = completed(); after['rows'][0]['values']['post_pending_total'] = 0
        self.assertFalse(self.qualify(after=after)['accepted'])

    def test_errors_are_retained_with_observed_deltas(self):
        report = load(); report['total_errors'] = 1
        result = self.qualify(report=report)
        self.assertFalse(result['accepted'])
        self.assertEqual(result['source_deltas']['post_pending_total'], 10)
        self.assertFalse(self.qualify(status=1)['accepted'])

    def test_accounting_fields_and_failed_boundary_reject(self):
        for key in load():
            report = load(); report[key] = -1
            with self.subTest(key=key):
                self.assertFalse(self.qualify(report=report)['accepted'])
        before = receipt(); before['accepted'] = False
        self.assertFalse(self.qualify(before=before)['accepted'])
        after = completed(); after['rows'][1]['values']['native_active_requests'] = 1
        self.assertFalse(self.qualify(after=after)['accepted'])


class SettlingTests(unittest.TestCase):
    def settle(self, take):
        now = [0.0]
        def wait(seconds): now[0] += seconds
        directory = Path(self.temp.name) / 'epoch'
        result = observer.settle(['source', 'destination'], 'image', directory,
            clock=lambda: now[0], wait=wait, take=take)
        self.assertTrue((directory / 'receipt.json').exists())
        return result, directory

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_two_quiescent_reads_and_all_attempts_retained(self):
        result, path = self.settle(lambda *args: rows())
        self.assertTrue(result['accepted'])
        self.assertEqual(len(result['attempts']), 2)
        self.assertEqual(result['native_publication_cache_seconds'], 0)
        for attempt in result['attempts']:
            self.assertEqual(controller.digest(path / attempt['path']), attempt['sha256'])

    def test_busy_gauge_has_deadline_and_attempt_bound(self):
        def take(*args):
            sample = rows(); sample[0]['values']['native_active_requests'] = 1; return sample
        result, _ = self.settle(take)
        self.assertFalse(result['accepted'])
        self.assertLessEqual(result['end_monotonic'], observer.SETTLE_SECONDS)
        self.assertLessEqual(len(result['attempts']), observer.SETTLE_ATTEMPTS)
        self.assertGreater(len(result['attempts']), 1)

    def test_changing_counts_restart_reset_or_scrape_error_reject(self):
        # Every invalid observation remains on disk; no traffic retry occurs.
        for failure in ('identity', 'reset', 'scrape'):
            with self.subTest(failure=failure):
                self.temp.cleanup(); self.temp = tempfile.TemporaryDirectory()
                self.addCleanup(self.temp.cleanup)
                count = [0]
                def take(*args):
                    sample = rows(); count[0] += 1
                    if count[0] > 1:
                        if failure == 'identity': sample[0]['identity_before']['starttime'] += 1
                        elif failure == 'reset': sample[0]['values']['native_finalized_total'] = 0
                        else: sample[0]['error'] = 'scrape failed'
                    return sample
                result, path = self.settle(take)
                self.assertFalse(result['accepted'])
                self.assertEqual(len(list(path.glob('attempt-*.json'))), 2)

    def test_capture_keeps_raw_response_on_late_deadline(self):
        now = [0]
        ident = rows()[0]['identity_before']
        def identity(*args):
            return ident
        def fetch(*args):
            now[0] = 7
            return subprocess.CompletedProcess([], 0, stdout=body(values()).encode(), stderr=b'')
        with patch.object(observer, 'read_identity', identity), patch.object(observer, 'fetch', fetch):
            result = observer.capture(['source', 'destination'], 'image', 6.5, lambda: now[0])
        self.assertIn('body', result[0])
        self.assertIn('error', result[0])


class AdmissionTests(unittest.TestCase):
    def test_phase_source_and_manifest_only_scope(self):
        controller.validate_input(controller.SOURCE, 'h2-upload-vendor-preflight', [], controller.BASELINE)
        controller.validate_input('a'*40, 'h2-upload-diagnostic', [controller.MANIFEST], controller.BASELINE)
        for candidate, phase, changes, parent in [
            ('main', controller.PHASES[0], [], controller.BASELINE),
            (controller.SOURCE, 'gap-compare', [], controller.BASELINE),
            (controller.SOURCE, controller.PHASES[0], ['src/admin/mod.rs'], controller.BASELINE),
            (controller.SOURCE, controller.PHASES[0], [], '4a'*20),
        ]:
            with self.assertRaises(ValueError): controller.validate_input(candidate, phase, changes, parent)

    def test_fixed_two_cells_and_no_ranking_kind(self):
        self.assertEqual(controller.CELLS, [dict(payload=1024, concurrency=100), dict(payload=1048576, concurrency=50)])
        self.assertNotIn('h2-upload-diagnostic', ranking.KINDS)
        self.assertNotIn('h2-upload-diagnostic', ranking.PHASES)

    def test_ranking_rejects_observer_cargo_feature_delta(self):
        with patch.dict('os.environ', GAP_CANDIDATE_SHA=controller.SOURCE,
                        GAP_CANDIDATE_KIND='h2-handoff', BENCH_PHASE='gap-compare'):
            with self.assertRaisesRegex(ValueError, 'frozen build inputs: Cargo.toml'):
                ranking.selection()

    def test_pinned_source_preserves_channel_and_send_task(self):
        path = 'vendor/hyper-1.10.0-ferrum-patched/src/proto/h2/client.rs'
        source = subprocess.check_output(['git', 'show', controller.SOURCE + ':' + path], cwd=ROOT, text=True)
        self.assertIn('let (cancel_tx, cancel_rx) = oneshot::channel::<()>();', source)
        self.assertIn('cancel_tx: Some(cancel_tx),', source)
        self.assertIn('self.executor.execute_h2_future(H2ClientFuture::Send {', source)
        self.assertNotIn('ferrum_lazy_cancel_tests', source)
        self.assertNotIn('SendBatch', source)
        self.assertEqual(subprocess.check_output(['git', 'show', '-s', '--format=%P', controller.SOURCE_ORIGIN], cwd=ROOT, text=True).strip(), controller.BASELINE)


if __name__ == '__main__':
    unittest.main()
