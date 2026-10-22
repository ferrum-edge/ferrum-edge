"""Synthetic proc/cgroup and mocked command contracts; no Cargo or workloads."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import mesh_gap_checks as checks


class CheckMemoryContracts(unittest.TestCase):
    def fixture(self, root, membership='/job'):
        proc, cgroup = root/'proc', root/'cgroup'
        (proc/'self').mkdir(parents=True)
        (proc/'meminfo').write_text('MemTotal: 16000 kB\nMemAvailable: 4000 kB\nSwapTotal: 2000 kB\nSwapFree: 1000 kB\nSecret: DO_NOT_LOG\n')
        (proc/'self/cgroup').write_text('0::'+membership+'\n')
        for directory in {cgroup,cgroup/membership.lstrip('/')}:
            directory.mkdir(parents=True,exist_ok=True)
            for filename in checks.CGROUP_MEMORY_FILES:
                value = 'low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\noom_group_kill 0\n' if 'events' in filename else ('max' if filename.endswith('.max') else '1234')
                (directory/filename).write_text(value+'\n')
        return proc,cgroup

    def test_fixed_numeric_host_current_and_root_counters(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc,cgroup=self.fixture(Path(temporary))
            snapshot=checks.memory_snapshot(proc,cgroup)
            self.assertEqual(snapshot['host_meminfo_kib'],dict(MemTotal=16000,MemAvailable=4000,SwapTotal=2000,SwapFree=1000))
            self.assertEqual([r['scope'] for r in snapshot['cgroups']],['current','root'])
            self.assertEqual([r['current'] for r in snapshot['cgroups']],[True,False])
            self.assertEqual(snapshot['cgroups'][0]['values']['memory.events']['oom_kill'],1)
            self.assertEqual(snapshot['cgroups'][1]['values']['memory.max'],'max')
            self.assertEqual(snapshot['errors'],[])
            self.assertTrue(all(not r['errors'] for r in snapshot['cgroups']))
            self.assertNotIn('DO_NOT_LOG',json.dumps(snapshot))
            self.assertNotIn(str(proc),json.dumps(snapshot))
            self.assertLess(len(json.dumps(snapshot)),4096)

    def test_current_root_is_not_duplicated_or_mislabeled(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc,cgroup=self.fixture(Path(temporary),'/')
            snapshot=checks.memory_snapshot(proc,cgroup)
            self.assertEqual(len(snapshot['cgroups']),1)
            self.assertEqual(snapshot['cgroups'][0]['scope'],'root')
            self.assertTrue(snapshot['cgroups'][0]['current'])

    def test_missing_oversized_and_invalid_inputs_stay_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc,cgroup=self.fixture(Path(temporary))
            (cgroup/'job/memory.peak').unlink()
            (cgroup/'job/memory.current').write_text('9'*(checks.MEMORY_READ_BYTES+1))
            (cgroup/'job/memory.events').write_text('oom_kill -1\n')
            snapshot=checks.memory_snapshot(proc,cgroup)
            current=snapshot['cgroups'][0]
            self.assertEqual({r['source'] for r in current['errors']},{'memory.peak','memory.current','memory.events'})
            self.assertEqual(current['values']['memory.max'],'max')
            (proc/'self/cgroup').write_text('0::/../../DO_NOT_LOG\n')
            snapshot=checks.memory_snapshot(proc,cgroup)
            self.assertEqual(snapshot['cgroups'],[])
            self.assertEqual(snapshot['errors'][0]['source'],'cgroup_membership')
            self.assertNotIn('DO_NOT_LOG',json.dumps(snapshot))
            missing=checks.memory_snapshot(Path(temporary)/'missing',cgroup)
            self.assertEqual({r['source'] for r in missing['errors']},{'host_meminfo','cgroup_membership'})

    def run_mocked(self, root, command, name='clippy', code=0, heartbeat=False, **options):
        process=mock.Mock(pid=123)
        process.wait.side_effect=[subprocess.TimeoutExpired(command,30),code] if heartbeat else [code]
        def spawn(*args,**kwargs):
            kwargs['stdout'].write('test result: ok. 1 passed; 0 failed; 0 ignored;\n')
            return process
        clocks=[0,30,31] if heartbeat else [0,1]
        with mock.patch.object(checks.subprocess,'Popen',side_effect=spawn) as popen, \
             mock.patch.object(checks.time,'monotonic',side_effect=clocks), \
             mock.patch.object(checks,'emit_memory_snapshot') as emit, \
             contextlib.redirect_stdout(io.StringIO()):
            result=checks.run_command(command,root,root,name,**options)
        return result,popen,emit,process

    def test_actual_clippy_command_alone_gets_one_job_and_boundary_snapshots(self):
        commands=[['cargo','clippy','--locked','--features','cloud-secrets','--lib','--tests','-p','ferrum-edge','--','-D','warnings'],
                  ['cargo','clippy','--locked','--lib','--tests','-p','ferrum-edge','--','-D','warnings']]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(checks.os.environ,{'CARGO_BUILD_JOBS':'99','RUSTFLAGS':'--cap-lints=allow','FERRUM_SECRET':'DO_NOT_LOG'}):
            root=Path(temporary)
            for command in commands:
                with self.subTest(command=command):
                    (record,_),popen,emit,process=self.run_mocked(root,command,name='strict-check',heartbeat=True)
                    self.assertEqual(popen.call_args.args,(command,))
                    self.assertEqual(popen.call_args.kwargs['env']['CARGO_BUILD_JOBS'],'1')
                    self.assertEqual(record['command'],command)
                    self.assertIsNone(record['rustflags'])
                    self.assertFalse(any(k.startswith('FERRUM_') for k in popen.call_args.kwargs['env']))
                    self.assertEqual(emit.call_args_list,[mock.call('strict-check','before'),mock.call('strict-check','heartbeat'),mock.call('strict-check','after')])
                    self.assertEqual(process.wait.call_args_list,[mock.call(timeout=30),mock.call(timeout=30)])

    def test_other_commands_keep_two_jobs_and_only_existing_heartbeat(self):
        commands=[['cargo','test','--locked','--features','cloud-secrets','--test','unit_tests','filter'],
                  ['cargo','build','--locked','--features','cloud-secrets','--bin','ferrum-edge'],['cargo','fmt','--all','--','--check']]
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for command in commands:
                (record,_),popen,emit,_=self.run_mocked(root,command,heartbeat=True)
                self.assertEqual(popen.call_args.args,(command,))
                self.assertEqual(record['correctness_environment']['CARGO_BUILD_JOBS'],'2')
                self.assertEqual(emit.call_args_list,[mock.call('clippy','heartbeat')])  # name alone cannot select Clippy settings

    def test_diagnostic_unavailability_never_replaces_real_exit(self):
        command=['cargo','clippy','--locked','--features','cloud-secrets','--lib','--tests','-p','ferrum-edge','--','-D','warnings']
        unavailable=dict(schema='mesh_gap_check_memory.v1',host_meminfo_kib={},cgroups=[],errors=[dict(source='host_meminfo',error='PermissionError',errno=13)])
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            process=mock.Mock(pid=123)
            process.wait.return_value=0
            with mock.patch.object(checks.subprocess,'Popen',return_value=process),mock.patch.object(checks,'memory_snapshot',return_value=unavailable),contextlib.redirect_stdout(io.StringIO()) as output:
                record,_=checks.run_command(command,root,root,'clippy')
                self.assertEqual(record['exit_code'],0)
                self.assertEqual(output.getvalue().count('[gap-check-memory]'),2)
                self.assertIn('PermissionError',output.getvalue())
            process.wait.return_value=101
            with mock.patch.object(checks.subprocess,'Popen',return_value=process),mock.patch.object(checks,'memory_snapshot',return_value=unavailable),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):
                checks.run_command(command,root,root,'clippy')
            self.assertEqual(json.loads((root/'clippy.json').read_text())['exit_code'],101)


if __name__ == '__main__':
    unittest.main()
