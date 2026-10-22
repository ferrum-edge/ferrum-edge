import copy
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'.github/scripts'))
import mesh_header_ladder_plan as plan
spec=importlib.util.spec_from_file_location('header_collector',ROOT/'tests/performance/mesh_runtime/collect_resources.py')
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)

class HeaderLadderTests(unittest.TestCase):
 def test_finite_reversed_geometry(self):
  rows=plan.cells();self.assertEqual(len(rows),30);self.assertEqual(len(plan.cells(True)),6)
  self.assertEqual(len({r['directory'] for r in rows}),30)
  self.assertEqual([(r['arm'],r['profile']) for r in rows[:15]],list(reversed([(r['arm'],r['profile']) for r in rows[15:]])))
  for arm in plan.ARMS:
   for rep in (1,2):
    zero=[r for r in rows if r['arm']==arm and r['repetition']==rep and r['header_count']==0]
    self.assertEqual(len(zero),2);self.assertEqual({r['header_value_bytes'] for r in zero},{32})
 def test_receipt_population_includes_warmup_and_drains(self):
  cell=plan.cells()[1];receipt=plan.header_metadata(cell['header_count'],cell['header_value_bytes'])
  load=dict(warmup_requests=2,total_requests=4,drained_requests=1,cohort_requests=5,
   diagnostic_headers=dict(receipt,validated_receipt=receipt['expected_receipt'],validated_exchanges=7))
  self.assertEqual(plan.header_issues(cell,load),[])
  for key,value in [('count',True),('value_bytes',256),('validated_exchanges',6),('validated_receipt',None)]:
   bad=copy.deepcopy(load);bad['diagnostic_headers'][key]=value;self.assertTrue(plan.header_issues(cell,bad))
 def test_bounds_and_exact_wire_encoding(self):
  self.assertEqual(plan.header_metadata(8,32),dict(count=8,value_bytes=32,added_request_wire_bytes=416,expected_receipt='08-0020'))
  for count,value in [(True,32),(-1,32),(33,32),(8,257),(8,None)]:
   with self.assertRaises(ValueError):plan.header_metadata(count,value)
 def test_missing_ratios_are_never_filtered(self):
  rows=plan.comparisons([]);self.assertEqual(len(rows),15)
  self.assertTrue(all(r['identical_workload_aa']==[None,None] for r in rows))
  self.assertTrue(all(v==[None,None] for r in rows for v in r['profile_over_baseline'].values()))
 def test_collector_explicit_phase_crosses_sudo_as_argv(self):
  a=SimpleNamespace(diagnostic_header_count=0,diagnostic_header_value_bytes=32,header_ladder_diagnostic=True,
   mesh='ferrum',production_observe=True,perf_leaf=False,allocation_url=[],rate=0,payload_size='1024',duration='30',concurrency='100',warmup='3')
  self.assertEqual(collector.header_diagnostic_args(a),['--diagnostic-header-count','0','--diagnostic-header-value-bytes','32'])
  for key,value in [('header_ladder_diagnostic',False),('diagnostic_header_count',True),('diagnostic_header_value_bytes',None),('mesh','consultcp'),('perf_leaf',True),('duration','60')]:
   b=copy.copy(a);setattr(b,key,value)
   with self.assertRaises(ValueError):collector.header_diagnostic_args(b)
  self.assertEqual(collector.header_diagnostic_args(SimpleNamespace()),[])

if __name__=='__main__':unittest.main()
