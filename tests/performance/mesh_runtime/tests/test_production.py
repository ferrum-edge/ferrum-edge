import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("campaign", ROOT/".github/scripts/mesh_production_campaign.py")
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)

class ProductionContracts(unittest.TestCase):
    def test_full_plan_has_balanced_adjacent_identical_image_controls(self):
        cells=campaign.plan("ranking")
        self.assertEqual(len(cells),128)
        self.assertEqual(len({tuple(c.values()) for c in cells}),128)
        for load in ("fixed","saturated"):
            for payload in (1024,1048576):
                blocks=[[c["arm"] for c in cells if c["load"]==load and c["payload"]==payload and c["repetition"]==r] for r in range(1,5)]
                self.assertEqual(blocks[0],list(reversed(blocks[1])))
                self.assertEqual(blocks[2],list(reversed(blocks[3])))
                for block in blocks:
                    self.assertEqual(abs(block.index("ferruma")-block.index("ferrumb")),1)
                    self.assertEqual(abs(block.index("ferrumtcpa")-block.index("ferrumtcpb")),1)

    def test_bad_metadata_and_missed_fixed_slots_fail(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=dict(mesh="ferrum",protocol="http1",payload_size=1024,duration_secs=3,rate=2000,concurrency=100,
                  total_errors=0,warmup_errors=0,total_requests=6000,admitted_requests=6000,cohort_requests=6000,
                  admitted_errors=0,missed_requests=0,offered_requests=6000,missed_slot_count=0,missed_reservations=0,unclaimed_requests=0,first_missed_slot=None,last_missed_slot=None)
        load.update(dict(rps=2000,cohort_p50_us=5,cohort_p95_us=7,cohort_p99_us=8,cohort_scheduled_p50_us=6,cohort_scheduled_p95_us=8,cohort_scheduled_p99_us=9,admission_delay_p99_us=1,admission_delay_max_us=2))
        resource=dict(valid=True,errors=[])
        self.assertEqual(campaign.validate(cell,load,resource),[])
        for key,value in (("cohort_p99_us",None),("rps",float("nan")),("missed_requests",1),("mesh","envoy"),("duration_secs",2),("offered_requests",5999),("warmup_errors",1)):
            self.assertTrue(campaign.validate(cell,{**load,key:value},resource))
        self.assertTrue(campaign.validate(cell,load,{"valid":False,"errors":[]}))
        boundary={**load,"admitted_requests":5998,"cohort_requests":5998,"missed_requests":2,"missed_slot_count":2,
                  "missed_reservations":1,"unclaimed_requests":1,"first_missed_slot":5998,"last_missed_slot":5999}
        self.assertEqual(campaign.validate(cell,boundary,resource),[])
        self.assertTrue(campaign.validate(cell,{**boundary,"first_missed_slot":5},resource))
        self.assertTrue(campaign.validate(cell,{**boundary,"missed_slot_count":1},resource))
        self.assertTrue(campaign.validate(cell,{**boundary,"unclaimed_requests":0},resource))

    def test_invalid_failure_stub_retains_complete_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            cell=campaign.plan("smoke-l7")[1]
            (root/"production-plan.json").write_text(json.dumps([cell]))
            path=root/"ferruma/saturated/run_1/payload_1024"
            path.mkdir(parents=True)
            (path/"ferrum_http1_1024.json").write_text(json.dumps(dict(mesh="ferrum",rps=0,total_errors=-1,error="loadgen failed")))
            (path/"ferrum_http1_1024.resources.json").write_text(json.dumps(dict(valid=False,errors=["PID missing"])))
            with patch.object(campaign,"ROOT",root):
                self.assertEqual(campaign.summarize(),1)
            result=json.loads((root/"production-summary.json").read_text())
            self.assertEqual(result["parsed_cells"],1)
            self.assertFalse(result["valid"])
            self.assertIsNone(result["groups"][0]["metrics"])
            self.assertIn("INVALID",(root/"production-summary.md").read_text())

if __name__=="__main__": unittest.main()
