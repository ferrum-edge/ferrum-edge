import importlib.util
from pathlib import Path
import unittest
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
                  admitted_errors=0,missed_requests=0,offered_requests=6000)
        resource=dict(valid=True,errors=[])
        self.assertEqual(campaign.validate(cell,load,resource),[])
        for key,value in (("missed_requests",1),("mesh","envoy"),("duration_secs",2),("offered_requests",5999),("warmup_errors",1)):
            self.assertTrue(campaign.validate(cell,{**load,key:value},resource))
        self.assertTrue(campaign.validate(cell,load,{"valid":False,"errors":[]}))

if __name__=="__main__": unittest.main()
