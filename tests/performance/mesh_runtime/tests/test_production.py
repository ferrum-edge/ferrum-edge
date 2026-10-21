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
    def valid_load(self, cell):
        count=cell["rate"]*cell["duration"] if cell["rate"] else 6000
        return dict(mesh=campaign.physical(cell["arm"]),protocol="http1",payload_size=cell["payload"],
            duration_secs=cell["duration"],rate=cell["rate"],concurrency=100,
            total_errors=0,warmup_errors=0,warmup_requests=30,total_requests=count,drained_requests=0,
            admitted_requests=count,cohort_requests=count,admitted_errors=0,
            scheduled_requests=count if cell["rate"] else 0,cohort_scheduled_requests=count if cell["rate"] else 0,
            total_bytes=count*cell["payload"],drained_bytes=0,rps=count/cell["duration"],
            missed_requests=0,offered_requests=count if cell["rate"] else 0,missed_slot_count=0,
            missed_reservations=0,unclaimed_requests=0,first_missed_slot=None,last_missed_slot=None,
            cohort_p50_us=5,cohort_p95_us=7,cohort_p99_us=8,cohort_scheduled_p50_us=6,
            cohort_scheduled_p95_us=8,cohort_scheduled_p99_us=9,admission_delay_p99_us=1,admission_delay_max_us=2)

    def boundary_load(self, cell):
        load=self.valid_load(cell)
        load.update(total_requests=5998,admitted_requests=5998,cohort_requests=5998,
            scheduled_requests=5998,cohort_scheduled_requests=5998,total_bytes=5998*cell["payload"],
            rps=5998/cell["duration"],missed_requests=2,missed_slot_count=2,missed_reservations=1,
            unclaimed_requests=1,first_missed_slot=5998,last_missed_slot=5999)
        return load

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
        load=self.valid_load(cell)
        resource=dict(valid=True,errors=[])
        self.assertEqual(campaign.validate(cell,load,resource),[])
        for key,value in (("cohort_p99_us",None),("rps",float("nan")),("missed_requests",1),("mesh","envoy"),("duration_secs",2),("offered_requests",5999),("warmup_errors",1)):
            self.assertTrue(campaign.validate(cell,{**load,key:value},resource))
        self.assertTrue(campaign.validate(cell,load,{"valid":False,"errors":[]}))
        boundary=self.boundary_load(cell)
        self.assertEqual(campaign.validate(cell,boundary,resource),[])
        self.assertTrue(campaign.validate(cell,{**boundary,"first_missed_slot":5},resource))
        self.assertTrue(campaign.validate(cell,{**boundary,"missed_slot_count":1},resource))
        self.assertTrue(campaign.validate(cell,{**boundary,"unclaimed_requests":0},resource))

    def test_counts_require_nonnegative_integers(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.valid_load(cell)
        keys=("total_requests","drained_requests","cohort_requests","admitted_requests","admitted_errors",
            "total_errors","warmup_requests","warmup_errors","scheduled_requests","cohort_scheduled_requests",
            "offered_requests","missed_requests","missed_slot_count","missed_reservations","unclaimed_requests",
            "total_bytes","drained_bytes")
        for key in keys:
            for value in (-1,True,"0",None,0.5):
                with self.subTest(key=key,value=value):
                    errors=campaign.validate(cell,{**load,key:value},{"valid":True,"errors":[]})
                    self.assertIn(f"missing or invalid nonnegative integer count {key}",errors)

    def test_success_drain_histogram_bytes_and_rps_conservation(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.valid_load(cell)
        cases=(({"cohort_requests":5999},"successful cohort must equal useful completions plus drains"),
            ({"drained_requests":1},"successful cohort must equal useful completions plus drains"),
            ({"admitted_requests":5999},"admitted cohort accounting mismatch"),
            ({"admitted_errors":1},"total errors do not cover admitted and warmup errors"),
            ({"scheduled_requests":5999},"scheduled successful histograms do not conserve completions and drains"),
            ({"cohort_scheduled_requests":5999},"scheduled successful histograms do not conserve completions and drains"),
            ({"total_bytes":0},"successful echo byte accounting mismatch"),
            ({"drained_bytes":1024},"successful echo byte accounting mismatch"),
            ({"rps":1999},"throughput does not match useful completions and duration"))
        for change,expected in cases:
            with self.subTest(change=change):
                self.assertIn(expected,campaign.validate(cell,{**load,**change},{"valid":True,"errors":[]}))
        impossible={**self.boundary_load(cell),"total_requests":6000,"total_bytes":6000*cell["payload"],"rps":2000}
        self.assertTrue(campaign.validate(cell,impossible,{"valid":True,"errors":[]}))

    def test_boundary_cohort_keeps_successful_drain_out_of_useful_rps(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.boundary_load(cell)
        load.update(total_requests=5997,scheduled_requests=5997,drained_requests=1,
            total_bytes=5997*cell["payload"],drained_bytes=cell["payload"],rps=5997/3)
        self.assertEqual(campaign.validate(cell,load,{"valid":True,"errors":[]}),[])

    def test_saturated_counts_have_no_scheduled_population(self):
        cell=campaign.plan("smoke-l7")[1]
        load=self.valid_load(cell)
        self.assertEqual(campaign.validate(cell,load,{"valid":True,"errors":[]}),[])
        for key in ("scheduled_requests","cohort_scheduled_requests","offered_requests","missed_requests"):
            self.assertTrue(campaign.validate(cell,{**load,key:1},{"valid":True,"errors":[]}))

    def summarize_fixture(self,root,cell,load,resource):
        (root/"production-plan.json").write_text(json.dumps([cell]))
        path=root/cell["arm"]/cell["load"]/f"run_{cell['repetition']}"/f"payload_{cell['payload']}"
        path.mkdir(parents=True)
        name=f"{campaign.physical(cell['arm'])}_http1_{cell['payload']}"
        (path/f"{name}.json").write_text(json.dumps(load))
        (path/f"{name}.resources.json").write_text(json.dumps(resource))
        with patch.object(campaign,"ROOT",root):
            status=campaign.summarize()
        return status,json.loads((root/"production-summary.json").read_text())

    def test_malformed_counts_remain_in_summary_ledger(self):
        cell=campaign.plan("smoke-l7")[-1]
        for value in ("6000",None,True,-1):
            with self.subTest(value=value),tempfile.TemporaryDirectory() as tmp:
                load={**self.valid_load(cell),"total_requests":value}
                status,result=self.summarize_fixture(Path(tmp),cell,load,dict(valid=True,errors=[],proxy_cpu_seconds=1.0))
                self.assertEqual(status,1)
                self.assertEqual(result["parsed_cells"],1)
                self.assertEqual(result["cells"][0]["report"]["total_requests"],value)
                self.assertIsNone(result["cells"][0]["cpu_us_per_completion"])

    def test_boundary_summary_preserves_strict_status_losses_and_scheduled_latency(self):
        cell=campaign.plan("smoke-l7")[-1]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            status,result=self.summarize_fixture(root,cell,self.boundary_load(cell),dict(valid=True,errors=[],proxy_cpu_seconds=1.0))
            self.assertEqual(status,0)
            self.assertTrue(result["valid"])
            self.assertFalse(result["strict_zero_miss_valid"])
            self.assertFalse(result["cells"][0]["strict_zero_miss"])
            loss=result["fixed_admission_losses"][0]
            self.assertEqual((loss["offered"],loss["missed"]),(6000,2))
            self.assertEqual(loss["loss_fraction"],2/6000)
            self.assertIn("6/8/9",(root/"production-summary.md").read_text())

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
