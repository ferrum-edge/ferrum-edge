import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
from types import SimpleNamespace
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("campaign", ROOT/".github/scripts/mesh_production_campaign.py")
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)

class ProductionContracts(unittest.TestCase):
    def valid_resource(self, cell):
        return dict(valid=True, errors=[], proxy_cpu_seconds=1.0,
            elapsed_seconds=cell["duration"], begin={"monotonic": 10.0},
            end={"monotonic": 10.0+cell["duration"]})

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
            cohort_p50_us=5,cohort_p95_us=7,cohort_p99_us=8,cohort_scheduled_p50_us=6 if cell["rate"] else 0,
            cohort_scheduled_p95_us=8 if cell["rate"] else 0,cohort_scheduled_p99_us=9 if cell["rate"] else 0,
            admission_delay_p99_us=1 if cell["rate"] else 0,admission_delay_max_us=2 if cell["rate"] else 0)

    def boundary_load(self, cell):
        load=self.valid_load(cell)
        load.update(total_requests=5998,admitted_requests=5998,cohort_requests=5998,
            scheduled_requests=5998,cohort_scheduled_requests=5998,total_bytes=5998*cell["payload"],
            rps=5998/cell["duration"],missed_requests=2,missed_slot_count=2,missed_reservations=1,
            unclaimed_requests=1,first_missed_slot=5998,last_missed_slot=5999)
        return load

    def error_load(self, cell, errors=1):
        load=self.valid_load(cell)
        successful=load["total_requests"]-errors
        load.update(total_requests=successful,cohort_requests=successful,admitted_errors=errors,total_errors=errors,
            scheduled_requests=successful if cell["rate"] else 0,
            cohort_scheduled_requests=successful if cell["rate"] else 0,
            total_bytes=successful*cell["payload"],rps=successful/cell["duration"])
        if not successful:
            for key in campaign.TAIL_KEYS:
                load[key]=0
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

    def test_fixed_diagnostic_is_bounded_and_does_not_replace_ranking(self):
        cells=campaign.plan("smoke-fixed")
        self.assertEqual(len(cells),8)
        self.assertTrue(all(c["duration"]==30 and c["rate"]==2000 and c["payload"]==1024 and c["load"]=="fixed" for c in cells))
        self.assertEqual([c["arm"] for c in cells[:4]],list(reversed([c["arm"] for c in cells[4:]])))
        self.assertEqual(len(campaign.plan("ranking")),128)

    def test_bad_metadata_and_missed_fixed_slots_fail(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.valid_load(cell)
        resource=self.valid_resource(cell)
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
                    errors=campaign.validate(cell,{**load,key:value},self.valid_resource(cell))
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
                self.assertIn(expected,campaign.validate(cell,{**load,**change},self.valid_resource(cell)))
        impossible={**self.boundary_load(cell),"total_requests":6000,"total_bytes":6000*cell["payload"],"rps":2000}
        self.assertTrue(campaign.validate(cell,impossible,self.valid_resource(cell)))

    def test_boundary_cohort_keeps_successful_drain_out_of_useful_rps(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.boundary_load(cell)
        load.update(total_requests=5997,scheduled_requests=5997,drained_requests=1,
            total_bytes=5997*cell["payload"],drained_bytes=cell["payload"],rps=5997/3)
        self.assertEqual(campaign.validate(cell,load,self.valid_resource(cell)),[])

    def test_saturated_counts_have_no_scheduled_population(self):
        cell=campaign.plan("smoke-l7")[1]
        load=self.valid_load(cell)
        self.assertEqual(campaign.validate(cell,load,self.valid_resource(cell)),[])
        for key in ("scheduled_requests","cohort_scheduled_requests","offered_requests","missed_requests"):
            self.assertTrue(campaign.validate(cell,{**load,key:1},self.valid_resource(cell)))

    def summarize_fixture(self,root,cell,load,resource):
        (root/"production-plan.json").write_text(json.dumps([cell]))
        self.write_cell(root,cell,load,resource)
        with patch.object(campaign,"ROOT",root):
            status=campaign.summarize()
        return status,json.loads((root/"production-summary.json").read_text())

    def write_cell(self,root,cell,load,resource):
        path=root/cell["arm"]/cell["load"]/f"run_{cell['repetition']}"/f"payload_{cell['payload']}"
        path.mkdir(parents=True)
        name=f"{campaign.physical(cell['arm'])}_http1_{cell['payload']}"
        (path/f"{name}.json").write_text(json.dumps(load))
        (path/f"{name}.resources.json").write_text(json.dumps(resource))

    def test_malformed_counts_remain_in_summary_ledger(self):
        cell=campaign.plan("smoke-l7")[-1]
        for value in ("6000",None,True,-1):
            with self.subTest(value=value),tempfile.TemporaryDirectory() as tmp:
                load={**self.valid_load(cell),"total_requests":value}
                status,result=self.summarize_fixture(Path(tmp),cell,load,self.valid_resource(cell))
                self.assertEqual(status,1)
                self.assertEqual(result["parsed_cells"],1)
                self.assertEqual(result["cells"][0]["report"]["total_requests"],value)
                self.assertIsNone(result["cells"][0]["cpu_us_per_completion"])

    def test_boundary_summary_preserves_strict_status_losses_and_scheduled_latency(self):
        cell=campaign.plan("smoke-l7")[-1]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            status,result=self.summarize_fixture(root,cell,self.boundary_load(cell),self.valid_resource(cell))
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

    def test_conserved_errors_are_observations_but_never_zero_error_capacity(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.error_load(cell)
        load.update(warmup_errors=2,total_errors=3)
        resource=self.valid_resource(cell)
        self.assertEqual(campaign.validate_observation(cell,load,resource),[])
        self.assertEqual(campaign.validate(cell,load,resource,require_zero_errors=False),[])
        self.assertTrue(campaign.validate(cell,load,resource))
        with tempfile.TemporaryDirectory() as tmp:
            status,result=self.summarize_fixture(Path(tmp),cell,load,resource)
            row=result["cells"][0]
            self.assertEqual(status,1)
            self.assertTrue(result["measurement_valid"])
            self.assertTrue(row["measurement_valid"])
            self.assertFalse(row["zero_error_capacity_qualified"])
            self.assertEqual(row["classification"],"observed_end_to_end_errors")
            self.assertEqual(row["report"],load)
            metrics=row["observed_metrics"]
            self.assertEqual(metrics["goodput_rps"],5999/3)
            self.assertEqual(metrics["admitted_error_rate"],1/6000)
            self.assertEqual(metrics["total_error_rate"],3/(5999+30+3))
            self.assertEqual(metrics["warmup_error_rate"],2/32)
            self.assertEqual(result["groups"][0]["metrics"]["total_errors"]["all"],[3])

    def test_admission_losses_outside_capacity_bound_remain_observed(self):
        cell=campaign.plan("smoke-fixed")[1]
        load=self.valid_load(cell)
        successes=load["offered_requests"]-3
        load.update(total_requests=successes,cohort_requests=successes,admitted_requests=successes,
            scheduled_requests=successes,cohort_scheduled_requests=successes,total_bytes=successes*cell["payload"],
            rps=successes/cell["duration"],missed_requests=3,missed_slot_count=3,missed_reservations=2,
            unclaimed_requests=1,first_missed_slot=59997,last_missed_slot=59999)
        self.assertEqual(campaign.validate_observation(cell,load,self.valid_resource(cell)),[])
        self.assertTrue(campaign.validate(cell,load,self.valid_resource(cell)))
        with tempfile.TemporaryDirectory() as tmp:
            status,result=self.summarize_fixture(Path(tmp),cell,load,self.valid_resource(cell))
            self.assertEqual(status,1)
            self.assertTrue(result["measurement_valid"])
            self.assertEqual(result["zero_error_cells"],1)
            self.assertEqual(result["zero_error_capacity_cells"],0)
            self.assertEqual(result["cells"][0]["observed_metrics"]["admission_miss_rate"],3/60000)
            self.assertEqual(result["fixed_admission_losses"][0]["missed"],3)
        for change in ({"missed_slot_count":2},{"unclaimed_requests":0},{"first_missed_slot":59999},
                       {"last_missed_slot":60000},{"admitted_requests":60000}):
            self.assertTrue(campaign.validate_observation(cell,{**load,**change},self.valid_resource(cell)))

    def test_errors_do_not_excuse_malformed_counts_metadata_or_resource_faults(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.error_load(cell)
        for change in ({"admitted_errors":0},{"cohort_requests":6000},{"total_errors":0},
                       {"total_bytes":0},{"rps":2000},{"mesh":"envoy"},{"rate":1999},
                       {"total_requests":-1}):
            self.assertTrue(campaign.validate_observation(cell,{**load,**change},self.valid_resource(cell)))
        for change in ({"valid":False},{"errors":["PID changed"]},{"proxy_cpu_seconds":None},
                       {"proxy_cpu_seconds":-1},{"elapsed_seconds":999},{"begin":None},
                       {"end":{"monotonic":9}}):
            self.assertTrue(campaign.validate_observation(cell,load,{**self.valid_resource(cell),**change}))

    def test_empty_histograms_cannot_hide_nonzero_raw_quantiles(self):
        cell=campaign.plan("smoke-l7")[-1]
        load=self.error_load(cell,6000)
        for key in campaign.TAIL_KEYS:
            with self.subTest(key=key):
                self.assertTrue(campaign.validate_observation(cell,{**load,key:1},self.valid_resource(cell)))
        load.update(total_errors=0,admitted_errors=0,admitted_requests=0,missed_requests=6000,
            missed_slot_count=6000,missed_reservations=100,unclaimed_requests=5900,
            first_missed_slot=0,last_missed_slot=5999,admission_delay_p99_us=0,admission_delay_max_us=0)
        self.assertEqual(campaign.validate_observation(cell,load,self.valid_resource(cell)),[])
        self.assertTrue(campaign.validate(cell,load,self.valid_resource(cell)))
        for key in ("admission_delay_p99_us","admission_delay_max_us"):
            with self.subTest(key=key):
                self.assertTrue(campaign.validate_observation(cell,{**load,key:1},self.valid_resource(cell)))
        saturated=campaign.plan("smoke-l7")[1]
        load=self.valid_load(saturated)
        for key in campaign.TAIL_KEYS[3:]:
            self.assertTrue(campaign.validate_observation(saturated,{**load,key:1},self.valid_resource(saturated)))

    def test_zero_goodput_and_every_repetition_remain_in_group_statistics(self):
        cell=campaign.plan("smoke-l7")[-1]
        cells=[{**cell,"repetition":repetition} for repetition in range(1,5)]
        loads=[self.valid_load(cell),self.error_load(cell),self.valid_load(cell),self.error_load(cell,6000)]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"production-plan.json").write_text(json.dumps(cells))
            for planned,load in zip(cells,loads):
                self.write_cell(root,planned,load,self.valid_resource(planned))
            with patch.object(campaign,"ROOT",root):
                self.assertEqual(campaign.summarize(),1)
            result=json.loads((root/"production-summary.json").read_text())
            group=result["groups"][0]
            self.assertEqual((group["planned_repetitions"],group["parsed_repetitions"],
                group["measurement_valid_repetitions"],group["zero_error_repetitions"],
                group["capacity_qualified_repetitions"]),(4,4,4,2,2))
            self.assertEqual([row["repetition"] for row in group["observations"]],[1,2,3,4])
            self.assertEqual(group["metrics"]["total_errors"]["all"],[0,1,0,6000])
            self.assertEqual(group["metrics"]["goodput_rps"]["all"],[2000,5999/3,2000,0])
            for key in ("cpu_us_per_completion",*campaign.TAIL_KEYS):
                self.assertIsNone(group["metrics"][key]["all"][-1])
                for statistic in ("median","min","max"):
                    self.assertIsNone(group["metrics"][key][statistic])
            self.assertEqual(result["cells"][-1]["report"]["cohort_p99_us"],0)
            self.assertEqual(result["cells"][-1]["observed_metrics"]["admitted_error_rate"],1)
            self.assertFalse(group["all_valid"])
            self.assertTrue(group["all_measurement_valid"])
            missing=root/cells[-1]["arm"]/cells[-1]["load"]/'run_4'/f"payload_{cell['payload']}"
            (missing/f"{campaign.physical(cell['arm'])}_http1_{cell['payload']}.resources.json").unlink()
            with patch.object(campaign,"ROOT",root):
                self.assertEqual(campaign.summarize(),1)
            group=json.loads((root/"production-summary.json").read_text())["groups"][0]
            self.assertEqual((group["planned_repetitions"],group["parsed_repetitions"],group["measurement_valid_repetitions"]),(4,3,3))
            self.assertEqual(len(group["observations"]),4)
            self.assertIsNone(group["observations"][-1]["observed_metrics"])
            self.assertIsNone(group["metrics"])

    def test_classification_requires_exact_plan_and_rejects_timeout_or_fixture_failure(self):
        cell=campaign.plan("smoke-l7")[-1]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"production-plan.json").write_text(json.dumps([cell]))
            self.write_cell(root,cell,self.error_load(cell),self.valid_resource(cell))
            args=SimpleNamespace(**cell,runner_exit_code=1,measurement_only=True)
            with patch.object(campaign,"ROOT",root):
                self.assertEqual(campaign.classify_planned(args),0)
                args.measurement_only=False
                self.assertEqual(campaign.classify_planned(args),1)
                args.measurement_only=True
                for code in (124,137,143,2):
                    args.runner_exit_code=code
                    self.assertEqual(campaign.classify_planned(args),1)
                args.runner_exit_code=1
                args.rate=1999
                with self.assertRaisesRegex(ValueError,"matching planned cell"):
                    campaign.classify_planned(args)
                args.rate=cell["rate"]
                _,load_path,resource_path=campaign.cell_paths(cell)
                load_path.write_text(json.dumps(self.valid_load(cell)))
                self.assertEqual(campaign.classify_planned(args),1)
                load_path.write_text(json.dumps(self.error_load(cell)))
                resource_path.write_text(json.dumps({**self.valid_resource(cell),"valid":False}))
                self.assertEqual(campaign.classify_planned(args),1)

    def test_ranking_shell_gates_continuation_and_refuses_stale_observations(self):
        script=(ROOT/".github/scripts/mesh_production_campaign.sh").read_text()
        self.assertIn('pipeline_status=("${PIPESTATUS[@]}")',script)
        self.assertIn('[ "${BENCH_PHASE:-smoke-l7}" = ranking ] && [ "${pipeline_status[0]}" -eq 1 ] && [ "${pipeline_status[1]}" -eq 0 ]',script)
        self.assertIn('refusing to reuse an existing planned observation',script)
        self.assertIn('--runner-exit-code 1',script)

if __name__=="__main__": unittest.main()
