#!/usr/bin/env python3
"""Bounded header slope diagnostic using an existing qualified runtime image."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from mesh_gap_candidate import BASELINE, BUILDER, ROOT, digest, maintenance_origin, require_remote, write
from mesh_gap_build import command
import mesh_gap_baseline_reuse as reuse
from mesh_gap_export import export_public
from mesh_header_ladder_plan import LIMITS, cells, comparisons, header_issues
import mesh_production_campaign as production

OUTPUT=ROOT/'results/header-ladder/campaign'
IMAGES=ROOT/'results/header-ladder/images'
PUBLIC=ROOT/'results/header-ladder/public'
ORIGIN_RUN,ORIGIN_ATTEMPT=39718016243,1
ORIGIN_HEAD='235ff449d94a626af354e297fca86445b7614bb7'
ENVOY='envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4'
REPOSITORY,REPOSITORY_ID='ferrum-edge/ferrum-edge',1175627632


def read(path): return production.read_json(Path(path))

def require(ok,message):
    if not ok: raise ValueError(message)

def inspect(image):
    return json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]


def prepare():
    require_remote()
    require(os.environ.get('BENCH_PHASE')=='header-ladder-diagnostic','explicit header diagnostic phase required')
    OUTPUT.mkdir(parents=True,exist_ok=True)
    require(set(p.name for p in OUTPUT.iterdir()) <= {'preflight'} and not (OUTPUT/'preflight').is_symlink(),
        'unexpected preexisting diagnostic output')
    write(OUTPUT/'plan.json',dict(smoke=cells(True),mesh=cells(),planned_cells=30,planned_smoke_cells=6,
        state='preparing',errors=[],cleanup_complete=False,performance_eligible=False,limits=LIMITS))
    require(os.environ['GITHUB_REPOSITORY']==REPOSITORY and int(os.environ['GITHUB_REPOSITORY_ID'])==REPOSITORY_ID,
            'same repository required')
    token=os.environ['GITHUB_TOKEN'];prefix=f'/repos/{REPOSITORY}/actions'
    request=dict(run_id=ORIGIN_RUN,attempt=ORIGIN_ATTEMPT,artifact_name=f'mesh-gap-image-baseline-{ORIGIN_RUN}-{ORIGIN_ATTEMPT}')
    run=reuse.api_json(f'{prefix}/runs/{ORIGIN_RUN}/attempts/{ORIGIN_ATTEMPT}',token)
    listing=reuse.api_json(f'{prefix}/runs/{ORIGIN_RUN}/attempts/{ORIGIN_ATTEMPT}/jobs?per_page=100',token)
    artifacts=reuse.api_json(f'{prefix}/runs/{ORIGIN_RUN}/artifacts?per_page=100',token)
    require(run['head_sha']==ORIGIN_HEAD and listing['total_count']==len(listing['jobs'])<=100
        and artifacts['total_count']==len(artifacts['artifacts'])<=100,'exact origin or complete listing missing')
    matches=[a for a in artifacts['artifacts'] if a.get('name')==request['artifact_name']]
    require(len(matches)==1,'original baseline image artifact missing or ambiguous')
    artifact=matches[0];job=reuse.validate_origin(request,REPOSITORY,REPOSITORY_ID,run,listing['jobs'],artifact)
    helper=subprocess.check_output(['git','show',ORIGIN_HEAD+':.github/scripts/mesh_gap_build.py'],cwd=ROOT)
    require(hashlib.sha256(helper).hexdigest()==digest(ROOT/'.github/scripts/mesh_gap_build.py'),
            'frozen baseline build executor changed')
    directory=IMAGES/'baseline'
    with tempfile.TemporaryDirectory(prefix='header-baseline-',dir=os.environ['RUNNER_TEMP']) as temporary:
        archive=Path(temporary)/'image.zip'
        downloaded=reuse.download(f'{prefix}/artifacts/{artifact["id"]}/zip',token,archive,artifact)
        reuse.extract(archive,directory)
    receipt=read(directory/'receipt.json')
    recipe=dict(baseline_sha=BASELINE,profile='release',features='cloud-secrets',allocation_instrumentation=False,
        builder_image=BUILDER,maintenance_origin=maintenance_origin(),
        dockerfile_sha256=hashlib.sha256(subprocess.check_output(['git','show',BASELINE+':Dockerfile'],cwd=ROOT)).hexdigest())
    reuse.validate_original(receipt,recipe,ORIGIN_HEAD,reuse.fixed_input_hashes())
    require(receipt['image_archive_sha256']==digest(directory/'image.tar')
        and receipt['dockerfile_sha256']==digest(directory/'Dockerfile.source')
        and receipt['compiler_native_packages_sha256']==digest(directory/'compiler-native-packages.log'),
        'original baseline archive or build metadata changed')
    write(IMAGES/'origin.json',dict(request=request,run=run,job=job,artifact=artifact,download=downloaded,
        scope='Exact original baseline build reused; no candidate runtime or candidate-check receipt is represented. Origin performance outcome is not selected.'))
    command(['docker','load','--input',str(directory/'image.tar')],OUTPUT,'load-baseline',timeout=180)
    baseline=inspect(receipt['image_id']);labels=baseline['Config']['Labels']
    require(baseline['Id']==receipt['image_id'] and baseline['Config']['User']=='65532:65532'
        and labels.get('org.opencontainers.image.revision')==BASELINE
        and labels.get('io.ferrum.benchmark.profile')=='release'
        and labels.get('io.ferrum.benchmark.features')=='cloud-secrets','loaded baseline identity differs')
    command(['docker','pull',ENVOY],OUTPUT,'pull-envoy',timeout=240)
    envoy=inspect(ENVOY)
    require(ENVOY in envoy.get('RepoDigests',[]) and envoy['Os']=='linux' and envoy['Architecture']=='amd64',
            'Envoy immutable digest/platform mismatch')
    tag='header-ladder-tools:'+uuid.uuid4().hex
    command(['docker','build','--progress','plain','-f','tests/performance/mesh_runtime/Dockerfile.production-tools',
        '-t',tag,'tests/performance/mesh_runtime'],OUTPUT,'build-tools',timeout=1200)
    tools=inspect(tag)
    source=dict(runtime_sha=BASELINE,harness_sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        runtime_recipe=recipe,image_ids=dict(ferrum=baseline['Id'],envoy=envoy['Id'],tools=tools['Id']),
        envoy_reference=ENVOY,envoy_source_sha='b579d07d3ad7ee11d32b105e91a5a39ad24718d7',
        images=dict(ferrum=baseline,envoy=envoy,tools=tools),baseline_build_receipt=receipt,
        tool_inputs={str(p.relative_to(ROOT)):digest(p) for p in sorted((ROOT/'tests/performance/mesh_runtime').rglob('*'))
            if p.is_file() and not p.is_symlink() and 'target' not in p.parts and p.suffix in ('.rs','.toml','.lock','.py','.sh')},
        config_inputs={str(p.relative_to(ROOT)):digest(p) for p in sorted((ROOT/'tests/performance/mesh_runtime/configs').rglob('*')) if p.is_file()},
        workers=4,proxy_cpu_quota='default unchanged; actual values recorded',rate=0,payload=1024,
        performance_eligible=False,limits=LIMITS)
    write(OUTPUT/'provenance.json',source)


def observation(cell,directory,source,status):
    row=dict(cell=cell,measurement_valid=False,capacity_qualified=False,metrics={},issues=[],runner_exit_code=status)
    try:
        load_path=directory/f"{cell['arm']}_http1_1024.json"
        resource_path=directory/f"{cell['arm']}_http1_1024.resources.json"
        load,resource=read(load_path),read(resource_path);row.update(load=load,resources=resource)
        require(isinstance(load,dict) and isinstance(resource,dict),'load and resource reports must be objects')
        issues=production.validate_observation(cell,load,resource)+header_issues(cell,load)
        ordinary=type(load.get('total_errors')) is int and (load['total_errors']>0 or load.get('total_requests')==0)
        if not (status==0 or status==1 and ordinary):issues.append('runner failure is not a conserved ordinary outcome')
        containers=resource.get('containers',[]);observed=resource.get('production',{}).get('proxy_containers',[])
        expected=0 if cell['arm']=='direct' else 2
        require(isinstance(containers,list) and isinstance(observed,list)
            and all(isinstance(c,dict) for c in containers+observed),'proxy identities must be object lists')
        if (len(containers)!=expected or len(observed)!=expected
            or any(c.get('image_id')!=source['image_ids'][cell['arm']] for c in containers+observed)
            or len({c.get('pid') for c in containers})!=expected
            or any(c.get('network_mode')!='host' or c.get('cpu_limit_nanos')!=0 or c.get('cpu_quota') not in (0,-1) for c in observed)):
            issues.append('actual proxy image/identity/network/default quota differs')
        for original,live in zip(containers,observed):
            if any(original.get(k)!=live.get(k) for k in ('name','pid','image_id')):
                issues.append('observed proxy identity differs from measured process')
        if cell['arm']=='ferrum' and any(c.get('worker_environment')!=['FERRUM_WORKER_THREADS=4'] for c in observed):
            issues.append('Ferrum worker environment differs')
        if expected and (not resource.get('rss_samples') or not production.finite_number(resource.get('proxy_rss_bytes_mean'),positive=True)):
            issues.append('proxy RSS evidence missing')
        if not production.finite_number(resource.get('host_cpu_steal_percent')) or resource['host_cpu_steal_percent']>5:
            issues.append('host steal gate failed')
        auxiliary=resource.get('production',{}).get('auxiliary_containers',[])
        require(isinstance(auxiliary,list) and all(isinstance(c,dict) for c in auxiliary),
            'auxiliary identities must be an object list')
        if len(auxiliary)!=2 or len(resource.get('auxiliary_cpu',[]))!=2 or any(c.get('image_id')!=source['image_ids']['tools'] for c in auxiliary):
            issues.append('loadgen/backend image/resource identity missing')
        for population,identities in (('processes',containers),('auxiliary',auxiliary)):
            before=resource.get('begin',{}).get(population,[])
            after=resource.get('end',{}).get(population,[])
            if (len(before)!=len(identities) or len(after)!=len(identities)
                or len({i.get('pid') for i in identities})!=len(identities)
                or any(type(identity.get('pid')) is not int or identity['pid']<=1
                    or left.get('pid')!=identity['pid'] or right.get('pid')!=identity['pid']
                    or type(left.get('starttime')) is not int or left['starttime']<=0
                    or left['starttime']!=right.get('starttime')
                    for identity,left,right in zip(identities,before,after))):
                issues.append('measurement PID/generation identity differs: '+population)
        if expected:
            auth=directory/'logs/auth_probes.log';text=auth.read_text()
            for proof in ('plaintext refused','valid client certificate handshake','no-client-cert refused','rogue-CA client certificate refused'):
                if '[auth-probe] ok: '+proof not in text:issues.append('missing authentication proof: '+proof)
        cap=production.validate(cell,load,resource)
        metrics=production.observed_metrics(cell,load,resource) if not issues else {}
        if metrics:
            metrics.update(proxy_rss_bytes_mean=resource.get('proxy_rss_bytes_mean'),proxy_rss_bytes_peak=resource.get('proxy_rss_bytes_peak'))
            if cell['arm']=='direct':metrics['cpu_us_per_completion']=None
        row.update(measurement_valid=not issues,capacity_qualified=not issues and not cap,issues=issues,
            capacity_issues=cap,metrics=metrics,evidence_sha256={load_path.name:digest(load_path),resource_path.name:digest(resource_path)})
    except (OSError,ValueError,TypeError,KeyError,IndexError,ArithmeticError) as error:row['issues'].append(str(error))
    write(directory/'observation.json',row);return row


def run_cell(cell,source):
    directory=OUTPUT/cell['directory'];directory.mkdir(parents=True,exist_ok=False)
    write(directory/'identity.json',dict(cell=cell,image_ids=source['image_ids'],harness_sha=source['harness_sha']))
    env={k:v for k,v in os.environ.items() if not k.startswith(('FERRUM_','BENCH_','MESH_BENCH_')) and k!='GITHUB_TOKEN'}
    env.update(BENCH_PHASE='header-ladder-diagnostic',FERRUM_IMAGE=source['image_ids']['ferrum'],ENVOY_IMAGE=ENVOY,
        TOOLS_IMAGE=source['image_ids']['tools'],BENCH_CARGO_PROFILE='release',BENCH_FERRUM_FEATURES='cloud-secrets',
        BENCH_WORKERS='4',BENCH_RATE='0',BENCH_PRODUCTION_OBSERVE='true',
        BENCH_DIAGNOSTIC_HEADER_COUNT=str(cell['header_count']),BENCH_DIAGNOSTIC_HEADER_VALUE_BYTES=str(cell['header_value_bytes']))
    argv=['timeout','--signal=TERM','--kill-after=10s','450s','bash','tests/performance/mesh_runtime/run_mesh_runtime_bench.sh',
        cell['arm'],'--payload-sizes','1024','--duration',str(cell['duration']),'--concurrency',str(cell['concurrency']),
        '--warmup',str(cell['warmup']),'--output-dir',str(directory),'--skip-build']
    print('header diagnostic '+cell['directory'],flush=True)
    child=None
    with (directory/'run.log').open('w') as stream:
        try:
            child=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
            status=child.wait(timeout=465)
        finally:
            if child is not None:
                # Only this freshly owned session: reap descendants before the
                # next step removes this run's labeled fixture containers.
                try:os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:pass
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=5)
    return observation(cell,directory,source,status)


def measure():
    require_remote();plan=read(OUTPUT/'plan.json');source=read(OUTPUT/'provenance.json')
    plan.update(state='measuring',errors=[]);write(OUTPUT/'plan.json',plan)
    def interrupted(signum,frame):raise InterruptedError('diagnostic interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    started=time.monotonic()
    try:
        for smoke in (True,False):
            for cell in cells(smoke):
                if time.monotonic()-started>2100:raise TimeoutError('fixed diagnostic wall budget exceeded')
                row=run_cell(cell,source)
                if not row['measurement_valid']:raise ValueError('structural evidence failure at '+cell['directory'])
                if smoke and not row['capacity_qualified']:raise ValueError('smoke qualification failed at '+cell['directory'])
        plan['state']='completed'
    except Exception as error:
        plan.update(state='failed');plan['errors'].append(type(error).__name__+': '+str(error))
        raise
    finally:
        plan['elapsed_seconds']=time.monotonic()-started;write(OUTPUT/'plan.json',plan)


def summarize():
    smoke=[];rows=[]
    for is_smoke,target in ((True,smoke),(False,rows)):
        for cell in cells(is_smoke):
            path=OUTPUT/cell['directory']/'observation.json'
            try:
                row=read(path);require(row['cell']==cell,'planned cell metadata changed')
            except (OSError,ValueError,TypeError,KeyError):
                row=dict(cell=cell,measurement_valid=False,capacity_qualified=False,metrics={},issues=['planned cell missing or malformed'])
            target.append(row)
    report=dict(planned_cells=30,planned_smoke_cells=6,mesh=rows,gateway=[],smoke=smoke,
        measured_valid_cells=sum(r['measurement_valid'] for r in rows),
        all_capacity_qualified=all(r['capacity_qualified'] for r in rows),
        smoke_qualified=all(r['measurement_valid'] and r['capacity_qualified'] for r in smoke),
        complete_valid_observations=all(r['measurement_valid'] for r in rows),
        comparisons=comparisons(rows),performance_eligible=False,limits=LIMITS)
    write(OUTPUT/'report.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('mesh','gateway','smoke','comparisons')},indent=2))
    return report


def cleanup():
    require_remote()
    owner=os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    argv=['docker','ps','-aq','--filter','label=ferrum.meshbench.owner='+owner]
    ids=subprocess.check_output(argv,text=True,timeout=15).split()
    if ids:
        subprocess.run(['docker','rm','-f',*ids],check=True,timeout=30)
    require(not subprocess.check_output(argv,text=True,timeout=15).split(),'owned fixture cleanup incomplete')
    path=OUTPUT/'plan.json'
    if path.exists():
        plan=read(path);plan['cleanup_complete']=True;write(path,plan)


def accept():
    report=summarize();plan=read(OUTPUT/'plan.json')
    manifest=read(PUBLIC/'export.json')
    require(manifest.get('complete') is True and manifest.get('schema')==2,'complete public export missing')
    require(plan['state']=='completed' and plan.get('errors')==[] and plan.get('cleanup_complete') is True and report['smoke_qualified']
        and report['complete_valid_observations'],'diagnostic incomplete/unqualified; all observations retained')
    # This gates evidence only. Product errors in complete cells remain failed SLOs.


if __name__=='__main__':
    try:
        require_remote()
        action=sys.argv[1]
        if action=='prepare':prepare()
        elif action=='measure':measure()
        elif action=='summarize':summarize()
        elif action=='cleanup':cleanup()
        elif action=='export':export_public(OUTPUT,IMAGES,PUBLIC)
        elif action=='accept':accept()
        else:raise ValueError('unknown header diagnostic action')
    except Exception as error:
        # HTTP errors can contain signed artifact URLs. Never print those details.
        reason=str(error) if isinstance(error,ValueError) else type(error).__name__
        print('header diagnostic action failed: '+reason,file=sys.stderr)
        raise SystemExit(1)
