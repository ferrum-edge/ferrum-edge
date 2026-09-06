# Trusted CI policy validation performance

Issue [#4668](https://github.com/ferrum-edge/ferrum-edge/issues/4668) tracks
reducing CPU work in the trusted Cross verifier without changing its decisions.
Before the parallel-policy split in #4680, CI Plan ran the Cross verifier
before most CI jobs: its validation step took 5m09s
in [PR run 34005446618](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34005446618)
and 6m56s in [merge-group run 33973581181](https://github.com/ferrum-edge/ferrum-edge/actions/runs/33973581181).

A local `cProfile` run of the existing `--self-test` command, which also performs
repository validation, recorded 1,315,116 shell tokenizations and 16,979,146
executable basename lookups. Their cumulative CPU costs were 49s and 53s under
the profiler; use unprofiled wall times for the before/after comparison because
profiling adds substantial overhead.

## Experiment

Cache only shell tokens and executable basenames, indexed by the complete input
string. Results are immutable tuples, strings, or the existing malformed-input
`None`. Each in-process LRU holds at most 2,048 entries and bypasses strings over
4,096 characters. Long inputs still go through the original parser. No results
persist to disk or another CI run.

Policy decisions remain uncached: they depend on the current dispatcher and
opaque-stdin scopes as well as the text. Trusted-base extraction, generation
admissions, and all existing hostile-input fixtures continue to execute. Added
self-tests exercise cache hits, lexical equivalence, malformed input, path
semantics, long-input bypass, and entry limits.

## Validation and measurement

Run from the repository root on the base and candidate with the same Python
version and machine:

```sh
/usr/bin/time -p python3 .github/scripts/verify_cross_build_policy.py --self-test
python3 .github/scripts/verify_required_ci.py
git diff --check
```

Record peak memory as well as elapsed time; on macOS `/usr/bin/time -l` supplies
both. Compare the hosted **Candidate policy self-test** job against its baseline.
The lexical-reuse experiment's original **CI Plan** and **Trusted Cross Build
Policy** jobs ran the reviewed base verifier, so its passing candidate test
alone did not demonstrate lower planning latency. That end-to-end measurement requires reviewed landing
and subsequent PR/merge-group runs. Keep their required checks intact.

Local timing and hosted results are recorded on the experiment PR linked from
[#4668](https://github.com/ferrum-edge/ferrum-edge/issues/4668). A faster parser
alone does not establish a shorter whole-PR critical path; compare artifact
compilation, Unit Tests, and other required workflows separately.


## Parallel trusted validation (#4680)

After lexical reuse landed, [main run 34016773796](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34016773796)
still spent **6m21s** in CI Plan; its policy step consumed **316s**, from
06:33:52 to 06:39:08 UTC. These are the issue's baseline measurements, not
results from the parallel-policy implementation.

`CI Policy` now performs the same complete trusted self-tests and workflow
validation as an independent read-only job. CI Plan retains authenticated,
immutable-base planning, diff hygiene, formatting, and shard coverage. Both
jobs pin their own trust source without consuming candidate planner output.
Every `Tests` aggregate, including light mode, requires successful policy and
its post-validation completion output. Failure, cancellation, skipping, and
missing/invalid output all reject the aggregate and block main image packaging.
No policy decisions are cached, and the separate protected-policy workflow,
required check inventory, default test coverage, thresholds, and exact-SHA
production release proof remain unchanged.

The cheap planner diff rejects modifications to the already-frozen verifier
and its protected workflow. Other invalid changes may compile speculatively
while policy runs. Expect roughly five minutes of overlap on a similarly
provisioned full-mode run; this is a hypothesis, not measured improvement.
A second checkout/fetch and runner allocation add overhead, and runner queueing
can reduce overlap. Light-mode completion still waits for full verification.

### Hosted comparison to collect

Use matched source/toolchain, runner class, dependency cache state and event
kind for base/candidate runs. Record the exact head SHA, run ID and attempt,
cache-hit evidence, and GitHub step/job timestamps. Compare PR, merge-group,
and post-adoption main separately; light-mode/fork smoke cases verify that
trust and failure semantics survive the new scheduling.

| Metric | Definition | Parallel result |
| --- | --- | --- |
| Plan completion | CI Plan `completed_at` minus workflow `run_started_at` | Pending |
| First compiler | Earliest application compilation step start minus workflow start | Pending |
| Policy overlap | Intersection of CI Policy runtime with application compilation | Pending |
| Required Tests completion | Tests `completed_at` minus workflow start | Pending |
| Runner-minutes | Sum of all job runtime seconds / 60, including failed/cancelled speculative work | Pending |

Also compare an invalid frozen-policy edit (early rejection) and an invalid
semantic-policy edit (speculative compilation) to quantify the added cost.
Candidate regressions run remotely through `verify_required_ci.py`: actual
aggregate-shell cases cover full/light success, failure, cancellation, skipped,
missing result, and missing/invalid completion output; extraction cases cover
PR live-base ancestry, merge-group identity, main/manual checkout identity,
transport failure, and failed/interrupted verifier execution.

No local builds, tests, or timing runs were performed for this implementation;
exact pushed-head remote CI is the validation authority. The immutable-base
policy may reject the workflow migration itself because it changes previously
frozen CI executable surfaces. Keep that result visible and report it to the
controller. Do not weaken the guard, change branch protection, or treat a
policy bypass as successful exact-SHA release evidence. End-to-end timing
requires a reviewed adoption and subsequent runs; until then all candidate
performance and CI results above remain pending.
