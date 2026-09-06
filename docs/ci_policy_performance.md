# Trusted CI policy validation performance

Issue [#4668](https://github.com/ferrum-edge/ferrum-edge/issues/4668) tracks
reducing CPU work in the trusted Cross verifier without changing its decisions.
The CI Plan job runs before most CI jobs: its Cross validation step took 5m09s
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
The experiment PR's **CI Plan** and **Trusted Cross Build Policy** jobs still run
the reviewed base verifier, so a passing candidate test does not yet demonstrate
lower planning latency. That end-to-end measurement requires reviewed landing
and subsequent PR/merge-group runs. Keep their required checks intact.

Local timing and hosted results are recorded on the experiment PR linked from
[#4668](https://github.com/ferrum-edge/ferrum-edge/issues/4668). A faster parser
alone does not establish a shorter whole-PR critical path; compare artifact
compilation, Unit Tests, and other required workflows separately.
