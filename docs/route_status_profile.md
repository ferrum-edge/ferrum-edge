# Isolated route-status measurements

The on-demand Resources Scale Benchmark workflow accepts `benchmark=route-status`
and a `baseline_ref`. Select the candidate branch or commit as the workflow ref;
use an immutable baseline commit for reproducible comparisons. The default
`benchmark=resources` retains the existing proxy traffic benchmark.

The route-status jobs build the same external unit target with CI's three Cargo
jobs and line-table debug settings, then run only the existing
`large_route_snapshots_scale_indexing_while_budget_bounds_planning` test three
times in separate processes. Each run retains the 1,000/10,000-route fixtures,
real conflict inputs, both no-reuse planning calls, and every original assertion.
The ordinary CI Unit Tests job still runs the complete external target.

The artifact records exact revisions, all three outputs, test-count proof,
wall time excluding compilation, and GNU time maximum child RSS. This isolates
the scale case from other concurrent unit tests; Cargo's small command overhead
is included. Baseline and candidate use separate standard hosted runners, so
repetitions describe observed behavior rather than proving statistical
significance on a shared machine. Report full unit-suite/readiness measurements
separately, and do not infer peak-memory reduction from fewer allocations alone.

Artifacts expire after fourteen days. A missing/filtered-away/ignored scale test
fails the measurement job. This workflow does not publish a release or change
production build profiles.
