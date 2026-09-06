# Scaling publication diagnostics

The 30,000-proxy scale harness enables the existing
`FERRUM_DB_SLOW_QUERY_THRESHOLD_MS=1000` setting. Warnings report SQL resource
loading and full-configuration loading that exceed one second. A separate
warning reports the runtime `update_config` portion of a full reload, its
resource counts, cursor, and commit result. Runtime application timing excludes
the preceding database snapshot read, migration gate and topology-permit wait.

The existing `load_full_config` duration includes snapshot reads and subsequent
validation. Compare it with resource-loader warnings to distinguish database
hydration from validation; do not treat it as SQL server execution time alone.
Runtime application likewise includes validation and staging, not solely an
atomic pointer swap. These warnings identify the dominant area for a later
profile rather than claiming to isolate every internal operation.

Issue #4116's SQLite failure reached 27,000 proxies with successful traffic but
did not publish the final 30,000-proxy cursor within 900 seconds. The harness
retains that convergence bound, all cardinalities, traffic assertions, poll
cadence and the 10,000-row change-log safety valve. Diagnostics change neither
publication decisions nor the order of snapshot/cursor operations. The slow
query setting remains disabled by default outside the harness.

Dispatch Scheduled Scaling Regression against a reviewed diagnostic branch to
collect fresh evidence. Only a successful scheduled/dispatched main run closes
the durable scaling-gate issue. A branch diagnostic run does not close it.
