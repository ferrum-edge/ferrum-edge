# Default MySQL client-certificate evidence boundary

This supplements the [Compose fixture proposal](compose-fixture-security-proposal.md)
in [draft PR #6002](https://github.com/ferrum-edge/ferrum-edge/pull/6002).
It does not approve landing, consumer adoption, a release, or either draft
advisory. A hosted run has exercised the same-CLI observer, but exact-head
qualification remains incomplete.

## Observed failure and published implementation

The [hosted qualification for `623c1548114813021627912572865143c66524e5`](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37199023536/job/111426692812)
observed `2013/client-server-lost-during-query` on the default rogue-client
attempt. The TLS 1.2 rogue-client control observed `2026/tls-alert-unknown-ca`;
the subsequent trusted default mTLS `SELECT 1` passed. Qualification failed,
cleanup passed, and the later credential scan was not reached. Neither the
disconnect nor that positive establishes the default attempt's certificate
rejection cause.

On 2026-10-04, public Docker registry HTTP reads identified the existing pinned
MySQL index and its Linux amd64 image. Downloaded index/manifest/config bytes were
checked with `shasum -a 256`; these are artifact identities, not executed-image
qualification:

| Published object | SHA-256 identity |
| --- | --- |
| Existing `mysql:8.0` index | `7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` |
| Linux amd64 manifest | `62fb722c78b24245ddff1796a0fcee4a49cc5b87e0aaaf20c92d1da9e0a2497b` |
| Image configuration | `6cd09145362dfe6831b14545de3d5fd6cc75c37cfd6ef8561429c1fc73518b39` |

The manifest names Docker-library source revision
`7cf11d5360282effadb347353d5f82339506b106`; its
[Dockerfile](https://github.com/docker-library/mysql/blob/7cf11d5360282effadb347353d5f82339506b106/8.0/Dockerfile.oracle#L54)
and the image configuration select MySQL `8.0.46-1.el9`.
The official MySQL `mysql-8.0.46` source tag resolves to commit
`0a7df2e4693d8f10901a26034ae6257699356e30`.

In that source, [`vio_ssl_read` and `ssl_should_retry`](https://github.com/mysql/mysql-server/blob/0a7df2e4693d8f10901a26034ae6257699356e30/vio/viossl.cc#L224)
discard the TLS read reason and clear the error queue in a release build.
[`cli_safe_read_with_ok_complete`](https://github.com/mysql/mysql-server/blob/0a7df2e4693d8f10901a26034ae6257699356e30/sql-common/client.cc#L1190)
maps a failed packet read to the generic client-loss error.
The server's [`sslaccept` failure path](https://github.com/mysql/mysql-server/blob/0a7df2e4693d8f10901a26034ae6257699356e30/sql/auth/sql_authentication.cc#L2901)
returns a packet error with a debug-only diagnostic; it does not publish a
connection-bound certificate verification reason through that path.
The documented [host-cache SSL counter](https://dev.mysql.com/doc/refman/8.0/en/performance-schema-host-cache-table.html)
counts failures rather than identifying a certificate and verification reason.
These findings explain the telemetry limitation; they do not prove which cause
produced the recorded CLI error. No manufactured server-log record is used.

## Same-attempt hosted MySQL CLI observation

The earlier CPython separate-connection probe described in prior revisions
has been removed. It did not establish the certificate rejection cause for
the MySQL CLI attempt. Hosted qualification now uses
`scripts/mysql_cli_tls_observer.c`, a bounded private `LD_PRELOAD` observer
injected into the original `/usr/bin/mysql` process by
`scripts/qualify_compose_fixtures.py`. The observer does not implement TLS or
change the command arguments, query, TLS policy, trust, or verification.
The original CLI performs the handshake and `SELECT 1` itself.

Using the public OpenSSL info callback and read-only accessors, the observer
requires one SSL object and one completed default TLS 1.3 handshake on the
owner thread, successful server verification, verify-peer mode, the loopback
MySQL peer on port 3306, and the expected server and selected client
certificate signatures. A successful positive additionally requires the
CLI's `SELECT 1` result. For a rogue-client attempt, it requires an incoming
fatal TLS alert with a certificate-specific alert code admitted by the
qualifier. The CLI's error 2013 by itself remains inadmissible; it only
provides the expected failed-query outcome alongside the independently
observed alert on that same attempt. Hosted evidence includes a trusted
default CLI positive before and after the rogue attempt.

The observer fails closed if required symbols or expected library paths are
unavailable, it cannot prove the executable and private observer inputs,
callbacks are already present or change, the handshake/object lifecycle is
unexpected, or any binding/evidence is incomplete. It resolves symbols from
the CLI's existing OpenSSL mappings and does not load a second OpenSSL
library. Its only output is one bounded numeric record to privately captured
stderr at normal exit; malformed or missing records cannot pass. Certificate
bytes, signatures, secrets, raw TLS data, callback arguments, and unredacted
CLI output are not logged or uploaded. Synthetic parser self-check records
test admission logic only and are not runtime proof.

The hosted run at [job 111436786371](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37202471389/job/111436786371)
reported the default CLI positive before the rogue attempt, an incoming
`unknown_ca` alert paired with error 2013 on the same original CLI attempt,
and the default CLI positive after it. The job then failed during the later
process argv, healthcheck and log scan; unconditional cleanup passed. This is
evidence for that MySQL CLI attempt only. It is not a complete qualification
pass or evidence that the SQL profiles and consumers are ready for adoption.

## CLI admission and completion constraint

Certificate-alert classification now matches complete OpenSSL 3 library and
reason records under `2026/HY000`, with one bounded stderr line, exit status 1
and empty stdout for the certificate negative. The fixed records follow the
client's `ERR_error_string_n` use and OpenSSL's
[formatter](https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/crypto/err/err.c#L559)
and [reason catalog](https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/ssl_err.c#L390).
Unknown formatting, additional lines, altered codes/SQLSTATE, certificate
words in unrelated messages, generic disconnects, exit 127 and timeouts
remain inadmissible. Error 1045 and late-auth-read error 2013 remain bounded
diagnostic categories but are no longer admitted as certificate-specific
default-client proof. MySQL missing-client authentication rejection remains
its separate control.

An unresolved default CLI attempt is marked `UNQUALIFIED`, then its trusted
default `SELECT 1` still runs in `finally`. Existing profiles, positives, all
other negatives, readiness checks and live SQL argv/healthcheck/log credential
scan continue. The final qualification fails unless the same-attempt observer
proves the required default CLI positives and certificate-specific refusal.
Cleanup remains in the original `finally` and unconditional workflow step.
There is no aggregate PASS for an unresolved CLI disconnect.

The optional hosted qualification path adds a C observer executable compiled
with GCC on the runner. Its finite dispatcher adds the
`mysql-observer-compile`, `mysql-observer-server-der` and
`mysql-observer-client-der` operations to compile the observer and derive the
pinned server/client certificate signatures it checks. These additions do not
change the frozen checker or job digest, required trust checks, other CI jobs,
release publication, runtime, Cargo/dependencies or existing image/TLS profile
pins. The observer runs only in hosted qualification; this requires no local
execution and adds no guarded-job edit or trusted-policy admission.

The released CLI still emits error 2013 for the observed rogue-client
attempt because its SQL diagnostic loses the TLS read reason. The observer
provides independent same-attempt evidence through the incoming certificate-
specific alert. Error 2013 alone remains insufficient, and hosted qualification
must still pass the later argv, healthcheck and log scans before an aggregate
PASS is possible.

Root attention: collect exact-head hosted qualification/scanner/cleanup
results and unchanged trusted-policy results, perform a whole-candidate review
and fresh focused security review of the observer callback/provenance,
classifier admission and deferred failure. Keep the PR draft and defer the
released SQL profile/consumer adoption owner decision until complete
qualification. Local verification consists only of static inspection,
published artifact HTTP reads/integrity checks and `git diff --check`;
no local Python, OpenSSL, MySQL, Docker, formatter, script, build or test ran.
