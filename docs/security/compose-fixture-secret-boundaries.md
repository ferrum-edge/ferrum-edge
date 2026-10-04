# Default MySQL client-certificate evidence boundary

This supplements the [Compose fixture proposal](compose-fixture-security-proposal.md)
in [draft PR #6002](https://github.com/ferrum-edge/ferrum-edge/pull/6002).
It does not approve landing, consumer adoption, a release, or either draft
advisory. The new probe has not been executed during this preparation.

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

## Narrow hosted capability probe

`scripts/qualify_compose_fixtures.py` now makes a separate connection to the
existing loopback MySQL fixture using CPython's standard `ssl` module. This
is a distinct attempt, not instrumentation of the MySQL CLI connection. It
uses the same generated rogue certificate/key and fixture trust anchor,
verifies `localhost`, and requires the expected server certificate bytes.
It leaves the context's default TLS 1.2-to-maximum range in place and requires
actual TLS 1.3 negotiation. A trusted default MySQL CLI query independently
checks `Ssl_version=TLSv1.3` before the probe. No TLS version is pinned or
disabled on the server or ordinary clients.

The probe sends only a MySQL SSLRequest, following the official
[OpenSSL STARTTLS implementation](https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/apps/s_client.c#L2418).
It sends no SQL authentication response, password or query, and reads no SQL
credential option file. It uses a directly constructed `SSLContext` with the
fixture CA, rather than loading system trust or an environment-selected TLS
key log.

CPython's [_msg_callback implementation](https://github.com/python/cpython/blob/f6650f9ad73359051f3e558c2431a109bc016664/Lib/ssl.py#L581)
exposes the connection's decrypted TLS handshake/alert messages through
[OpenSSL's message callback](https://docs.openssl.org/3.0/man3/SSL_CTX_set_msg_callback/).
The observer requires the same socket object throughout. Following the
[TLS 1.3 certificate and authentication formats](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2),
it requires the initial client/server hello sequence, server certificate
request, exact server leaf DER, server Finished, exact rogue leaf DER
(including its certificate signature), a populated RSA-PSS CertificateVerify
from the loaded matching RSA-2048 key, and client Finished. OpenSSL verifies
the server's chain, hostname and handshake signature before the probe reads
the delayed rejection.

A probe pass additionally requires the received fatal alert bytes `02 30`
(unknown CA), TLS version 1.3, and the exact OpenSSL exception tuple
`SSL_ERROR_SSL / SSL / TLSV1_ALERT_UNKNOWN_CA`. The parsed MySQL connection ID
must be nonzero. The container must use the existing image pin and unchanged
container ID, its read-only `/client` mount must name the generated directory,
and the expected certificate/CA/key files must remain unchanged across the
probe. The bounded output category `tls13-bound-unknown-ca`, protocol number
13, parsed numeric MySQL connection ID and alert number 48 describe only
this separate attempt. They do not assign that reason to error 2013 from the
CLI. Unproven attempts emit a fixed failure category without those numbers.

The network attempt has one five-second deadline, with individual socket
operations capped at three seconds. Greeting payloads are capped at 4 KiB;
TLS handshake messages at 16 KiB; leaves at 8 KiB and four entries; total
callback data at 64 KiB and 128 messages. Unexpected ordering, duplicate
events, wrong socket/certificate/protocol, local material failures, generic
EOF, timeout, absent server, application/authentication data and unrelated
TLS errors cannot pass. Unsupported private callback behavior fails closed.
Certificate bytes, signatures, subjects, keys, connection greetings and raw
exceptions are never logged, uploaded or written as probe artifacts.

Hosted parser self-checks exercise malformed/truncated/oversized certificate
vectors, wrong alert direction/version/type/length, and unbound sockets or
alerts. Their synthetic parser bytes are explicitly not certificate fixtures
or runtime evidence. The live server, generated certificate and real alert
are required independently.

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
default `SELECT 1` still runs in `finally`. The separate probe also has a
subsequent trusted default `SELECT 1`. Existing profiles, positives, all
other negatives, readiness checks and live SQL argv/healthcheck/log credential
scan continue. After those scans the final qualification still fails unless
both the default CLI certificate diagnostic and separate probe are proven.
Cleanup remains in the original `finally` and unconditional workflow step.
There is no aggregate PASS for an unresolved CLI disconnect.

No new subprocess executable, dispatcher operation, helper, workflow or
trusted-policy admission is introduced. The literal finite command graph,
frozen checker and job digest, required trust checks, other CI jobs, release
publication, runtime, Cargo/dependencies and existing image/TLS profile pins
are unchanged.

The precise remaining constraint is the released CLI's loss of the SSL read
reason, coupled with the absence of a connection-specific verification reason
in the inspected server failure path. If the same CLI continues to emit only
2013, this change deliberately cannot produce a complete qualification pass.
A successful separate probe supplies reviewable certificate-cause evidence
for its own default TLS 1.3 attempt. Root must decide whether that distinct
proof scope is sufficient or assign independently reviewed instrumentation
of the actual CLI/server connection. This round does not weaken that boundary
or replace the CLI control with the new probe.

Root attention: collect exact-head hosted probe/scanner/cleanup results and
unchanged trusted-policy results, perform a whole-candidate review and fresh
focused security review of the new protocol parser, callback/provenance,
classifier admission and deferred failure. Keep the PR draft and defer the
released SQL profile/consumer adoption owner decision until complete
qualification. Local verification consists only of static inspection,
published artifact HTTP reads/integrity checks and `git diff --check`;
no local Python, OpenSSL, MySQL, Docker, formatter, script, build or test ran.
