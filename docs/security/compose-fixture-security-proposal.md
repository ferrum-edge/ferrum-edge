# Compose fixture security candidate — owner decision required

This is an **unmerged approval candidate**, prepared on 2026-10-04 from
`b1d462c89`. It changes sample/fixture startup behavior shipped with Edge
0.9.10. Pushing this branch authorizes neither default-main activation nor a
release, advisory publication, or advisory closure. Root must review the
candidate, obtain hosted evidence for the exact head, resolve the consumer
dependency below, and obtain product/security owner approval before landing.

Associated imported drafts (also read from the GitHub API during preparation):

- [GHSA-wq9h-xxp4-7r2m](https://github.com/ferrum-edge/ferrum-edge/security/advisories/GHSA-wq9h-xxp4-7r2m): Mongo sample known-password fallback.
- [GHSA-x87v-w7p2-77f4](https://github.com/ferrum-edge/ferrum-edge/security/advisories/GHSA-x87v-w7p2-77f4): TLS fixture network exposure and password argv.

Both were observed in `draft` state. No advisory metadata has been changed.
The imported file under `.orchestration/` is task input and is not committed.

## Source findings and precise exposure

The original `docker-compose.yml` used the same committed fallback for the
Mongo root user `ferrum` and the gateway URI. The Mongo database service was
unprofiled, so ordinary default startup also created it. **It had no published
Mongo port.** The realistic database exposure is to peers on
`ferrum-network`, a host/container route, or an operator-added published port;
the advisory's host-network scenario requires that additional reachability.
The published gateway proxy ports are not a Mongo port. The sample grants the
gateway Mongo root credentials, amplifying the impact if that credential is
exposed. This candidate does not redesign database roles or Mongo TLS.

Both SQL fixture paths published ports without a host IP, selecting Docker's
wildcard publication by default. Compose committed SQL passwords and a MySQL
root password in its healthcheck argv. The shell helper also passed SQL
passwords in Docker and MySQL argv, printed full connection URIs, and made the
MySQL server key world-readable. Its MySQL readiness check used `mysqladmin
ping`, which does not prove successful authentication or a SQL query.

## Candidate contract and compatibility costs

| Surface | Candidate behavior | Compatibility cost |
| --- | --- | --- |
| Default Compose | `ferrum-sqlite` and `postgres` stay active; Mongo database moves into `mongodb` profile | Default startup no longer creates an unused Mongo container |
| Non-Mongo interpolation | No `MONGO_PASSWORD` required | Existing admin JWT, PostgreSQL password, and CP/DP JWT interpolation guards still apply to all services |
| Mongo startup | Require at least 32 hexadecimal characters; reject unset, empty, short, or other characters before initialization; run `mongod --auth` | Arbitrary existing passwords must be rotated to the supported alphabet; failure occurs at startup, not `compose config` |
| Mongo URI | Same validated hexadecimal value used for the database and gateway | Hexadecimal needs no URI escaping; arbitrary raw passwords are deliberately rejected rather than incorrectly embedded |
| SQL publication | `127.0.0.1:15432:5432` and `127.0.0.1:13306:3306` in Compose and therefore the helper | LAN clients can no longer use the fixture ports; remote Docker daemons bind their own host loopback |
| SQL secrets | Fresh independent 256-bit hexadecimal PostgreSQL, MySQL, and MySQL root passwords in private files; image `_FILE` inputs | Hard-coded `test-password` consumers must change; no known-password compatibility mode |
| SQL readiness | Authenticated `SELECT 1`, CA trust and hostname verification; no password argv/config content | Requires the complete generated file layout, Docker Compose v2 with `--wait`, and readable private bind mounts |
| SQL TLS | PostgreSQL rejects non-TLS TCP; MySQL retains `require_secure_transport=ON`; trusted server certificates and client identity available | Seven-day disposable certificates require cleanup and regeneration, not long-lived fixture reuse |
| Setup/cleanup | Refuse pre-existing directories/containers; copy server keys as account-owned `0600`; marker/path-label checked cleanup includes private material | Old directories and containers must be deliberately retired; direct Compose requires explicit absolute `CERTS_DIR` |

Both Mongo services must share the profile: merely profiling the gateway
would leave the unprofiled database starting on default commands. Compose
interpolates the whole file before filtering profiles. `${MONGO_PASSWORD:?}`
in this monolithic file would therefore add a new required secret to every
PostgreSQL/SQLite/CP/DP command. The selected startup guard uses Compose's `$$`
escape for container-side evaluation and `${MONGO_PASSWORD:-}` solely to pass
an empty value to that guard; it supplies no fallback credential. It checks
before the official image entrypoint even for a previously initialized volume.
An invalid secret prevents the database from serving and its health-dependent
gateway from starting. Operators who explicitly bypass the entrypoint or
dependencies depart from the supplied contract.

The selected alphabet is a deliberate small-scope tradeoff. A 32-byte random
hex value is recommended, although the guard admits 32 or more hex characters
and cannot measure entropy. It does not reject every guessable operator value.
Preserving arbitrary passwords would require a safe, matching encoded URI
input or a credential-file URL builder, plus validation that raw and encoded
inputs agree. Percent encoding only the password component is necessary for
reserved characters; percent-encoding an entire URI is incorrect. Neither
variant is silently implemented here.

Alternatives for the owner: (1) a global `:?` guard with explicitly required
Mongo input for every command, at the cost of unrelated-profile ergonomics;
(2) split Mongo into a separately included Compose file with `:?` guards, at
the cost of changing invocation/file inclusion; or (3) the selected startup
guard, keeping current profile invocation but restricting the password
alphabet and deferring validation to startup. Inactive profiles do not avoid
interpolation in any of these options. No alternative may reinstate a working
known-password fallback or accept empty credentials as a no-auth deployment.

For default and PostgreSQL commands, provide the existing
`FERRUM_ADMIN_JWT_SECRET`, `POSTGRES_PASSWORD`, and
`FERRUM_CP_DP_GRPC_JWT_SECRET` inputs; use generated hex values so the existing
PostgreSQL sample URI needs no escaping. `MONGO_PASSWORD` can be absent.
For Mongo, additionally export a private fresh hex secret and select only
`mongodb ferrum-mongodb` with `--profile mongodb`. Do not print full Compose
configuration or environment: the Mongo and ordinary PostgreSQL sample
credentials remain inspectable in their environment/URL values.

## Private material, trust, and lifecycle

The helper creates a new owned directory with `umask 077`: directories `0700`,
all files `0600`. Server certificate subdirectories contain no database
passwords or client private keys. Root container wrappers copy server material
into account-owned private directories and resolve the `postgres`/`mysql`
account names instead of assuming a numeric UID. No private key is made
world-readable. Server certificates include `localhost`, the Compose service name,
and `127.0.0.1` SANs; the client certificate has CN `ferrum` and clientAuth EKU.
The generated CA is marked as a CA, with appropriate signing key usage.

Compose file-backed secrets are read-only host bind mounts, **not an encrypted
secret store**; Compose UID/mode declarations would not change source-file
permissions, so none are relied upon. Official entrypoints read password files
and may export resolved passwords to child environments. PostgreSQL probes
use `PGPASSWORD`; MySQL probes/admin operations use private option files.
The MySQL root account is restricted to localhost and has a distinct secret.
SQL probes check actual queries and preserve CA/hostname verification. The
fixture supplies client certificates without requiring mTLS by default;
qualification temporarily requires them to prove both mTLS positives and
missing/untrusted-client negatives. Ordinary verified TLS still works.

The helper writes credential-bearing `connections.env` privately instead of
printing URIs. Its generated alphabet avoids URI, shell, and option-file
escaping ambiguities. A direct-Compose operator accepting arbitrary secrets
must correctly quote option files and percent-encode URI password components;
the helper only generates hex. Generated material is retained after successful
startup until explicit cleanup with the same directory. Failures attempt
cleanup, and database logs are withheld because upstream initialization might
emit sensitive data. Cleanup removes the disposable volumes/network and owned
directory; abrupt termination, failed Docker operations, snapshots, and
filesystem recovery can leave material. Unlinking is not secure erasure.

## Existing volumes and migration requirements

**Mongo:** initialization variables never rotate an already-created user's
password. A volume created with the old fallback retains that password even
when a valid fresh input is configured; the gateway may fail authentication
while Mongo still accepts the old credential. Before reuse, keep Mongo isolated,
back up valuable data, authenticate through a protected administrative session
using the current credential, rotate the `ferrum` user in `admin` to the new
supported secret, and update the gateway input together. Do not put current or
new secrets in argv, echoed commands, or logged URIs. Prove the new credential
works and the old one is refused. For disposable data, deliberately remove
only the identified Mongo volume and initialize a new one. A blanket Compose
`down --volumes` would also destroy PostgreSQL/SQLite data and is not a migration
instruction. This branch does not mutate or delete any operator volume.

**SQL TLS fixtures:** these are disposable and not a migration path for real
data. Stop/remove old named test containers and their anonymous volumes,
deliberately delete old private material, then generate a fresh fixture.
The new helper refuses old directories lacking its ownership marker and never
rotates an existing database in place. Direct Compose recreation retaining an
old anonymous/external volume does not change its users' passwords; retire or
explicitly rotate it before use. Never point this disposable configuration at
production volumes.

## Hosted qualification and separate guarded dependency

The added optional `.github/workflows/compose-fixture-qualification.yml`
executes `scripts/qualify_compose_fixtures.py` on an Ubuntu hosted runner,
with `contents: read`, no retained checkout credentials, no secret inputs,
no release operations, and a 15-minute job limit. The qualification command
has a 10-minute deadline, each subprocess has a deadline, profile startup uses
30/120-second waits, and cleanup runs in `finally` plus an unconditional workflow
step. It captures private subprocess output and emits only aggregate pass/fail
messages. No secret/config/log artifacts are uploaded. Images are published,
digest-pinned references; the profile override uses the released 0.9.10 binary
and `--no-build`, not a newly built gateway.

Qualification covers actual default/SQLite and PostgreSQL startup without a
Mongo input; Mongo missing, empty, short and non-hex refusal, including missing
and empty inputs with an initialized volume; valid Mongo
gateway/authenticated-shell connections and old-password refusal; actual SQL
Docker bind metadata and host loopback/non-loopback reachability; private-file
permissions; refusal to replace a live fixture; SQL `SELECT 1`, create/drop
and table probes; correct trust/hostname positives and wrong-CA/hostname,
plaintext, missing-client, and untrusted-client negative controls; mTLS
positives; healthcheck, live SQL/Docker argv and container-log secret scans;
and private-directory cleanup. An expected TLS/auth diagnostic is required for
negative controls: a timeout alone is not a passing rejection.

The canonical frozen checker at
`.github/scripts/verify_cross_build_policy.py` lists `.github/scripts/`,
`comparison/`, `scripts/`, `tests/k8s/`, and `tests/performance/` in
`APPROVED_AUTOMATION_ROOTS`; `tests/scripts/` is excluded. Both workflow root
commands now name the `scripts/` implementations directly. The qualifier's
two subprocess call sites use a literal `bash scripts/compose_fixture_command.sh`
argument list. That dispatcher enumerates the Compose, Docker SQL, Mongo, and
OpenSSL and bounded observation-fixture GCC operations with literal executable names and literal setup/cleanup
script edges. Operation selectors, paths, SQL queries, and connection settings
are quoted environment data; no input is evaluated as shell source or selected
as an executable. Unknown selectors fail. This makes the implementation and
its transitive command graph available to the existing scan without changing
the checker, digests, guarded CI bindings, or either required trust check.

The released `tests/scripts/setup_db_tls.sh` path remains only a manual
forwarder to the full `scripts/setup_db_tls.sh` implementation: the five SQL
cells still name it in their setup diagnostics. Its retention preserves that
entrypoint, not their historical password behavior. No workflow executes the
forwarder. The unreleased `tests/scripts/qualify_compose_fixtures.py` path is
removed.

Current candidate source inventory (replace the earlier seven-file inventory
when recording exact-head qualification/review evidence):

| File | Role |
| --- | --- |
| `docker-compose.yml` | Default/profile Mongo startup boundary |
| `docker-compose.tls-test.yml` | Loopback SQL, private mounts, verified readiness |
| `scripts/setup_db_tls.sh` | Full SQL generation, startup, ownership and cleanup implementation |
| `scripts/qualify_compose_fixtures.py` | Hosted assertions, private capture, bounded diagnostic admission |
| `scripts/test_compose_fixture_qualification.py` | Hosted synthetic canary, inventory and command-failure controls |
| `scripts/compose_fixture_command.sh` | Explicit command graph for all qualifier subprocesses |
| `scripts/mysql_cli_tls_observer.c` | Hosted-only public OpenSSL observation of the unchanged MySQL CLI argv |
| `tests/scripts/setup_db_tls.sh` | Released manual entrypoint forwarder |
| `.github/workflows/compose-fixture-qualification.yml` | Hosted qualification and unconditional cleanup roots |
| `docs/database_tls.md` | Setup/cleanup usage and consumer dependency |
| `docs/security/compose-fixture-security-proposal.md` | Scope, source inventory, evidence and owner decision |

Published index identities read from Docker Hub on 2026-10-04 (availability,
not runtime qualification):

| Image tag | Published index digest |
| --- | --- |
| `postgres:16-alpine` | `sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea` |
| `mysql:8.0` | `sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` |
| `mongo:7-jammy` | `sha256:f71f6d0913c945096cd058557cbadf4ad435007f378d84b3c4c636c928735e72` |
| `ferrumedge/ferrum-edge:0.9.10` | `sha256:430d6a7d41361de5ad12562786481f97f1e97fef72a0b5f1a0699eced7cdd4cc` |

Concrete separate dependency: five SQL TLS cells in
`tests/functional/functional_db_tls_test.rs` embed `test-password` in their
base URL. This is the complete five-call inventory at candidate base
`0c17ded8b`; the line numbers refer to that unchanged file:

| Consumer | Base URL call line | Private generated input | Retained gateway TLS policy |
| --- | --- | --- | --- |
| `test_postgresql_tls_verify_full` | 507 | `PG_TLS_URL` | `verify-full` and generated CA |
| `test_postgresql_tls_require` | 557 | `PG_TLS_URL` | `require` |
| `test_mysql_tls_verify_identity` | 616 | `MYSQL_TLS_URL` | `verify-full` and generated CA |
| `test_mysql_tls_required` | 665 | `MYSQL_TLS_URL` | `require` |
| `test_health_endpoint_shows_db_status` | 763 | `PG_TLS_URL` | `require`; retain current minimal health assertion |

Proposed adoption diff for the test owner (not applied in this proposal): add
one test-only `sql_tls_base_url(key)` reader for the helper's private
`connections.env`, selected by a proposed
`FERRUM_TEST_SQL_TLS_CONNECTIONS_FILE` path. Parse the two `KEY=value` records
as data, without sourcing a shell file or echoing values. Require a readable
private file, both nonempty URLs, the expected scheme/user/loopback host/fixture
port, and the generated hexadecimal password contract. Missing/malformed input
must fail with a fixed credential-free diagnostic when a SQL fixture is
present or `FERRUM_DB_TLS_REQUIRED=1`; do not fall back to a historical password
or skip a present fixture. If a future extension accepts arbitrary passwords,
percent-encode only the password component when constructing a URL, and retain
decoding for the container client. Document any new `FERRUM_*` test input in
`docs/configuration.md` and `ferrum.conf` in that separately approved change.

Replace each of the five literal-base-URL calls using its table key:

```rust
let base_url = sql_tls_base_url("PG_TLS_URL"); // MYSQL_TLS_URL for the two MySQL cells
let (db_url, _isolated_db) = provision_isolated_sql_database(&base_url);
```

Keep the per-cell database isolation and gateway-before-database drop order.
The shared implementation in `tests/common/backend_availability.rs` also
needs an adoption review: PostgreSQL create/drop currently uses the local
trusted socket; MySQL create/drop forwards the URL's decoded password through
`MYSQL_PWD`. For the TLS MySQL container only, propose using the mounted
`/run/secrets/mysql-client.cnf` as the first client option for create/drop,
retaining authenticated CA/hostname-verified queries and redacted errors.
Leave the ordinary `ferrum-ci-postgres`/`ferrum-ci-mysql` consumers on their
existing separate contract. The five gateway TLS policies and Admin API
behavior need no change for credential adoption.

The data-plane setup inside
`.github/workflows/ci.yml` independently provisions the old SQL passwords and
the Mongo TLS/mTLS fixtures. Its separate, owner-approved adoption must update
SQL generation (lines 2216–2316), SQL readiness and grants (2520–2550), test
input wiring (the functional test step near 2653), and final cleanup together.
Generate the same private file/mount layout and separate root secret; pass only
the connections-file path and existing `FERRUM_TEST_CERT_DIR` to tests, and
retain `FERRUM_DB_TLS_REQUIRED=1`. Replace SQL readiness with authenticated
verified `SELECT 1`, use the private root option file for grants, withhold raw
failure logs, and remove private material in unconditional cleanup. Any use of
this helper by a guarded workflow needs its own approved reachability/contract
update; keep the independently provisioned Mongo TLS/mTLS fixtures intact.

Before proposal landing, root must coordinate the test/common-helper owner and
guarded-CI owner into one compatible adoption batch, obtain the required policy
approval for those files, and collect exact-head hosted evidence for all five
cells, database cleanup and credential exposure checks. This round inventories
and proposes that batch; it does not implement or approve it. The candidate's
own SQL client probes remain independent of these Rust/Admin consumers.
This candidate changes neither that job nor any frozen verifier, planner,
aggregate, publication inventory, or required check. The new optional check
does not certify the Rust gateway's database trust implementation or the
unchanged guarded fixtures, and is not added to branch protection.

## Evidence status, remaining risks, and owner decision

Verified during preparation: source/consumer inspection, imported/API draft
state, published image index identities, and local `git diff --check` only.
The [first hosted qualification](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37195808893/job/111417306382)
for `0c17ded8b` passed the profile/Mongo phase and reached SQL mTLS after the
ordinary TLS controls, then failed with the generic negative-control diagnostic.
The independent review recorded no other static blocker across the seven-file
proposal. Cleanup completed, but the live SQL argv/log credential scan was not
reached. This failed run is not qualification approval.

The [second hosted qualification](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37196574213/job/111419615974)
for `827f328d70d621e60cb0f5fd92f6ecc6718f8322` identifies the failure as
`mysql-untrusted-client-default`. Ordinary verified TLS wrong-CA, hostname and
plaintext negatives passed, as did PostgreSQL missing/untrusted client and
MySQL missing-client controls. The trusted MySQL TLS 1.2 query and the paired
`mysql-untrusted-client-tls12` certificate-alert negative passed. The default
rogue-client attempt failed, but its stderr matched neither the TLS/auth
substrings nor the two narrowly allowed error-2013 messages. Raw stderr was
not retained. The later default positive and live argv/log scan were not
reached; cleanup ran. This remains failed qualification, not proof of the
default rejection's cause.

The [required trusted policy check](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37196573281/job/111419613381)
and [CI policy check](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37196574202/job/111419819039)
also rejected both `tests/scripts/` workflow commands as outside their scanned
automation roots. The relocation and explicit dispatcher above address that
demonstrated reachability failure. Their acceptance is still unverified until
the unchanged hosted checkers inspect the new exact head.

MySQL's
[`sslaccept`/X509 path](https://github.com/mysql/mysql-server/blob/8.0/sql/auth/sql_authentication.cc)
drops invalid client certificates during the handshake. In TLS 1.3,
[`SSL_connect` can finish before the server verifies the client](https://mta.openssl.org/pipermail/openssl-users/2022-October/015568.html);
the MySQL [client read path](https://github.com/mysql/mysql-server/blob/8.0/sql-common/client.cc)
can then report `ERROR 2013 (HY000)` while reading the authorization packet or
final connect information, rather than `SSL connection error`/`Access denied`.
The precise historical stderr was withheld, so this remains a possible
source-based explanation, not an observed diagnostic from either run. The
second run disproved assuming the two existing exact error-2013 patterns were
sufficient. No additional error-2013 variant is admitted on that assumption.

The repair names every negative case using fixed, credential-free labels and
keeps subprocess output private. For MySQL it extracts only a four-digit numeric
error and a fixed diagnostic category from a bounded, single-error record;
it emits neither SQLSTATE nor any message, argv, password, certificate/key
material, user/host, or path. Certificate-specific TLS alerts, authentication
rejection, the two exact late-auth-read error-2013/HY000 messages with system
error 0, other late-read system errors, initial-handshake disconnects, and
unclassified failures remain distinct. A connection reset is classified for
diagnosis but is not newly admitted. Generic SSL errors (including local
material failures/unsupported protocols), unknown errors, ambiguous/missing
records and timeouts cannot pass the default rogue-client control.

The untrusted MySQL client must actually fail on its default protocol. The
current classifier admits only certificate-specific error-2026 alerts on its
own; neither error 1045 nor any error-2013 message establishes certificate
rejection. The TLS 1.2 certificate-specific negative and paired SQL positive
remain a distinct control. A default trusted `SELECT 1` runs after the rogue
attempt even if its cause is unknown; availability cannot upgrade an unresolved
negative to PASS. The server's allowed protocols, client verification settings,
and default CLI query/options remain unchanged.

The [479abdf8 hosted qualification](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37201180556/job/111433021934)
again reported default CLI `2013/client-server-lost-during-query`, explicitly
`UNQUALIFIED`, while the TLS 1.2 control reported `2026/tls-alert-unknown-ca`
and the subsequent default trusted `SELECT 1` passed. Its separate CPython TLS
1.3 handshake probe reported `probe-capability-or-provenance-failure`; that was
a **distinct attempt**, never evidence about the original CLI connection. The
run reached the live argv/log scan but failed before reporting that scan PASS.
Neither its default CLI cause nor a completed qualification is proved.

This diagnosis replaces the private CPython message callback and separate
handshake with public observation inside the existing immutable CLI invocation.
The published pinned index selects amd64 manifest
`sha256:62fb722c78b24245ddff1796a0fcee4a49cc5b87e0aaaf20c92d1da9e0a2497b`,
whose [image source](https://github.com/docker-library/mysql/blob/7cf11d5360282effadb347353d5f82339506b106/8.0/Dockerfile.oracle)
installs `8.0.46-1.el9` on Oracle Linux 9. The
[matching MySQL VIO source](https://github.com/mysql/mysql-server/blob/mysql-8.0.46/vio/viossl.cc)
calls `SSL_new` and `SSL_read`; its
[connector source](https://github.com/mysql/mysql-server/blob/mysql-8.0.46/vio/viosslfactories.cc)
configures peer verification and identity checking.
[OpenSSL's public info callback](https://docs.openssl.org/3.0/man3/SSL_CTX_set_info_callback/)
reports incoming alerts with `SSL_CB_READ_ALERT`. These primary sources make
interposition plausible; published image/source metadata **does not prove**
that the immutable binary dynamically interposes those functions. The hosted
capability checks must establish that fact for each actual invocation.

The explicit dispatcher compiles the small observer with GCC only on the
hosted runner, into the private SQL client mount; it links no runner libssl.
The preload changes only the loader environment of the original CLI argv:
private option file, `SELECT 1`, endpoint, rogue certificate/key overrides and
default protocol settings are identical. Real functions resolve through
`dlsym(RTLD_NEXT)` from one `libssl.so.3` mapping; certificate getters resolve
from one `libcrypto.so.3` mapping. The process executable must match
`/usr/bin/mysql`. Unsupported symbols, mappings or interposition fail closed.

The observer attaches once to the real `SSL_new` result only when neither an
object nor a context info callback is already present. Pre-existing callbacks
are left untouched and make this conservative observer unsupported, preserving
their getter semantics as well as their events. If a context callback is
introduced later, the observer removes its originally-null object override
before forwarding that current event with unchanged arguments; future events
use OpenSSL's normal context fallback. An application object setter is also
respected. The observer never reinstalls itself to recover evidence. It
preserves errno around its own work. It never sets verification modes,
protocol limits, verification callbacks, key logging or message callbacks,
performs TLS I/O, serializes certificates inside TLS, or reads/clears the
OpenSSL error queue. Callback introduction/replacement makes observation
unqualified. Another SSL
object, handshake, thread or incoming alert, an outgoing fatal alert, changed
binding, or a missing free also prevents qualification.

A single bounded numeric record (at most 128 bytes) is emitted to privately
captured stderr at normal process exit. It contains only fixed booleans,
bounded counts, protocol 13, and numeric incoming-alert level/code. The harness
separates this record from the original error without printing either raw
record or raw error. A passing refusal requires a completed verified TLS 1.3
handshake, peer-verification mode, socket peer `127.0.0.1:3306` or `[::1]:3306`,
matching generated server/selected-client certificate signatures, one SSL
object/handshake, intact callback observation through free, and an incoming
fatal `unknown_ca(48)`, `certificate_unknown(46)` or `bad_certificate(42)`.
An exact catalog error 2013 may accompany that same attempt's certificate
alert; **bare 2013 remains insufficient**. Instrumented valid-client `SELECT 1`
positives before and after must show the same verified default TLS 1.3 binding
and no incoming alert; the subsequent original uninstrumented query must also
pass. This qualifies the newly observed invocation only, and cannot
retroactively prove the cause of any earlier unobserved 2013.

Public certificate DER is generated by finite OpenSSL commands in runner temp;
a strict outer-DER parser extracts only the generated RSA signature for private
comparison through `X509_get0_signature`/ASN.1 getters. No signature, hash, key,
password, user, server message or TLS session secret reaches hosted output.
The harness requires the pinned container identity, matching read-only client
and option-file mounts, and unchanged private material across each invocation.
All generated `.so`, DER/signature inputs and finite `.records` files stay
under the existing runner-temp SQL directory: mode `0600`, runner ownership,
single links, regular files and explicit size limits. The existing private
directory, `finally` cleanup, SIGTERM/SIGINT handling and unconditional workflow
cleanup cover success, failure and signals; no artifact/cache/upload is added.
Parser/admission self-checks cover duplicate, missing, malformed, oversized,
noncertificate and unbound observations. Synthetic self-checks are never
runtime evidence. Remaining availability and credential argv/log scans
still run before the final fail-closed assertion.

The [feadc91cf hosted qualification](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37202471389/job/111436786371)
passed both instrumented original default CLI TLS 1.3 `SELECT 1` positives,
the same original rogue-client invocation with `2013` plus an incoming
`unknown_ca` alert, and the subsequent uninstrumented trusted query. It then
failed at `CHECK: live SQL process argv, healthcheck configuration and logs`
with the generic withheld command error. Unconditional cleanup passed.
This establishes the observed invocation's certificate refusal, but supplies
no completed credential scan or whole-candidate approval.

Static inspection identifies a deterministic defect in the next command:
`docker top ... -eo args` omits the PID header required by Docker's
[daemon process filter](https://github.com/moby/moby/blob/v28.0.4/daemon/top_unix.go#L64).
The daemon invokes host `ps` and rejects output without that header; it does
not depend on `ps` being installed in either SQL image. The withheld stderr
does not prove the precise error text from that run. The repaired command
uses `-eo pid,args -ww`, retaining the required PID and full-width argv.
Nonzero exit, launch failure and deadline diagnostics now name only a fixed
operation/container stage and bounded numeric exit status, never command
inputs or output. No deadline or sleep-query duration was increased.

The live scan validates nonempty PID/argv inventories, observes both sleeping
clients, and scans those same complete snapshots rather than taking another
snapshot after the clients may have finished. Each inventory must contain its
inspected server PID. The host scan enumerates `/proc` directly and requires
both owned Docker clients alive with readable argv containing their exact
query argument. An unreadable process or missing owned client fails; only an
unrelated process that exits between enumeration and reading is absent from
the snapshot. Kernel processes with an empty cmdline have no userspace argv.
The scan checks all three generated credential canaries against complete
Docker configuration, retained `State.Health.Log` output, every container argv
row, both container-log streams and host argv. Disabled/missing healthchecks,
missing health history/output, unhealthy state and empty container logs fail.
Raw argv, environment, logs and private observer records remain withheld.

The dedicated scanner tests run inside the existing hosted qualifier before
fixture startup. They inject each synthetic canary into every required surface
for both SQL containers, including trailing bytes in a long argv, and require
rejection. They also cover malformed/empty/duplicate process inventories,
missing health/log surfaces, failed commands, timeouts, launch failures and
incomplete/unreadable/exited owned host processes. Test exception details stay
in a private in-memory unittest stream; only a fixed aggregate result is
printed. These synthetic controls supply no runtime fixture evidence.

The scan repair leaves the C observer, strict full-record incoming-alert
parser, original CLI/TLS profiles, image pins, ownership labels and all cleanup
paths unchanged. Its exact pushed head still needs hosted execution and root's
review before approval. No workflow, Cargo or guarded consumer change is made.

This source is **not yet completely hosted-qualified**. Root must independently review all
new observation, parser, command and cleanup logic, inspect exact-head hosted
capability and positive/negative evidence, and confirm the original controls and
credential scan/cleanup still pass. If dynamic interposition is unsupported or
the actual CLI exposes no certificate-specific alert, retain failed qualification
with the fixed nonsecret capability/binding/refusal category. Do not retry an
uninvestigated failure or classify it as an external blocker.

Concrete redesign for fresh root/security-owner review if this client-side
instrumentation proves infeasible: preserve the original CLI failure as an
unqualified diagnostic; separately qualify the security invariant that default
TLS 1.3 on this immutable server admits the trusted certificate/query and
refuses the generated untrusted certificate at server-side verification. A
server-side public OpenSSL observer would need to bind the actual server
verification result to the original CLI's socket/peer and selected certificate,
preserve existing callbacks/verification, retain the same privacy/lifecycle
limits, and pair it with availability/credential scans. Adopting that gate would
require an explicit reviewed qualification-contract decision; neither a
separate client probe nor a generic disconnect satisfies the current gate.

**Focused re-review required:** the new diagnostic/admission code, post-attempt
positive in `finally`, command/environment boundary, dispatcher operation
inventory, moved setup root calculation, and retained manual forwarder were
not in the prior immutable `827f328d7` review input. Root must review these
changes against the new exact head and confirm that all original controls and
both hosted trust contracts remain effective. The actual default-case proof
must remain failed until its permitted diagnostic is observed and identified.

**The repaired head still requires a fresh complete hosted run.** Root must
record its exact SHA and checkout/merge-tree identity, run URL/result, all
default/PostgreSQL and Mongo checks, SQL TLS/mTLS positives and every wrong
CA/hostname/plaintext/missing/untrusted-client rejection, the later live
argv/healthcheck/log credential scan, and successful cleanup before owner
approval. An earlier-head pass, an unreached scan, or a partial run is
insufficient. No local repository code, builds, tests, formatters, Compose, or
fixture scripts were executed.

Remaining boundaries: host administrators/local same-user processes can read
secrets; loopback publication does not isolate local users, Docker bridge peers,
or remote Docker hosts; Docker/network implementation details may affect
reachability and only the tested hosted platform will have evidence. Shared
client credentials and a CA signing key are intentionally kept in the private
disposable directory, and client identity is mounted into both SQL containers.
SQL and Mongo fixture accounts remain highly privileged. Existing Mongo users
need rotation; source edits cannot revoke old credentials. Sample Mongo/Postgres
passwords remain in Compose environment/URI metadata. Digest pins need deliberate
refresh for upstream fixes. Hard-coded SQL consumers and the guarded hosted
fixtures remain unchanged pending their own approval. Local Docker Desktop
bind-mount ownership behavior is unqualified until separately exercised.

Requested owner decision after hosted evidence: approve the startup guard and
hex alphabet; accept removal of Mongo from default startup and loopback-only SQL
publication; approve generated-file SQL credentials and explicit retirement of
old fixtures; authorize the separate consumer/guarded-contract dependency; then
decide landing/release/advisory handling. Reject or revise these compatibility
choices explicitly if required. This branch supplies the concrete reviewable
candidate and does not assert a patched released version.

Reference semantics: [Compose interpolation](https://docs.docker.com/reference/compose-file/interpolation/),
[Compose secrets limitations](https://docs.docker.com/reference/compose-file/services/#secrets),
[official PostgreSQL entrypoint](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh),
and [official MySQL entrypoint](https://github.com/docker-library/mysql/blob/master/docker-entrypoint.sh).
