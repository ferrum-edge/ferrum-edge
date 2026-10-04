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
executes `tests/scripts/qualify_compose_fixtures.py` on an Ubuntu hosted runner,
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
base URL (`test_postgresql_tls_verify_full`, `test_postgresql_tls_require`,
`test_mysql_tls_verify_identity`, `test_mysql_tls_required`, and
`test_health_endpoint_shows_db_status`). They need private input URL support,
including percent encoding when accepting arbitrary passwords, before they
can consume this generated fixture. The data-plane setup inside
`.github/workflows/ci.yml` independently provisions the old SQL passwords and
the Mongo TLS/mTLS fixtures; its guarded job must receive a separately approved
contract/generation update if it is to adopt this helper or generated inputs.
This candidate changes neither that job nor any frozen verifier, planner,
aggregate, publication inventory, or required check. The new optional check
does not certify the Rust gateway's database trust implementation or the
unchanged guarded fixtures, and is not added to branch protection.

## Evidence status, remaining risks, and owner decision

Verified during preparation: source/consumer inspection, imported/API draft
state, published image index identities, and local `git diff --check` only.
**Hosted execution, format, compile, tests, real Docker binds, and TLS handshakes
are unverified at handoff.** This document describes test intent and source
behavior, not a successful hosted run. Root must attach the exact candidate
SHA and hosted run URL/result, independently review the changes, and resolve
any failures before seeking owner approval. No local repository code, builds,
tests, formatters, Compose, or fixture scripts were executed.

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
