# Dependency security upgrade #5912

Implementation and hosted lockfile resolution as of 2026-10-04. This record
does not claim that a Dependabot alert is closed on the default branch or that
hosted build, formatting or behavioral tests passed.

## Verified advisory scope

The repository's open Dependabot alerts were read through the GitHub API:

| Alert | Advisory | Package | Lockfile | Fixed floor |
|---|---|---|---|---|
| 1 | [GHSA-w9wp-h8wv-79jx](https://github.com/advisories/GHSA-w9wp-h8wv-79jx) | `opentelemetry_sdk` | root | 0.32.1 |
| 6 | [GHSA-8ffr-xgwf-xj56](https://github.com/advisories/GHSA-8ffr-xgwf-xj56) | `aws-smithy-json` | root | 0.62.7 |
| 5 | [GHSA-6g2r-675j-hx59](https://github.com/advisories/GHSA-6g2r-675j-hx59) | `xxhash-rust` | root | 0.8.16 |
| 7 | GHSA-6g2r-675j-hx59 | `xxhash-rust` | `tests/performance/mesh` | 0.8.16 |

All committed lockfiles were inspected statically. Only the root carries the
affected SDK and Smithy JSON. Before this change, the root and mesh carried xxhash 0.8.15; fuzz
already carried fixed xxhash 0.8.18. The imported hosted lockfiles use xxhash
0.8.16 in root/mesh and retain 0.8.18 in fuzz. Other standalone benchmark graphs, eBPF,
and the committed dimpl regression graph contain none of these affected
packages. Root, mesh and fuzz are the three graphs consuming Ferrum's Hyper
and reqwest path patches. Independent HTTP benchmark clients use registry
Hyper intentionally and do not depend on the production Ferrum crate.

## Published compatible chain

Official crates.io sparse-index entries and downloaded crate sources were
checked; the selected versions are published and not yanked. The crates.io
API endpoint returned HTTP 403 locally, so publication was verified against
`https://index.crates.io/` and `https://static.crates.io/` instead.

| Package | Selected version | Published minimum Rust |
|---|---|---|
| `google-cloud-secretmanager-v1` | 1.10.0 | 1.88.0 |
| `google-cloud-auth` | 1.11.0 | 1.88.0 |
| `google-cloud-gax-internal` | 0.7.14 | 1.88.0 |
| `google-cloud-gax` | 1.11.0 | 1.88.0 |
| `google-cloud-wkt` | 1.5.0 | 1.88.0 |
| `opentelemetry`, semantic conventions | 0.32.0 | 1.75.0 |
| `opentelemetry_sdk` | at least 0.32.1, on the 0.32 line | 1.75.0 |
| `tracing-opentelemetry` | 0.33.0 | 1.75.0 |
| `hyper` | 1.10.0, with retained Ferrum patches | 1.63 |
| `reqwest` | 0.13.4, with retained Ferrum patches | 1.85.0 |
| `aws-smithy-json` | 0.62.7 | 1.91.1 |

Security-only optional GAX/WKT/SDK constraints keep GCP on this compatible
generation, while preserving its existing enabled features. Otherwise newer
GAX releases can require reqwest 0.14 and bypass the 0.13 vendor patch. The
Smithy constraint is enabled only by `secrets-aws`; the xxhash constraint is
a floor for a dependency already present in the ordinary production graph.
These are exceptions to the usual API-use reason for a direct dependency.
No secret-resolution or telemetry call site needed an API change: the published
Secret Manager builder, endpoint, anonymous credentials and payload APIs retain
the shapes used by `src/secrets/gcp.rs`.

The producer selects Smithy runtime API 1.12.3, types 1.4.9, schema 0.1.0 and
the existing async 1.2.14 and runtime API macros 1.0.0, rather than silently moving the AWS runtime onto its
newer 1.94.1 compiler generation. The selected runtime API and types require
Rust 1.91.1; schema and the macro crate require 1.91. No toolchain, build profile, crypto feature
pair or runtime FIPS policy is changed. Cloud secrets remain deliberately
unsupported for use in enforcing FIPS mode; this upgrade makes no new claim
about that combination.

## Archive provenance and patch ports

| Archive | SHA-256 | Published VCS revision |
|---|---|---|
| [`hyper-1.10.0.crate`](https://static.crates.io/crates/hyper/hyper-1.10.0.crate) | `eb92f162bf56536459fc83c79b974bb12837acfed43d6bc370a7916d0ae15ecc` | `79dbab620bf14b96cd5d53a60ca35d7fe2ddbaf1` |
| [`reqwest-0.13.4.crate`](https://static.crates.io/crates/reqwest/reqwest-0.13.4.crate) | `219c5811de6525e5416c7d5d53bb656d3afdbc6c5af816e0802bcfa42dbdc1c3` | `11489b34eda6d32b15ad4033e62beba2ee401350` |

Both archive hashes matched their index checksums. Hyper's published VCS
metadata includes `dirty: true`; the verifier records and checks that marker.
The archive checksum identifies the actual published bytes, not a claim that
the archive equals a clean checkout of its recorded revision.

Hyper's complete ordered [001–004 stack](upstream-hyper-patches/README.md)
was rebased. Patch 001 retains CONNECT_ERROR reset. Patch 002 retains positive
window progress and pending DATA; it now preserves Hyper 1.10's body-first
polling, real-chunk reservation and reset polling while waiting. No idle body
speculatively reserves a byte of connection capacity. Patch 003 retains greedy
HTTP/1 reads, deferred transport errors and the upgrade-error handoff, adapting
both upgrade call sites to upstream's documented `expect` invariants. Patch
004 retains the ready-chunk write-stall timer, CANCEL reset, expiration signal
and progress rearming. Existing embedded vendor regressions remain present.

Reqwest's [complete published-source delta](upstream-reqwest-patches/reqwest-ferrum.patch)
retains all four local patches and all later local source corrections:
request-scoped connect timeout, provider selection, physical-connection
admission and Unix socket reporting. The provider fallback conflict was resolved
in favor of Ferrum's existing Ring/AWS-LC feature selection. No local patch was
retired and no owner, upstream status or retirement decision was changed.
Upstream 0.13.4's TLS key logging is still disabled by default; its native-TLS
1.3, response decoding, DNS and HTTP/3 changes are also retained.

The integrity manifest was refreshed using `shasum -a 256` for the new vendor
files (all retained paths are LF text), keeping every other vendor entry.
No repository integrity script, formatter, Cargo command or test was executed
locally. Static `git apply` reconstruction from fresh archives matched both shipped
source trees and manifests byte-for-byte, and the new manifest entries passed
`shasum` verification. Hosted reconstruction must independently confirm this.

## Hosted lockfile production and remaining gates

The optional [Dependency Security Lockfiles workflow](../.github/workflows/dependency-security-lockfiles.yml)
has read-only contents permission, a fixed same-repository branch allowlist,
no secrets or write credentials, and a bounded 20-minute job. It reconstructs
both vendor deltas, runs targeted Cargo updates against the actual root, mesh
and fuzz manifests, checks every committed lockfile for the advisory floors,
checks metadata for exactly the intended vendor paths, and checks the ordinary
and supported base FIPS feature graphs. It does not flatten the workspace or
invent Cargo entries/checksums. The artifact includes lockfiles, source SHA,
Cargo/Rust versions, metadata, feature trees, checksums and a lockfile diff.

**Hosted resolution passed:** [run 37205581999](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37205581999)
produced artifact `dependency-security-lockfiles-993578017d5b02766cafd9bbae0f2b27d404c402-1`
(ID `11304234065`) from source SHA
`993578017d5b02766cafd9bbae0f2b27d404c402`, with Cargo and Rust 1.99.0.
Its source SHA and all three lockfile hashes were verified before the original
artifact bytes were imported. No graph or checksum was hand-edited.

| Imported lockfile | SHA-256 |
|---|---|
| `Cargo.lock` | `296c380b49cb46ed420da48f9a88ce64e8eab2a778fa331603e73e3d32078d10` |
| `fuzz/Cargo.lock` | `af0f00f7d3cc62c75dc2bd6c177531732afc9a8e725dcf51a4c1bd10f804b466` |
| `tests/performance/mesh/Cargo.lock` | `d9207e05814190457ebdcfd053f6f8b012102d4f2eee162a8786f2fc09c3f741` |

The producer passed vendor reconstruction, metadata resolution for all three
actual graphs, security-floor checks over every committed lockfile, exact vendor
path/uniqueness checks, the crypto manifest check, and ordinary/supported base
FIPS feature-tree checks. Root now locks SDK 0.32.1 and Smithy JSON 0.62.7.
Root/mesh/fuzz each resolve one Hyper 1.10.0 and one reqwest 0.13.4 from their
intended path patches. This demonstrates resolution and feature selection,
not compilation, behavioral correctness, or the AWS SDK's actual MSRV build.
The runtime versions listed above retain their published compiler floors.

**Remaining:** root must complete any new-workflow trusted-base admission and
run hosted formatting, compile, dependency audit, vendor, secret-provider,
small-window, write-stall, upgrade-error and stream-lifetime regressions on the
final pushed head. Existing FIPS CI rejected the pre-import head's stale
`--locked` graph; it must be rechecked after import. Hosted job success for the
lock producer does not replace these gates. Do not merge or release before
those gates and the owner-controlled bindings below are complete.

Root/automation owners must update the guarded existing `ci.yml` bindings:
the Hyper archive URL/name/checksum near lines 1714–1718 and every Hyper vendor
manifest path near lines 2027–2046. Their current 1.9.0 bindings cannot validate
this 1.10.0 port. Current path hints in `.claude/rules/dependencies.md`,
`.claude/rules/proxy-protocols.md` and vendor-integrity test fixture strings also
still name the former vendor directories; those worker-owned files were not
edited here. Historical released changelog/upgrade/benchmark entries stay intact.

Material risks pending hosted evidence: the body-first reservation adaptation
changes HTTP/2 capacity scheduling; reset polling precedes pending DATA on every
repoll; upstream Hyper adds its lock module and request-dispatch changes; and
reqwest changes TLS/DNS/response/HTTP/3 internals. The new producer and graph
checker passed on the hosted resolver head and have not been executed locally.
A resolver incompatibility, policy
admission rejection, feature-policy failure or hosted formatting diff requires
a follow-up before this security chain can be considered fixed.
