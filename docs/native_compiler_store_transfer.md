# Native compiler-store transfer proof

This manual workflow extends the synthetic envelope in PR #4746 to actual
compiler-cache bytes. It builds the actual locked Fuzz property suite on main,
hands data from a read-only runner to a separate publisher, then restores
the immutable GHCR digest anonymously on another fresh runner.

Path-filtered PRs run the read-only producer through successful compilation and
bounded export, so its real build environment is checked before merge. PRs do
not upload the handoff or run the publisher, reader or cleanup. Only manual main
runs in ferrum-edge/ferrum-edge may hand off and publish compiler-store data.
Path-filtered main pushes run the streaming format contracts only. The existing
public ferrum-edge-buildcache package is reused; package visibility, the 10 GB Actions
cache limit and the zero-dollar spending budget remain unchanged.

## Data boundary

The producer installs nightly-2025-07-01 and the existing checksum-pinned
sccache wrapper, runs cargo test --locked in fuzz, then stops its compiler-cache
server before snapshotting only .cache/sccache. Its explicit empty RUSTFLAGS
matches the production Fuzz lane and clears the root Cargo configuration's mold
linker flags; this isolated producer does not install that optional linker.
It restores and saves no Actions cache. Capture and handoff happen only after this actual property suite passes;
a competing lane cannot evict the source between a build and a later restore.

This is a separate transfer validation, with its producer exercised on relevant
PRs rather than every production change. It preserves the production sanitizer
suite and does not substitute the property suite for AddressSanitizer coverage.

The format is a bounded binary frame, not a tar archive: a fixed magic/version,
an eight-byte manifest length, strict JSON metadata and ordered file bytes.
Limits are 3 GiB payload, 32,768 regular files, an 8 MiB manifest, path depth
eight and 200-character relative names. Data moves in 1 MiB chunks. Links,
special files, unsafe paths, duplicate metadata, ordering/parent conflicts,
unexpected fields, invalid identities, changed source files, bad lengths,
checksums and trailing bytes are rejected. Capture assumes a quiescent store;
it is not a sandbox against concurrent hostile filesystem mutation.

The identity binds the snapshot to this workflow's SHA, run, attempt, Linux
x64 platform and the pinned property-build specification. The producer starts
with a fresh compiler store and captures this successful source build. The
reader checks snapshot provenance and byte identity; it does not yet compile
against the restored store. Compiler-key compatibility, source-changing reuse
and production lane/toolchain identity remain separate requirements before
this becomes a build cache backend.

The reader validates every byte and the producer's aggregate SHA-256 before
creating a fresh private destination. A second streaming pass copies regular
files with mode 0600, checks for changes, then inventories the result for byte
identity. Existing destinations cannot be overwritten. The scratch image has
only the frame; it is created and copied from but never started.

## Credentials and cleanup

The producer has contents-read permission and uploads one exact-ID artifact.
The publisher has packages-write permission on a separate runner, validates
the handoff before login, and publishes a unique invocation tag. It executes
no restored cache contents. The reader uses a fresh empty Docker config,
contents-read permission, the fixed repository and the exact published digest.

The large handoff expires after one day. Cleanup normally deletes it immediately
after the reader ends, after checking its exact name, source SHA and workflow
run. Registry cleanup requires the exact digest with the invocation's tag as its
only tag, full version pagination, exactly one match and an individual recheck.
It deletes only that version. The small proof artifact lasts seven days.

Cleanup failure is visible. A publisher interrupted after upload but before
returning its digest may leave its uniquely tagged version; investigate that
exact invocation before another dispatch. Do not broaden deletion scope.

## Remaining acceptance

This workflow proves real-data transport and permission separation. It does
not close #4643 or #4694 and does not yet change production build cache reads,
writes, FIPS, release profiles or compiler settings.

Production integration still needs capture from the existing required build
lanes, compatible lane and toolchain identity, same-input and source-changing
compiler reuse, bounded retained generations, and later-main retention evidence for Unit, Lint and
Artifacts. If moving compiler stores alone leaves too much Actions cache data,
target/dependency persistence must also be addressed. The prior target payload
measurement came from an already-pruned Actions archive and cannot bound an
unpruned end-of-build target directory.
