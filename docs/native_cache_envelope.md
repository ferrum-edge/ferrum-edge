# Native compiler-cache transport proof

Issue #4643 still requires native Rust cache retention after later main runs.
The Docker BuildKit registry caches do not automatically preserve a native
runner's compiler store. This proof tests a container-image envelope for those
bytes before connecting any compiler or changing an Actions cache lane.

The only payload is a deterministic public fixture: an empty file, binary bytes
and repeated text. The image starts from `scratch`, contains one bounded tar
file, has no executable, and is never started. The build context is a fresh
runner-temporary directory containing only that fixture. No workspace, Cargo
home, compiler cache, environment, credentials or logs enter the image.

PR/push checks exercise the archive boundary, rejected malformed members and
a local Docker build/create/copy/verify round trip on a GitHub-hosted runner.
The verifier accepts only regular files, rejects links, traversal, duplicates,
undeclared files and checksum/size mismatches, and validates everything before
creating a fresh destination. It does not invoke tar extraction or preserve
ownership/executable modes. The proof intentionally caps archives at 1 MiB,
payloads at 256 KiB and entries at 16; these are not production cache limits.

After integration, manually dispatch **Native Cache Envelope Proof** on main.
Only that trusted-main dispatch can publish, using the workflow token and the
existing `ferrum-edge-buildcache` package. Its unique `native-envelope-v1-proof`
tag and image label contain the run ID and attempt. A separate fresh runner
with no registry credentials pulls the immutable output digest, copies the tar
without starting the image, and compares it to the independently generated
fixture. The small JSON/digest evidence artifact is retained for seven days.

The cleanup job runs after the reader, including a failed reader, and deletes
only the version whose digest and sole tag both match this invocation. It
rechecks that version before deletion and fails visibly on missing permission,
ambiguity or additional tags. It does not remove shipping images or unrelated
cache generations. If the publisher is interrupted after uploading but before
returning its digest, investigate that exact run tag before another dispatch;
there is no broad orphan sweep. No automatic publication or scheduled run is
enabled. Check cleanup success as part of accepting the proof.

GitHub documents [anonymous reads of public container images and digest-pinned
pulls](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
The same document lists a 10 GB per-layer limit and ten-minute upload timeout.
[Public package use is currently free](https://docs.github.com/en/billing/concepts/product-billing/github-packages).
The existing free Actions allowance, spending budgets and package visibility
remain unchanged; this is not a permanent unlimited-storage guarantee.

This proof does not claim native cache reuse or resolve #4643/#4694. Production
adoption still requires real payload sizing, compiler/toolchain/family identity,
bounded transfer and extraction for the measured payload, a same-input warm
comparison, a source-changing reader that rebuilds affected inputs, and actual
Unit/Lint/Artifacts retention and timing across subsequent main runs. FIPS and
release publication remain separate contracts.
