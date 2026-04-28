# Upstream h3 patches

Tracks fixes we've drafted for [hyperium/h3](https://github.com/hyperium/h3) that address bugs surfacing in our HTTP/3 backend dispatch path. Each numbered subdirectory is a self-contained patch with the issue draft, PR description, unified diff, and a lifecycle README explaining how to file the upstream artifacts and how to retire the patch when it merges.

## Active patches

| ID | Title | Crate | Status | Tracked by |
|---|---|---|---|---|
| [001](001-recv-frame-drain-on-quic-close/) | frame: drain buffered bytes before propagating QUIC connection error | `h3` | Drafted; not applied | [PR #506](https://github.com/ferrum-edge/ferrum-edge/pull/506) gateway-side workaround |

## Conventions

Each subdirectory is `NNN-short-kebab-summary/` with:

- `README.md` — Status, links, hand-off steps, and retirement plan
- `issue.md` — Bug report draft for upstream
- `pr-description.md` — PR description draft for upstream
- `<file>.patch` — The unified diff against the pinned upstream version

When a patch is upstreamed and we've bumped past the affected version, move its directory to `_retired/NNN-...` with a STATUS.md noting the merge commit and the local cleanup that closed it out.

## Why this exists

The H3 / QUIC stack is young enough that we hit upstream bugs faster than they release. Vendoring patched crates is sometimes the right call — but vendoring without a written retirement plan creates dead code that nobody knows how to remove. This directory is the retirement plan, written in advance.

See also: [`docs/http3.md`](../http3.md) for the runtime behavior these patches affect.
