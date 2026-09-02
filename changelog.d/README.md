# Changelog fragments

Unreleased changes live here as one small file per change, instead of in
`CHANGELOG.md`'s `## [Unreleased]` section. Two pull requests touching no common
source file no longer conflict in the changelog (issue #4487), so the merge
queue is not capped by a shared text block and landing one pull request does not
force a re-sync sweep of every other open one.

`## [Unreleased]` in `CHANGELOG.md` stays **empty** between releases. Do not
hand-edit it; add a fragment here.

## Naming

```
changelog.d/<ref>.<section>.md
```

- `<ref>` — the issue number (`4487`), or `pr<N>` (`pr4501`) when there is no issue.
- `<section>` — one of `added`, `changed`, `deprecated`, `removed`, `fixed`,
  `security` (the Keep a Changelog sections `CHANGELOG.md` already uses), or
  `upgrade` for a `docs/upgrade_guide.md` block.

One change may ship several files: `4487.changed.md` and `4487.fixed.md` are
independent bullets, and a second bullet in the same section goes in its own
file under a different `<ref>` (for example `pr4501.changed.md`).

## Contents

A changelog fragment is **exactly one** top-level Markdown bullet — `- ` at
column 0, continuation lines indented two spaces — in the house style already
used in `CHANGELOG.md`: a bold lead, an `(issue #N)` citation, and a
`**BREAKING** —` prefix when the change breaks user-visible behavior.

```markdown
- **`ferrum-gateway` exposes the DP stale-config fence** (issue #4438). Data
  plane installs can set `dp.configMaxStaleSeconds`, which renders
  `FERRUM_DP_CONFIG_MAX_STALE_SECONDS` with the binary's default.
```

A breaking change **must** cite an issue number and **must** also ship
`changelog.d/<ref>.upgrade.md`, holding one or more `### <heading> (issue
[#N](https://github.com/ferrum-edge/ferrum-edge/issues/N))` blocks in the style
of `docs/upgrade_guide.md`, each ending in an `**Operator action:**` paragraph.

```markdown
### Stale-config fence is fail-closed (issue [#4438](https://github.com/ferrum-edge/ferrum-edge/issues/4438))

What changed, and what an operator sees at cutover.

**Operator action:** what to do before upgrading.
```

Use absolute `https://github.com/ferrum-edge/ferrum-edge/blob/main/...` URLs
rather than relative paths. A fragment's text is moved to the repository root at
release time, where a path relative to `changelog.d/` no longer resolves.

## Preview and validation

```bash
python3 -I scripts/assemble_changelog.py --preview   # render what will ship
python3 -I scripts/assemble_changelog.py --check     # the rules below
```

`--check` fails on an unknown section, a malformed name, an empty body, more
than one top-level bullet, an unindented continuation line, a `**BREAKING**`
bullet with no matching `.upgrade.md`, an `.upgrade.md` with no `**BREAKING**`
sibling, a relative link target, a hand-edited `## [Unreleased]` section, and a
`CHANGELOG.md` with no `## [Unreleased]` heading.

The same rules are enforced in CI by `changelog_fragments_tests` in the `Unit
Tests` job, so a fragment mistake fails the required check without a workflow
change. `changelog_upgrade_parity_tests` additionally requires every breaking
fragment's issue number to appear in its upgrade guidance.

## Release assembly

At release time, one command turns the fragments into a released section:

```bash
python3 -I scripts/assemble_changelog.py --release 0.10.0 [--date YYYY-MM-DD]
```

It renders the non-empty sections in Keep a Changelog order under a new
`## [X.Y.Z] - <date>` heading directly below a fresh empty `## [Unreleased]`,
inserts the `.upgrade.md` blocks into `docs/upgrade_guide.md` under
`## Breaking changes in X.Y.Z` (leaving older versions alone), updates the
compare-link references at the bottom of `CHANGELOG.md`, and deletes the
consumed fragments. Running it again with no fragments left is a no-op. See
[docs/ci_cd.md](../docs/ci_cd.md) → "Creating a New Release".
