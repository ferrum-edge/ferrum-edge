# Grouped automation trust candidate

Proposal for [GHSA-652c-qw6h-2hw6](https://github.com/ferrum-edge/ferrum-edge/security/advisories/GHSA-652c-qw6h-2hw6)
and [GHSA-w92m-frx7-pxjp](https://github.com/ferrum-edge/ferrum-edge/security/advisories/GHSA-w92m-frx7-pxjp).
This branch prepares code and hosted tests for independent root review. It does
not activate review generation, comment publication, releases, or a new trust
profile on main. No advisory publication or repository configuration is included.

## Evidence baseline and qualifications

The supplied drafts in `.orchestration/advisories.json` were read in full, then
the two advisory descriptions were read directly with `gh api`. Both were still
drafts and matched the supplied descriptions at inspection on 2026-10-04. The
local copy's SHA-256 was
`301dc2b6a37c67462109eb2cc6f26bc618515d108c5d791a01cda484f835aaa0`.
That private input is not part of this commit.

The drafts audited `ba42ee3f3555d200f33c05b748e80519892e57e1`. This candidate
traces the assigned current-main baseline
`b1d462c89408a30a28d65960cad6b67263875ff0`, not the historical line numbers.
Observations below are source facts unless explicitly called configuration or
an inference. No exploitation or malicious cache object was demonstrated.

The code-scanning alerts API returned HTTP 404, `no analysis found`, with a token
scope diagnostic. That is **not evidence that alerts are false or resolved**.
Root must inspect existing CodeQL alerts with appropriately authorized access,
retain their source/sink evidence, and compare them to the complete candidate.
This branch neither dismisses alerts nor changes scanning/admission policy.

## Current LLM review path

At the baseline, `.github/workflows/claude-review.yml`:

- Schedules on created `issue_comment` events for a PR, a matching review prefix,
  and the named owner's login. This limits who triggers work, not whose source
  the model reads. The trigger comment belongs to the owner; the PR source can
  belong to an external contributor.
- Grants `contents: read`, `pull-requests: write`, `issues: write`, and
  `id-token: write`. It checks out `refs/pull/<issue.number>/merge` with full
  history and `persist-credentials: false`. The moving merge ref is not bound
  to an immutable head captured by the comment event.
- Supplies the comment body as prompt text and explicitly tells the model to
  publish. Allowed tools include source reads, `gh pr comment:*`,
  `gh pr diff:*`, `gh pr view:*`, and the inline-comment MCP tool. The Bash
  patterns do not bind the destination to the triggering PR. An inline tool
  with `confirmed: true` is also authorized; Bash is not the only write path.

The pinned action is
`anthropics/claude-code-action@756cc22e19660d20e8cc9496b4f242475a7f7790`.
Its published source was inspected without executing it:

1. [`src/github/token.ts`](https://github.com/anthropics/claude-code-action/blob/756cc22e19660d20e8cc9496b4f242475a7f7790/src/github/token.ts)
   takes an explicit GitHub-token override if supplied. This workflow supplies
   none. Otherwise it obtains GitHub OIDC with audience
   `claude-code-github-action` and exchanges it at Anthropic's
   `/api/github/github-app-token-exchange` for an installation token.
   Consequently, the draft's **unused id-token grant** claim is incorrect for
   this pin. Removing OIDC without changing authentication breaks the action.
2. [`src/entrypoints/run.ts`](https://github.com/anthropics/claude-code-action/blob/756cc22e19660d20e8cc9496b4f242475a7f7790/src/entrypoints/run.ts)
   exports the App token as `GITHUB_TOKEN` and `GH_TOKEN`, prepares GitHub MCP,
   and passes provider auth to the Claude runner. GitHub workflow permissions
   alone do not bound a separately minted App token. The upstream custom-App
   manifest defaults to contents/issues/pull-requests write; the actual
   installed App and exchange-service grants were not observable here and must
   be checked by the owner. No claim of a specific installed grant is assumed.
3. `src/modes/agent/index.ts` and
   [`src/github/operations/git-config.ts`](https://github.com/anthropics/claude-code-action/blob/756cc22e19660d20e8cc9496b4f242475a7f7790/src/github/operations/git-config.ts)
   configure git auth again using that token. With no `allowed_non_write_users`
   setting, the action can place it in the origin URL. Checkout's
   `persist-credentials: false` does not prevent this later credential setup.
4. `action.yml` passes `CLAUDE_CODE_OAUTH_TOKEN` from the workflow secret to the
   provider/CLI environment. It is Anthropic provider authorization, separate
   from the GitHub App token. The SDK options copy the environment and default
   to user/project/local setting sources. No API-key or cloud-federation input
   is configured in this workflow.
5. The pin already calls `restoreConfigFromBase()` for PR contexts. Its
   sensitive list includes `.claude`, `.mcp.json`, `.claude.json`, `.gitmodules`,
   `.ripgreprc`, root `CLAUDE.md` / `CLAUDE.local.md`, and `.husky`. This is a
   real mitigation, so this proposal does **not** claim those root files are
   blindly executed at this pin. It does not remove arbitrary PR source text,
   nested instructions or the intentionally authorized publication tools.
   `action.yml` also has a buffered inline-comment post step.

The remaining real boundary problem is attacker-influenced review content
reaching a credentialed tool-capable model that is authorized to publish. A
successful injected public comment is plausible from these capabilities; no
successful exploit, secret theft, arbitrary Bash execution, or actual App grant
was measured. Source inspection does not prove that all PR content executes.

Read-only configuration inspection reported workflow ID `277041871` as
`disabled_manually`, and `GET /repos/ferrum-edge/ferrum-edge/environments`
returned `total_count: 0`. Therefore the unsafe source still exists, but a live
running review bot cannot be inferred. No workflow was enabled by this worker.

## Candidate review and publication boundary

`claude-review.yml` becomes manual-only, main-only and default-off through
`LLM_REVIEW_MODEL_ENABLED == 'true'`. Its token has only contents/PR read, with
no OIDC, issues write, App exchange, Claude Code action, or model GitHub tools.
It checks out only trusted automation at the dispatch's `github.sha`, with
sparse checkout and credentials not persisted. It never checks out PR code.

`generate_llm_review.py` accepts the requested PR number and a complete head SHA,
checks the open PR/base through GitHub, then requests comparison data using the
immutable base/head pair. It checks the same PR/head/base again after fetching
and after generating output. It rejects missing patches, capped file lists,
binary patches and excessive input. The model sees bounded JSON patch data,
not a worktree. Root/PR instruction files, settings, hooks and scripts are never
loaded as instructions or executed. The request uses the fixed Messages API
endpoint, a trusted system prompt, `tools: []`, and no tool loop. Prompt text
cannot turn on a tool. Unexpected response types and incomplete responses fail.

This deliberately replaces provider OAuth/Claude Code with a dedicated
Messages API key. The owner must provision a scoped workspace key, approved
model ID, spending limit and data-handling policy; the existing subscription
OAuth token is not silently repurposed. No API call is made during proposal
tests. See the official [Messages API](https://platform.claude.com/docs/en/api/messages/create).

The four-file artifact contains `input.json`, raw untrusted `review.txt`, the
deterministically rendered `comment.txt`, and a binding manifest. No raw model
text is printed in logs, workflow outputs or step summaries. Mention markers,
HTML delimiters, bidi/control characters are neutralized, and every model line
is rendered as literal indented code, including attempted Markdown escapes or
URLs. Sanitization is presentation control; human review remains mandatory.

`llm-review-publish.yml` is a separate manual-only, main-only, default-off
workflow. Its read-only inspect job verifies the source run's workflow path,
repository, main branch, exact automation revision, successful first attempt,
one unexpired artifact with matching workflow-run metadata, reviewed PR/head/base
and three human-supplied hashes. Archive download accepts one GitHub-issued HTTPS
redirect only to `productionresultssa<digits>.blob.core.windows.net`, without
forwarding any credential. Other storage backends need a separately reviewed
allowlist change. API and provider redirects and proxy discovery are disabled;
the provider endpoint is fixed, regardless of input or provider-base environment
variables.
Archives are read as data without extraction, with exact filenames, bounded
compressed/member sizes, no symlinks, no extra/duplicate members and duplicate
JSON-key rejection. JSON must be strictly decoded UTF-8, contain only finite
numbers, and nest objects and arrays no deeper than 64 containers. Both generator
and publisher validate the same closed input/patch schema:
1–299 unique relative paths, bounded UTF-8 text, a finite status set, and no
unknown patch fields, invalid Unicode or unexpected controls. These are finite
data contracts, not a guarantee of complete or truthful patch/model content.
The publisher regenerates the comment and compares its exact bytes.

Before the environment job can request approval, the read-only inspect job reads
the actual environment and deployment branch policies. It requires a positive
environment ID, exactly the named human required reviewer, prevent-self-review,
explicitly disabled administrator bypass, and one custom deployment policy for
the exact `main` branch, without tag/wildcard allowances. Missing fields, unknown
protection rule types, extra reviewers, unavailable APIs or unavailable plan
features fail closed. It rereads the environment around the branch-policy API
read, then exports only its validated ID and SHA-256 of the relevant settings
snapshot (including rule/policy IDs and settings revision) to the dependent job.
No model text becomes an output. A historical approval alone cannot pass this
preflight.

The publish job depends on successful inspection, uses the
`llm-review-publication` environment, and has only contents/actions/PR read plus
issues write. It runs the same trusted publisher script, without a provider
secret or model. Before its sole POST, it repeats artifact/identity/head checks
and requires a real approval in **this publisher run's**
[`/actions/runs/<id>/approvals`](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run).
The approval must name the **same environment ID** admitted before approval and
user `jeremyjpj0916` (ID `31913027`, type `User`). The publisher also reads its own
run metadata: its actor and triggering actor must identify the same distinct
named human on the trusted manual first attempt. Immediately before its sole
POST, after comment pagination and the live PR read, it revalidates the current
environment settings/identity against the inspect snapshot and reads actual
approval history again. Protection drift or a deleted/recreated environment
refuses the write even when a historical record still says approved. Absent
approval, an unprotected environment, administrator bypass, another environment,
a bot, self-approval, rejection or ambiguous history refuses the write. Reruns
are refused; create a new inspected
dispatch. Approved repeats are serialized per PR and skip an identical existing
GitHub Actions comment. Writes are not retried after uncertain HTTP failures.
The model cannot choose an endpoint, PR number, file path, or command to run.

## Current cache-to-publication trace

The baseline's `.github/actions/setup-boringcache/action.yml` selects the
backend only with an eligible repository/event/actor and available OIDC request
credentials. Fork PRs and Dependabot are excluded; trusted main pushes can
save, other eligible runs restore. `boringcache/one` is pinned to
`f0fb9b2d926a32b10c543e92093ba00c5a291b79` (v1.33.0). Its archive profiles and
`.boringcache.toml` include both Cargo downloads and executable target trees;
the Cargo adapter also uses sccache. The separate `boringcache-connect.yml`
downloads a checksum-pinned CLI and binds GitHub Actions to
`jeremy-j/ferrum-edge` through interactive Machine enrollment. The configured
workspace is visible in source; actual enrollment/capability settings are not.

These identity/save controls stop ordinary unauthorized cache writers. They
do **not** authenticate object code returned by a compromised service. The
checksum pin authenticates the CLI/wrapper, not restored compiler outputs.
Target archives can also contain executable build/test artifacts. The action's
old "verified compiler cache" step name was misleading and is corrected without
changing its guard or permitted nonpublication warm-cache behavior.

The actual baseline producer/consumer paths are:

| Producer | Consumer and publication consequence |
| --- | --- |
| `ci.yml` cached tests and `build-test-artifacts` | Tests and the `main-linux-image` job use warm compiler/test outputs. The image is a short-lived Actions tar artifact, **not** a registry push or signed release. |
| `ci.yml` `build-binaries` | Warm `pr-build` verification, not a release binary producer. It is not the binary input to main-latest. |
| `main-latest-image.yml` `build` | On successful main-push CI, BuildKit fetches the validated immutable source SHA by public Git URL with an empty build GitHub token. It compiles root Dockerfile's `runtime` stage on native amd64/arm64, using cloud-secrets and the existing architecture-specific release profile. No CI compiler/image artifact or BoringCache restore is consumed. Digests flow through smoke, manifest, attest/sign, verify and promote. |
| `release.yml` native release producer | No BoringCache action, but setup-sccache and Swatinem restore `target` and `.cache/sccache`. Native macOS/Windows release binaries can consume these outputs. The x86_64 GNU producer isolates its own sysroot target and clears wrappers, but isolation alone is not a fresh-directory proof if a target tree was restored. |
| `release.yml` ARM64 Cross producer | No compiler-cache restore; fixed empty Cross environment, `RUSTC_WRAPPER=`, existing cloud-secrets/release command and protected image/tool pins. Its published assets feed the default ARM64 image. |
| `release.yml` `docker` | Downloads only same-run `release-binaries-<target>`, stages the actual GNU assets, and packages them with Dockerfile.release. Both producer jobs are dependencies. |
| `release.yml` `docker-ebpf` | Builds `runtime-ebpf` and `runtime-ebpf-tools` from source on native runners. The ELF/userspace bytes flow through their existing digest/manifests and three-family attestation/signing jobs. No BoringCache restore. |

Thus the draft's direct **BoringCache CI object → signed main-latest bytes**
claim is not supported by current source. Matching source SHAs do not make
different builds share binary bytes. A compromised cache still influences
executable CI and validation evidence; poisoning a test/build artifact may
execute in those jobs or produce misleading success. That real exposure is not
dismissed. OIDC audience/capability for cache access is not release-signing
authorization, and no cross-audience cloud privilege was established.

## Smallest proposed cold publication boundary

The existing no-BoringCache and cold Cross release policy stays in place. The
native GitHub compiler-cache restore is an additional baseline gap, not an
already universally cold release lane. This candidate removes its cache action
and sccache setup, explicitly clears Rust compiler/workspace wrappers, and fails
on a preexisting target/sccache tree. Fresh hosted runners compile every native
release asset; the existing sysroot/ABI scan still gates the actual uploaded
GNU bytes. No Cargo manifest, crypto selection, Cross invocation, supported
profile, release/tag gate, binary artifact identity or consumer graph changes.

All publication BuildKit producers use `no-cache: true`: main-latest runtime,
release default packaging, and both release eBPF families. There is no remote
compiler/layer cache import and no warm CI artifact handoff into these builds.
The eBPF ELF and dependency compilations run inside the fresh build too.
Already signed main-SHA images retain the existing signature-verified reuse
policy; this is not proof that a historical image was cold and does not
retroactively rebuild or bless one. Base images, tool releases and source
dependencies remain their existing trust roots.

CI tests, FIPS validation and nonpublication performance/profile lanes retain
their current permitted warm caches. This boundary prevents their object bytes
from being the source of signed artifacts; it does not make cached test
execution safe from a malicious cache service or authenticate that service.
If the owner no longer trusts the service, the separate operational action is
to disable the backend, revoke/rotate the Machine connection and investigate
cached execution. No enrollment, cache deletion, setting or secret is changed
by this worker. No cache-content signature/hash scheme is invented here.

This candidate does not establish a direct BoringCache compiler-object path into
signed main-latest **or release** images, and does not claim demonstrated exploit
closure for that premise. Cold native GitHub compiler-cache hardening addresses
a separate publication exposure. Nonpublication BuildKit validation images also
retain registry cache imports, including `ambient-host-udp-live.yml` and
`production-dockerfile-smoke.yml`; their cached validation evidence remains a
residual risk alongside cached CI execution and historical signed-image reuse.

## Hosted evidence and admission

`automation-trust-proposal-checks.yml` runs the new unittest suite on the
proposal push and relevant PRs, with contents read and no secrets. Tests cover
exact PR/head fetching, hostile output, actual `prepare()` selection/provenance
checks, rerun/head/base motion during download, unsafe archives, UTF-8/finite
JSON/schema/byte limits, provider response processing, and the real urllib
redirect handlers with mocked HTTPS responses. Tests verify no credential
forwarding, no internal/unknown artifact endpoint, no provider endpoint override,
protection drift and environment identity, actual preflight outputs, distinct
human dispatch/approval, exact comment destination, repeat-dispatch behavior and
an ambiguous POST failure with **exactly one write attempt**, without a retry.
No test uses live credentials or contacts a model or GitHub.

For publication, structural checks enforce cold BuildKit/native producers and
same-run binary artifact dependencies, alongside the existing main-latest graph
parser. `automation_trust_contracts.json` pins the active producer/consumer and
release gate job bodies and entry conditions at the reviewed `5d7c29f…` candidate;
only blank/comment-only lines are omitted. Mutations must be rejected by the
actual contract validator, including structural refusal for cold-boundary changes.
The fixture does not freeze unrelated `ci.yml` or `fips-build.yml`, so legitimate
Admin/other main changes no longer break this proposal lane. There is no dynamic
subprocess baseline helper, network fixture acquisition or opaque process command.

The pinned candidate contract in these proposal tests is a regression fixture, **not**
an admission mechanism. Future reviewed publication changes must update the
test expectations deliberately. The trusted Cross checker, publication
verifier/inventory, digest/admission machinery, settings and main source are
untouched. In particular, `RELEASE_IMAGE_FAMILY_GENERATIONS` freezes complete
eBPF producer steps, so adding `no-cache` there is expected to fail the current
trusted contract. Other frozen producer/consumer surfaces may also reject the
candidate. That failure must remain visible; tests passing in the separate
candidate lane cannot authorize or bypass it.

No local formatter, tests, builds, scripts or model/provider requests were run.
Local verification is static source/diff inspection and `git diff --check`.
Hosted checks for the pushed SHA are unverified at worker handoff; root owns
collection and diagnosis. Do not treat pending/skipped checks as passing.
The previous exact-head PR run failed the unrelated whole-CI fixture assertion;
the policy log also identified two opaque fixture-helper commands. This repair
removes those failure sources without weakening trusted policy. The three
external frozen release producer/artifact-selection failures remain expected.

## Exact root and owner checklist

1. Root independently reviews this whole grouped candidate, current main
   source, advisory qualifications and hosted evidence for the full pushed SHA.
   Inspect CodeQL alerts with authorized access; keep actionable alerts open
   until their actual source/sink is addressed. No review-bot dispatch is
   needed or authorized by this proposal.
2. Preserve the candidate branch while protected checks refuse it. An owner
   must use the repository's established trusted-base policy process to admit
   the **exact** cold producer step changes and preserve all existing
   Cross/crypto/publication bindings. A narrowly reviewed trusted-policy update
   belongs to root/owner, outside this worker's scope. Do not rename/move a
   workflow to evade scanning, suppress a check, refresh digests automatically,
   self-authorize admission, or merge through a failure. This branch makes no
   release-behavior/trust-profile change on main.
3. Keep the existing Claude review workflow disabled. Leave
   `LLM_REVIEW_MODEL_ENABLED` and `LLM_REVIEW_PUBLISH_ENABLED` unset/false while
   root assesses the design. The candidate adds no comment trigger and never
   invokes a review bot. Review the installed Anthropic App's actual repositories
   and permissions; if it served only this review workflow, owner may remove
   that installation/revoke unused credentials after confirming other users.
   Do not change an installation shared with other automation blindly.
4. Only after an independent human decision to adopt, configure a dedicated
   Anthropic workspace API key as `ANTHROPIC_REVIEW_API_KEY`, set
   `LLM_REVIEW_MODEL` to a currently supported approved Messages API model ID,
   and set provider quota/spending/data-retention limits. No provider OAuth
   token, GitHub App private key, PAT or OIDC grant is needed by the candidate.
5. Physically create `llm-review-publication` in repository Settings →
   Environments **before** enabling any publisher. Require reviewer
   `jeremyjpj0916` (User ID `31913027`), enable **Prevent self-review**, disable
   administrator bypass, and restrict deployment branches to exact `main`
   (custom policies; no tag or wildcard allowance). The corresponding
   environment update body is:

   ```json
   {
     "wait_timer": 0,
     "prevent_self_review": true,
     "can_admins_bypass": false,
     "reviewers": [{"type": "User", "id": 31913027}],
     "deployment_branch_policy": {
       "protected_branches": false,
       "custom_branch_policies": true
     }
   }
   ```

   Add a deployment branch policy with `name: main`, `type: branch`, and
   verify the returned protection rules/branch policies with an owner account.
   See [GitHub environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
   Put no model credential in this publisher environment. If the plan cannot
   enforce required reviewers, leave publication off. GitHub availability differs
   for public/private repositories and paid plans; verify the actual repository
   with [the environment API](https://docs.github.com/en/rest/deployments/environments#get-an-environment)
   and [branch-policy API](https://docs.github.com/en/rest/deployments/branch-policies#list-deployment-branch-policies).
   Verify those exact read endpoints with the proposed job's existing read-only
   token, including explicit `can_admins_bypass: false` and branch `type: branch`.
   If fields or API permission are unavailable, **publication stays off**; do not
   add a PAT, privileged App/human credential, self-review fallback or implicit
   allow. An environment name or manual unprotected environment is not approval.
   This branch does not approve or provision any of this human configuration.
6. A separate designated maintainer must dispatch publication; the named owner
   cannot both dispatch and approve it. If no second maintainer is available,
   keep publication off and inspect review artifacts privately. Expanding the
   named reviewer set requires another reviewed code/configuration change.
7. When root explicitly authorizes a later activation, owner may enable the
   model workflow and its switch separately from the publisher switch. First
   verify hosted negative cases without a model credential or comment write.
   Never activate either from this worker run. After adoption, each model
   dispatch takes the PR number and exact head; inspect all four artifact files
   without executing any content. Hash input.json, review.txt and comment.txt
   and compare the manifest. A second maintainer dispatches the publisher with
   source run ID, PR/head and those three digests. The owner inspects those
   exact bytes and the inspect summary before approving this run's environment.
   Do not approve just because the model sounds authoritative.
8. Require new generation/inspection after PR head/base motion, main automation
   revision changes, expired artifacts, or a source/publisher rerun. There is an
   unavoidable GitHub read/POST race: a push after the last head read can leave
   an explicitly old-head comment. It never targets a model-chosen PR or claims
   a new head was reviewed. The environment/history APIs also offer no atomic
   settings precondition for a comment POST: changes after the final revalidation
   remain a residual race. Revision/ID checks catch observed drift, not every
   transient change between reads. Inspect uncertain POST outcomes before any
   manually authorized new dispatch; the publisher itself never retries.

The five findings in the independent whole-candidate review are addressed in
this repair: current environment admission/binding (P1), relevant publication
contracts instead of whole-CI equality (P2), removal of opaque fixture subprocesses
(P2), behavioral trust-boundary coverage (P2), and strict JSON/shared patch schema
(P3). This records implementation disposition only. Root must still perform a
fresh whole-candidate review and focused review of this delta, collect exact-head
hosted results, and arrange actual trusted-base admission before any adoption.

Remaining costs/limitations: cold publication takes longer and both eBPF
families compile independently; existing timeout budgets must be measured on
hosted runners without weakening them preemptively. The model is patch-only;
GitHub may omit context or truncate individual patches, so absence of findings
is never comprehensive approval. Sanitization cannot make model claims true or
prevent a person from manually following a printed URL. Cached nonpublication
test evidence and historical signed-image reuse remain explicit trust risks.
