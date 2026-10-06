# Dependency-fenced deployment mutations

Merged #6012 supplies this source capability for the
[0.9.12 candidate](releases/v0.9.12.md).
Release qualification, canonical publication and downstream adoption remain pending;
published v0.9.11 does not provide this profile.

The opt-in `deployment-v1` profile (#6010) supports exact proxy cascade removal
and API-spec replacement without replaying a whole namespace through restore.
Ordinary CRUD, API-spec replacement, backup and restore keep their existing
profiles. A proxy row ETag does not authorize this profile.

## Coherent owner evidence

Read `GET /deployment-snapshot` with an admin-role JWT and the intended
`X-Ferrum-Namespace`. Queries and resource filters are refused. The response has
`Cache-Control: no-store`, a strong `ETag`, and these members:

- `profile`: exactly `deployment-v1`.
- `namespace_etag`: the same quoted token as the HTTP `ETag`.
- `proxies`, `upstreams`, `plugin_configs`, `api_specs`: typed inspection data
  from the same primary snapshot. Specs carry content/hash/ownership metadata;
  the stored gzip document (`spec_content`) and any stored external-reference
  snapshot appear as `{"sha256": "<hex of stored bytes>", "len": <bytes>}`.
  `api_specs` is sorted by `id` in byte order and equals
  `evidence.resources[5]`, whatever order or collation the store returns.
- `api_spec_contents`: the stored bytes from the same snapshot, in the same
  order as `api_specs`. Each entry is `{"id", "spec_content_base64",
  "external_ref_snapshot_base64"}`, with `external_ref_snapshot_base64` `null`
  when no external-reference snapshot is stored. Each value decodes to the
  exact stored bytes whose `sha256`/`len` the evidence fences. Verify them
  against `api_specs`. This is the only copy of the bytes in the response. It
  sits outside `evidence`, so it is not part of the token's digest, but its
  digest and length are, so one read recovers the original documents. Together
  the base64 values are bounded at **256 MiB**. A namespace past that returns
  `507` with `durable: "not_started"` and discloses nothing.
- `evidence`: the complete comparison representation. It binds all namespace
  resources, spec metadata and stored-document digests, associations, trust,
  namespace metadata, the durable change watermark, and raw stored
  rows/documents. SQL includes every column of the resource and association
  tables, including credential indexes, with each column's SQLx type, runtime
  value type and lossless scalar evidence (float bits; blobs as `sha256`/`len`).
  Typed nulls retain their column type. MongoDB includes raw documents (binary
  values as `binary_sha256`/`len`/`subtype`) and the SHA-256 of their BSON
  bytes (`bson_sha256`), covering embedded association metadata.
  MongoDB credential representations and uniqueness hashes are stored on
  `consumers` and covered by those raw documents; `consumer_identity_index`
  is the separate identity reservation collection. Lease maintenance and audit
  records do not invalidate authority.

The read is admin-only because evidence contains unredacted credentials and
spec/plugin material. Security-audit admission is mandatory before disclosure,
independent of ordinary audit enablement. Keep the response and original token
in encrypted recovery storage; do not put evidence or tokens in routine logs.
A token uses a distinct `deployment-v1-` prefix and keyed HMAC under the admin
JWT secret over a bounded SHA-256 of the canonical evidence. Replicas must share
that secret. A backup/restore namespace token or individual row token is not
deployment authority. Stores compare that digest, not a retained copy of the
evidence, inside the mutation transaction. A namespace whose canonical evidence
would exceed **64 MiB** returns `507` with no token. Stores count typed
resources against that bound before reading raw rows/documents, then count each
raw row/document as they convert it. An over-bound namespace is therefore
refused before the rest of its evidence is built. A snapshot read or the
pre-transaction check of a mutation reports `durable: "not_started"`. A refusal
raised inside the mutation transaction, which rolls back, reports
`durable: "not_committed"`. A `507` is deterministic for unchanged namespace
state, so do not retry it. Stored spec documents count only as their digest
toward the 64 MiB bound, but every stored spec of the namespace is still loaded
in full to compute it.
Tokens issued before stored bytes were digested (v0.9.12) keep the
`deployment-v1-` shape but no longer match: they fail closed with `412`.
Finish or abandon in-flight recoveries before upgrading, then capture new
authority; never refresh authority to retry a refused recovery.

Snapshots require PostgreSQL, MySQL, SQLite or replica-set MongoDB. Standalone
MongoDB returns `501`. Missing stores or unavailable/undecodable coherent state
return `503`, without cached fallback. Existing representability checks remain:
an unknown top-level field on a MongoDB resource whose typed schema rejects
unknown fields refuses authority; it is never erased to make the operation
succeed. Unknown metadata inside supported association objects and arbitrary
credential/config maps is retained and fenced. Unknown collections are not
mutated or represented as deployable resources by this profile.

## Exact owner writes

After comparing the entire original target proxy, specification, generated
plugins and associations to the intended deployment, send the **original**
quoted token on exactly one `If-Match` field to one of:

```text
DELETE /proxies/{id}?conditional=true&cleanup_orphaned_upstream=false
PUT /api-specs/{id}?conditional=true
```

PUT takes the ordinary OpenAPI JSON/YAML body, preserves proxy identity, and
runs the existing spec extraction/admission rules. Both writes require their
existing roles (operator for proxy removal, admin for spec replacement) and
namespace authorization. They still obey read-only and database topology gates.
`apply=sync` may occur once; `apply=async` is refused in this profile.

`conditional` must occur exactly once with the value `true`. Removal also
requires exactly one `cleanup_orphaned_upstream=false`. Unknown parameters,
missing/duplicate/invalid mode values, missing/duplicate headers, lists,
wildcards, weak tags and tokens from another profile return `400`. Sending a
deployment token without the discriminator also refuses. Deployment mode on
other mutation routes refuses instead of applying their ordinary write. Ordinary requests
without this mode keep their supported missing-If-Match behavior.

An original token that no longer matches returns `412` without mutation. This
includes an operator changing hosts, plugins or a document-only spec field,
unrelated writes in the same namespace, and recorded changes later reverted. The store
compares evidence again inside the selected mutation's transaction. A live
owner/generation lease is pinned **before** establishing that snapshot; its
renewal is handed from the local keeper to the transaction and fenced at commit.
SQL uses the writer lock on SQLite and transaction row locks on PostgreSQL and
MySQL. PostgreSQL refreshes its READ COMMITTED view after acquiring the namespace
writer fences; MySQL establishes its REPEATABLE READ snapshot after those fences.
All selected dependency reads remain protected through commit. MongoDB uses snapshot/majority
transactions with a changed lease-document write pin. Driver transaction retries
retain the original expected representation and cannot substitute fresh authority.

Removal deletes only the selected proxy, owner spec, its cascade plugins,
selected associations and generated upstreams. A last-referenced hand-owned
upstream is retained. A shared group plugin, its other owners and their fields
survive. The namespace-wide orphan sweeper is not used. Spec replacement
preserves unrelated resources, hand-added plugin rows/associations, retained
association metadata and unknown fields on surviving supported documents.
Unrelated timestamps, historical credentials and trust revisions are never
prepared or rewritten. Matching resource bundles update only the spec row;
this profile also records a covering proxy change for acknowledgement. A group
plugin left without associations by spec replacement is retained for explicit
operator cleanup. Generated rows retain their original creation timestamps and
supported unknown columns/fields when the same ID survives. A surviving row
whose known semantics did not change retains its complete historical fields and
both timestamps. This includes a proxy whose final merged fields and associations
are unchanged during a plugin-only replacement: its raw row/document, timestamps
and row ETag stay intact, including hand-added association metadata. Explicit
associations must be unique and reference existing plugins scoped to this proxy,
or ownerless group plugins; foreign scopes refuse. A store schema that cannot
reinsert a selected row safely refuses and rolls back.

Missing or inconsistent target ownership/dependencies, foreign owners or shared
owners of a plugin the cascade would delete return `409` before selected writes.
Proven external references to spec-owned upstreams use the same typed
`409/not_committed/unconfirmed/recovery_cleanup_authorized=false` refusal on
resource-changing PUT/DELETE. Metadata-only replacement keeps its shortcut before
that guard. Database/commit/lease-release and other untyped failures remain
uncertain; driver messages cannot prove rollback. Ordinary invalid external-owner
proxy admission still returns `400` without a durable row or covering change.
Composition, named-schema, TCP-throttle and mTLS policy admission still apply
to the fenced candidate using the configured validation client. Invalid
submitted specs retain their ordinary validation errors. Admission
rejection or a definitive transaction failure rolls back every selected write.
No whole-namespace restore, late compensation or unconditional fallback runs.

## Acknowledgements and recovery adoption

Mutation results contain only identifiers and status, with no credential/spec
body echoes. A confirmed response has `profile: "deployment-v1"`, `id`,
`durable: "committed"`, `live`, and `recovery_cleanup_authorized`:

| Result | HTTP | Live status | Cleanup authorization |
| --- | --- | --- | --- |
| Commit and covering local generation applied; final audit and namespace admission lease release acknowledged | 200 | `applied` | `true` |
| Commit in CP mode, an unserved namespace, or a process without a serving coordinator | 200 | `not_applicable` | `false` |
| Commit confirmed but local apply, final audit, cursor capture or namespace admission lease release cannot be confirmed | 503 | `unconfirmed` | `false` |
| Transport/store acknowledgement uncertain | 503 if a response is available | `unconfirmed` | `false`; durable state `unknown` |
| Precondition/graph refusal | 412/409 | `unconfirmed` | `false`; durable state `not_committed` |
| Namespace too large inside the mutation transaction | 507 | `unconfirmed` | `false`; durable state `not_committed` |

Initial mode/evidence/admission failures may report `durable: "not_started"`.
Legacy validation/authentication errors need not contain these acknowledgement
members and cannot authorize cleanup. A covering local live result carries
`X-Ferrum-Config-Cursor`. This proves only this process's application; it does
not assert every remote DP has applied the change. CP consumers must separately
qualify downstream live application and retain recovery state in the meantime.

After a MongoDB transaction is confirmed committed, internal mTLS admission
mutex cleanup drains every guard and logs redacted cleanup failures for operator
recovery. Cleanup cannot turn that confirmed durable result into a failed or
unknown mutation. Transaction commit uncertainty still retains the mTLS fence;
the final audit, namespace admission lease release and live checks above still
control cleanup authorization.

Ordinary mutations on these routes retain their error contracts: proxy deletion
uses `Error` for plugin-composition rejection (`400`) and the typed `error` /
`detail` atomicity refusal (`501`). Namespace contention (`503`) may carry
`Retry-After: 1`; ordinary committed-not-live responses have `applied: false`
and may carry `X-Ferrum-Config-Cursor`. Pre-commit responses never carry that
cursor. Conditional dependency or ownership refusals use the deployment
acknowledgement at `409` for both removal and spec replacement. A `503` from
either mode never authorizes automatic recovery replay or journal removal.

A consumer adopting this capability must:

1. Capture and retain one coherent owner snapshot and its original token before
   validating the intended deployment. Compare the complete target spec and
   plugin bodies, including stored external-reference evidence.
2. Use the exact write route above with that original token. Never refresh the
   token merely to make recovery pass, and never downgrade to an ordinary
   DELETE, spec PUT, or restore-minus-target.
3. Require a complete response with the expected profile/target,
   `durable: "committed"`, `live: "applied"`, and
   `recovery_cleanup_authorized: true` before removing an automatic recovery
   journal or proceeding with dependent cleanup.
4. Retain the encrypted original journal after refusal, missing fields,
   committed-but-not-live results, audit/lease failures, cancellation or lost
   transport. Cancellation can leave an owned transaction settling on the
   server; absence of a response is never replay authorization. Reconciliation
   may inspect current owner state, but a fresh read cannot retroactively
   authorize replay of the original destructive action.

This is an owner capability and adoption contract. It does not assert Nexus
adoption, packaged qualification, publication or advisory closure.
