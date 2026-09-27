# Diagnostic Reference Lookup Across Replicas ADR

Status: Accepted and implemented (issue #5846, item 4).

## Context

Gateway diagnostic references (issue #5767, extended by #5846 items 1–3) put an
opaque `X-Ferrum-Diagnostic-Ref` on gateway-authored error responses. The
detail behind a reference lives only in a bounded, TTL-limited, sharded store
in the memory of the process that minted it, and is readable only through the
authenticated admin `GET /diagnostics/v1/refs/{ref}`. Behind a load balancer,
the admin listener an operator reaches is usually not the process that served
the response, so the lookup misses and nothing says where to look.

Every design has to keep the guarantees the feature already makes:

- No secrets, bodies, headers, paths, or raw error text in the detail.
- Namespace-scoped lookup: a reference outside the token's `ns` claim answers
  like an unknown one.
- Bounded memory and a bounded lookup budget.
- Uniform `404`s, so references cannot be probed.
- No new unauthenticated surface.

## Decision

Keep the store per process, and make the reference name its owner.

1. **Replica tag, opt-in.** `FERRUM_DIAGNOSTIC_REF_REPLICA_TAG=true` makes a
   store mint `fd2_<8 hex replica id>_<32 hex>` instead of `fd1_<32 hex>`. The
   replica id is 32 bits drawn from the process CSPRNG when the store is
   installed. It is derived from nothing (no host name, pod, node, address, or
   namespace) and changes on restart, when the store is emptied anyway. A
   CSPRNG failure at startup fails startup rather than silently minting
   untagged references. The default stays `false`, so the #5767 promise that a
   reference embeds nothing still holds unless the operator opts in.
2. **Discovery.** The process logs its replica id once at startup, exports
   `ferrum_diagnostic_ref_replica_info{replica_id} 1` on `/metrics` (joined by
   Prometheus to the target's pod and instance labels), and returns it as
   `replica_id` in its own `200` lookup body.
3. **Owner hint on a miss.** A tagged reference minted by another process
   answers the same `404` status and body as any miss, is counted as
   `not_found`, and is audited like one. When the caller passed every check a
   `200` would need on the answering process (the `diagnostics:read` scope, an
   `ns` claim, and an `ns` claim naming that process's namespace), the `404`
   adds `X-Ferrum-Diagnostic-Owner-Replica: <replica id>`. The hint is read
   from the reference the caller supplied. The answering process never learns
   whether the owner exists, still holds the reference, or serves the caller's
   namespace, so the hint can neither probe the owner nor cross a namespace.
   The owner enforces its own namespace check when the lookup reaches it.
4. **No control-plane fan-out.** Operators route the lookup to the owning
   replica themselves.

### Compatibility

`fd1_` references keep resolving on the untagged process that minted them. A
store resolves only the format it mints: re-spelling one format as the other
never resolves. In a mixed fleet an untagged process still hints at the owner
of an `fd2_` reference, and a tagged process answers an `fd1_` reference it did
not mint with the plain `404`, since an `fd1_` reference names no owner.

### What the tag reveals

Untagged references are unlinkable. With the tag, anyone who collects
references, clients included, can tell which responses one process served and
estimate how many processes answered, until the next restart. Nothing else is
revealed. That is the reason the tag is opt-in and derived from nothing.

## Rejected Alternatives

- **Control-plane fan-out over the CP↔DP channel.** ConfigSync `Subscribe` is a
  server-streaming RPC the data plane opens; the control plane only writes
  configuration to it and cannot call a data plane. Fan-out would need a new
  DP-side RPC (or a request/response protocol multiplexed onto the config
  stream) that carries diagnostic detail across the network, DP-side
  authorization mapping CP admin tokens to namespaces, and time and
  concurrency bounds. It would also not help `file` or `database` fleets, which
  have no control plane. The hint gives operator tooling the same routing
  answer without any of that surface.
- **Shared store** in the control plane, the configuration database, or Redis.
  Every referenced error would cost a network write on the proxy path, the
  detail would leave the process that owns it, the shared store would need its
  own per-namespace bounds, retention, and access control, and an outage of it
  would lose references or slow error responses.
- **Hash of a host, pod, or node name.** A short unkeyed hash of a guessable
  name (a Deployment's pod names follow a known pattern) can be reversed
  offline by a client, which leaks topology the operator never published. A
  keyed hash needs a key shared by every replica, which `file` and `database`
  fleets do not have.
- **The DP `node_id`.** It is already a random per-process UUID and shown by the
  control plane's `GET /cluster`, but it exists only in `dp` mode, so it cannot
  serve `file` or `database` fleets, and `/cluster` does not map it to a pod or
  address either.
- **Operator-assigned replica id** (for example from the downward API). It needs
  per-replica configuration, collides silently when two replicas share a value,
  and invites identifiers that name hosts.
- **Hint in the `404` body instead of a header.** A header keeps the body of
  every miss byte-identical, so a client that compares bodies cannot tell a
  hinted miss from any other.
- **Tag always on.** It would change the #5767 contract that a reference
  embeds nothing for every operator, including single-replica deployments
  that gain nothing from it.

## Consequences

- Operator tooling resolves a tagged reference in at most two admin requests:
  any replica, then the one the hint names (or directly, by parsing the
  replica id from the reference and looking it up in the startup log or the
  `ferrum_diagnostic_ref_replica_info` series).
- A restarted replica draws a new id; references it minted before the restart
  were already lost with its memory, so the hint then names an id no process
  reports, which is the correct answer.
- Two replicas share an id with probability about `n² / 2³³` for `n` replicas.
  A collision only sends a lookup to a replica that answers the plain `404`:
  the 128-bit key never matches another replica's entry.
- Hot-path cost is unchanged apart from nine more characters per minted
  reference.
