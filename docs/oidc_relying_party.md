# OIDC Relying Party

Ferrum Edge can act as an OpenID Connect relying party for browser-facing routes with the `oidc_relying_party` plugin. The plugin starts an authorization-code flow with PKCE, validates the returned ID token against provider JWKS, creates an encrypted gateway session cookie, optionally enriches claims from UserInfo, and can fan selected claims out to upstream request headers. The session uses a sliding idle window and, when a refresh token is available, transparently refreshes the access/ID tokens before they expire.

## Minimal Configuration

```yaml
plugin_name: oidc_relying_party
config:
  providers:
    - issuer: "https://idp.example.com/"
      discovery_url: "https://idp.example.com/.well-known/openid-configuration"
      client_id: ferrum-edge
      redirect_uri: "https://edge.example.com/oidc/callback"
      client_auth:
        method: client_secret_basic
        client_secret: "${OIDC_CLIENT_SECRET}"
      audiences: ["ferrum-edge"]
      claim_headers:
        email: X-Authenticated-Email
  session:
    encryption_secret: "${OIDC_SESSION_SECRET_32_BYTES_MIN}"
  behavior:
    post_login_default_path: "/"
```

Exactly one provider is supported. Use `discovery_url` for normal OIDC providers, or set `authorization_endpoint`, `token_endpoint`, and `jwks_uri` explicitly for providers without discovery. Provider endpoints must use HTTPS except for `localhost` or literal loopback development endpoints. Discovery-provided endpoints must preserve the discovery URL's host, scheme, and effective port.

## Security Behavior

- `redirect_uri` must be an absolute URI and the callback path is handled by the plugin before proxying. Before starting a browser flow, Ferrum requires the request `Host`/`:authority` to identify the same host as `redirect_uri`; DNS names compare case-insensitively, IP literals compare by address, and ports are ignored because cookies are not port-scoped. Trailing-dot DNS callback hosts, missing or malformed request authorities, and different hosts are rejected before state, cookies, or an authorization redirect are issued. In particular, a request on `app.example.com` cannot use a callback on `auth.example.com`; route the initial login through the callback host or configure a same-host callback instead. Forwarded-host headers do not override the request authority for this check.
- The ID token issuer, audience, expiry, not-before, and nonce are validated.
- ID token signature verification is bound to the header `kid`; a missing, empty, or unknown `kid` fails closed with no all-keys fallback. An unknown non-empty `kid` additionally triggers at most one out-of-band JWKS fetch per cooldown window (the shared JWKS store's `kid_miss_refresh_cooldown_seconds`, 30 s by default), so an identity-provider key rotation recovers without waiting out the refresh interval. The triggering request still fails closed; a later request verifies once the refreshed key set is published. This plugin has no cooldown field of its own — it consumes the process-wide JWKS store `jwks_auth` uses.
- ID tokens require a non-empty `sub`; multi-audience tokens require `azp` to identify the configured client. UserInfo must carry the same `sub` before any UserInfo claim is consumed.
- Sessions are sealed with AES-256-GCM and cryptographically bound to a versioned provider/client/audience/policy context. `session.encryption_secret` must be at least 32 bytes; `session.encryption_secret_previous` supports cookie rotation within the same context.
- When `session.cookie_name` is omitted, Ferrum derives a context-specific name so differently configured relying parties on one host do not reuse a default cookie.
- `session.store` supports only `cookie`; Redis-backed server-side sessions are rejected until implemented.
- Browser authorization-code flows are sealed into a distinct short-lived, host-only HttpOnly/SameSite correlation cookie with AES-256-GCM under the same `session.encryption_secret` (and optional `encryption_secret_previous`) as sessions, but with a distinct associated-data label so session cookies cannot be reused as pending-flow state. The OAuth `state` query parameter stays an opaque handle that selects the cookie name; PKCE verifier, nonce, original redirect, expiry, and context binding live only in the sealed cookie — never in URLs, logs, or unsealed cookie values. `session.domain` applies only to the durable session cookie and is never applied to this pending-flow cookie. Correlation cookies follow `session.secure` (secure by default; set it to `false` only for allowed localhost or literal-loopback HTTP development callbacks). Sealed pending-flow cookies honor `session.max_cookie_bytes`; oversized, expired, wrong-context, wrong-browser, tampered, or otherwise invalid state fails closed.
- Pending-flow **admission** (DoS bounds) remains process-local per plugin instance via `behavior.state_cache_max_entries` (default `10000`) and `behavior.state_cache_max_entries_per_source` (default `32`). Those caps limit how many logins an instance will *start*; they do not need to be shared across replicas for a callback to succeed. Same-instance callback replay is rejected after the sealed state is first accepted on that instance; cross-replica completion relies on the sealed cookie plus the provider's one-time authorization code.
- `behavior.trusted_redirect_hosts` gates post-login redirects. If no trusted redirect is available, the plugin uses `behavior.post_login_default_path`.
- UserInfo `sub` must match the ID token `sub`, and UserInfo cannot override protected ID token claims.
- Claim header mappings reject reserved headers, including `Authorization`, `Host`, hop-by-hop headers, and Ferrum consumer identity headers.

## Multi-replica deployments

Fresh logins work behind non-sticky load balancers when every Ferrum replica shares the same `oidc_relying_party` configuration and `session.encryption_secret` (plus `encryption_secret_previous` during rotation). The durable session cookie was already replica-safe; pending authorization-code state is now likewise carried in the sealed correlation cookie, so an `/oidc`/`/oauth` callback may land on a different replica than the one that issued the challenge. Sticky sessions are not required for login completion. Keep encryption secrets identical across the fleet; a replica with the wrong secret or a different provider/session context rejects sealed pending-flow cookies and fails closed.

Token refresh is the one place the cookie store's replica independence still shows. Refresh coalescing (see [Concurrent refreshes and spent refresh tokens](#concurrent-refreshes-and-spent-refresh-tokens)) is per instance: two replicas that both receive the same refresh-due cookie both submit the refresh token, and with a rotating provider only one can win. No replica can hand another the winner's tokens without a shared server-side session store, so the loser's contract is what protects the browser: it sees `invalid_grant`, emits no `Set-Cookie`, and does not re-submit that generation for `25` seconds. The browser keeps the winner's rotated cookie, and the only cost is one rejected grant per additional replica per generation. Providers that revoke the whole token family on detected reuse ([RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2)) can still invalidate the winner in that case; routing requests for one session cookie to one replica (cookie-based affinity on the session cookie name) removes the duplicate submission entirely and is recommended with such providers.

## Session Lifetime and Token Refresh

The gateway session has two bounds, both enforced on every request:

- **Absolute lifetime** — `session.ttl_secs` (default `3600`) measured from login. A session is never valid past this, regardless of activity.
- **Idle timeout** — `session.idle_ttl_secs` (default `1800`) of inactivity. This is a *sliding* window: each request advances the session's last-touch time, so an actively used session stays valid until the absolute lifetime. To keep the per-request cost and `Set-Cookie` churn low, the cookie is re-issued at most about twice per idle window (once more than half of `idle_ttl_secs` has elapsed since the last update), not on every request.

When the provider issues a refresh token (typically by adding the `offline_access` scope), the plugin proactively refreshes the tokens `behavior.refresh_skew_secs` (default `30`) before the earlier of the access-token expiry and the stored ID-token/UserInfo claims expiry:

- A new access token, a rotated refresh token, and an optional new ID token are accepted. A returned ID token is re-validated against the provider JWKS and must bind to the same subject; if it carries a `nonce` it must match the original login.
- On success, refreshed claims drive scope/role checks and claim-header fan-out, and the session cookie is re-issued. If the provider refreshes only the access token, the previous claims remain usable only until their stored claims expiry.
- Refresh is best-effort while the stored claims are still fresh. If the token endpoint remains unavailable or the provider omits fresh claims until the stored claims pass expiry plus clock skew, the plugin fails closed and re-challenges instead of serving stale authorization claims.

Both a sliding update and a refresh re-issue the session cookie on the proxied response via `Set-Cookie`, preserving any cookie the backend also set.

### Concurrent refreshes and spent refresh tokens

A browser routinely sends several requests carrying the same refresh-due cookie at once (parallel tabs, a page plus its asset fetches). Providers that rotate refresh tokens accept the token exactly once, so each such burst must submit it exactly once:

- **Single-flight per token generation.** Within one Ferrum instance, every request whose cookie carries the same refresh token joins one refresh transition, keyed by a SHA-256 digest of that token (the registry never holds the raw credential). The first request runs the grant; the others wait for its outcome without any lock and receive the winner's session state, so each of them re-issues the rotated cookie. A completed transition stays addressable for `25` seconds, so a request that decrypted the old cookie just before the winner finished, or a tab that still carries it, adopts the rotation instead of re-submitting the spent token. The retained registry is bounded (4096 completed records per instance, oldest evicted first); live transitions are never evicted. Requests whose cookie is not due never touch the registry.
- **`invalid_grant` re-seals nothing.** When the token endpoint answers `invalid_grant` (RFC 6749 §5.2: the token is spent, revoked, or expired), the request is still served while its stored claims are fresh, but it emits **no** `Set-Cookie`. The browser therefore keeps whatever cookie it holds — the rotated session whenever a winner exists anywhere in the fleet — rather than being handed the spent credential again. The instance records the spent identity for `25` seconds, so repeat requests with the same stale cookie are not re-submitted either. Once the stored claims expire, the freshness gate re-challenges as usual.
- **Transient failures keep the token.** A transport error, non-2xx without `invalid_grant`, or malformed response leaves the token live; the unchanged payload is re-sealed with the next attempt deferred by `30` seconds, and every request sharing the transition carries that same backoff.
- A follower whose leader is cancelled (client disconnect) re-elects exactly one replacement; one that outlives the leader's wait bound serves without a session update and never issues a duplicate grant.

## Client Authentication

Supported `client_auth.method` values are:

| Method | Notes |
|---|---|
| `client_secret_basic` | Sends the client secret with HTTP Basic auth |
| `client_secret_post` | Sends client credentials in the token request body |
| `private_key_jwt` | Signs a client assertion with RSA, EC, or EdDSA keys (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `EdDSA`) |
| `none` | Public client mode, allowed only for localhost or loopback token endpoints |

## Logout

Requests to `providers[].logout_path` clear the local session. When the provider exposes an end-session endpoint and `behavior.rp_initiated_logout` is true, the plugin redirects to the provider logout endpoint with `post_logout_redirect_uri` when configured.

## Related Plugins

Use `oauth2_introspection` for API requests that already carry bearer access tokens and do not need a browser login flow. Use `jwks_auth` for self-contained JWT access tokens where local signature verification is enough.
