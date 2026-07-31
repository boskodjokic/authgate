# authgate

[![CI](https://github.com/boskodjokic/authgate/actions/workflows/ci.yml/badge.svg)](https://github.com/boskodjokic/authgate/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-17-blue)](https://adoptium.net/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An identity service for applications that federate sign-in to one or more OpenID Connect
providers and want passwordless email sign-in, without running a password database.

```yaml
authgate:
  federation:
    audience: https://api.example.com
    providers:
      - name: google
        issuer: https://accounts.google.com
        audience: ${GOOGLE_CLIENT_ID}
        tenant: acme
      - name: okta
        issuer: https://acme.okta.com/oauth2/default
        audience: api://default
        tenant: acme
  magic-link:                # passwordless email, no password anywhere
    ttl: 10m
```

Adding a provider is a config block. There is no per-provider code path.

**Status: phase 5.** Both sign-in paths work end to end, tokens carry a permission set, sessions
renew by rotating refresh tokens with reuse detection, and logout withdraws them. What remains is
packaging: client libraries, docs and a live demo. See [Roadmap](#roadmap).

## Federated sign-in

The client signs in with the provider using that provider's own SDK, then exchanges the resulting
ID token:

```bash
curl -X POST localhost:8080/auth/federated/exchange \
  -H 'content-type: application/json' \
  -d '{"token":"<ID token from Google, Entra, Okta, ...>"}'
```

Inbound tokens are routed by their `iss` claim to exactly one verifier, rather than tried against
each provider in turn. Reading an unverified claim to do so is safe because it only *selects* a
verifier — the chosen provider still checks signature, issuer and audience against its own pinned
configuration, so a forged `iss` merely routes the token to something certain to reject it.

An account is reached by `(issuer, subject)`. Never by email: an address is mutable, and it is
asserted by whichever provider answered, so matching on it would let any provider that can claim an
address reach an account created through a different one.

## Signing in

```bash
# 1. Ask for a link. Always 202 — answering otherwise would let anyone
#    discover who holds an account, one address at a time.
curl -X POST localhost:8080/auth/magic-link \
  -H 'content-type: application/json' \
  -d '{"tenant":"acme","email":"you@example.com"}'

# 2. Open the emailed link. It carries the token in the URL fragment and
#    posts it back:
curl -X POST localhost:8080/auth/magic-link/redeem \
  -H 'content-type: application/json' \
  -d '{"token":"<from the link fragment>"}'

# {"access_token":"eyJra...","refresh_token":"y3VMRJ...","token_type":"Bearer","expires_in":900}
```

Step 2 is what the page at `/signin/` does, and `authgate.magic-link.redirect-base` points there by
default so the flow works from a fresh checkout. It is deliberately about fifty lines of plain HTML
and vanilla JavaScript — the reference implementation of the redemption step, meant to be read and
replaced by your own application's page rather than depended on.

The page is served under a Content-Security-Policy that permits no inline script, which is why its
JavaScript and CSS live in separate files. This origin also serves the identity service, so an
injected script here would be a compromise of identity rather than a defacement.

Redemption is a POST rather than a GET on the emailed URL, which is the obvious design and does
not survive contact with real mail: link scanners and inbox prefetchers fetch every URL in a
message before the recipient sees it, and a single-use token is spent by the time it is clicked.
The token rides in the fragment, which browsers never send to a server — so it also stays out of
access logs and `Referer` headers.

Tokens are stored as SHA-256 hashes. A leaked table is not a set of usable sign-in links.

## Sessions

Sign-in returns an access token and a refresh token. The access token is short-lived and
self-contained; the refresh token is long-lived, single-use, and rotated on every renewal.

```bash
curl -X POST localhost:8080/auth/refresh \
  -H 'content-type: application/json' \
  -d '{"refresh_token":"y3VMRJ..."}'
```

**Reuse detection.** Presenting a refresh token that has already been spent means two parties hold
it — whoever legitimately rotated it, and whoever copied it. Nothing in the request distinguishes
them, so the whole token family is withdrawn: the attacker's session ends, and so does the victim's.
The victim signs in again; the attacker cannot. Families are per sign-in, so one compromised device
does not end a session on another.

**Logout** withdraws the refresh family and denylists the access token presented with it. Note the
limit honestly: the denylist is enforced *here*. A resource server verifying against the published
JWKS — the entire point of the design — cannot see it, so an access token already in the wild stays
valid there until it expires. The short access TTL is what bounds that window, and revocation is
authoritative where it matters, at the refresh boundary, where no replacement can be obtained. This
is how every JWT-issuing provider behaves.

## Permissions

A permission is a `(resource, action)` pair — the two axes an application already thinks in. Roles
bundle them, accounts hold roles, and the effective set travels inside the access token:

```json
{ "sub": "…", "tenant": "…", "perms": { "material": ["read", "update"] }, "superuser": false }
```

A resource server therefore answers "may this caller update a material?" without a callback here.
The cost is staleness — a withdrawn role stays effective until the token expires — which is why the
default TTL is minutes and why phase 5 adds revocation.

AuthGate is its own first consumer: the admin API is guarded by Spring's stock
`oauth2-resource-server` reading that same claim. If a conforming client could not consume these
tokens, that configuration is where it would break.

```java
@PreAuthorize("hasAnyAuthority('superuser', 'material:update')")
```

### Bootstrapping

Every admin route needs a permission, permissions come from an account, and accounts are created
through the admin API. `authgate.bootstrap.email` breaks the cycle by creating one superuser — and
only on a database with no accounts at all, so removing that account cannot silently recreate it.

It is not a credential. The bootstrap account signs in by magic link like anyone else, so the value
is an address and is harmless in a deployment manifest.

## Why

Most applications that need enterprise SSO end up with one of two things: a hand-rolled chain of
`if (azureToken) … else if (googleToken) …` that grows a branch per customer, or a full Keycloak
deployment that is far more machine than the problem called for.

The hand-rolled version has a predictable set of defects, and they are the reason this project
exists:

- the signing key is symmetric and stored next to the user record, so read access to the database
  is forgery access to every account at once
- identity is keyed on email address, which is mutable and asserted by whichever provider
  answered — two IdPs asserting the same address become interchangeable
- tokens carry no id, so there is no way to revoke one; deactivating a user means waiting for
  expiry
- providers are tried in sequence, so ordering silently becomes load-bearing and a token from the
  last provider in the chain pays for every failure ahead of it

AuthGate fixes each of those by construction rather than by convention.

## Design

The service publishes a standards-compliant `/.well-known/openid-configuration` and
`/.well-known/jwks.json`.

That is the whole integration story: **any conforming OIDC client already speaks AuthGate.**
Spring's `oauth2-resource-server`, Python, Node, Go — all of them verify AuthGate tokens with no
bespoke SDK. The client libraries in this repository are conveniences, not requirements.

Inbound tokens are routed by their `iss` claim to exactly one verifier, which then validates
signature, issuer and audience against its own pinned configuration. Peeking at an unverified
claim is safe precisely because it only chooses a verifier — a forged `iss` routes the token to a
provider that will reject it.

Local tokens are signed with a server-held RSA key, identified by an RFC 7638 thumbprint so a
redeploy that reuses the key keeps every cached JWKS entry valid. Every token carries a `jti`, so
revocation can name one rather than waiting for expiry.

RS256 is a deliberate choice over Ed25519, which is the better algorithm on merit. Interoperability
is the property this service sells, and EdDSA does not clear that bar: a good share of OIDC client
libraries still reject it, and every major provider a caller has already integrated signs with
RS256. The algorithm is confined to one class and advertised through discovery, so adding ES256
later is additive rather than a migration.

## Modules

| Module | What it is |
|---|---|
| `server` | the identity service — deployable, published as a container image |
| `client-spring` | resource-server starter for Java consumers *(phase 6)* |
| `demo` | a sample protected API using `client-spring` *(phase 6)* |

A thin Python verifier ships separately as [`authgate` on PyPI](https://pypi.org/project/authgate/)
*(phase 7)*.

## Build

```bash
./gradlew build
```

Java 17, Gradle wrapper included. Local development dependencies — Postgres and a mail catcher —
come up with:

```bash
docker compose up -d
```

Postgres is required. The mail catcher — [Mailpit](https://mailpit.axllent.org/) — receives
sign-in links in development, with a web UI at http://localhost:8025; point the service at it with
`--spring.mail.host=localhost --spring.mail.port=1025`. Without a mail host configured the service
writes links to its own log instead, and says so on every use.

## Roadmap

| Phase | Deliverable | State |
|---|---|---|
| 0 | Gradle scaffold, CI, container build, dev compose | **done** |
| 1 | Schema, tenants and accounts, RS256 issuer, JWKS + discovery | **done** |
| 2 | Magic-link sign-in | **done** |
| 3 | Federation: generic OIDC, plus Google/Azure/Okta configuration | **done** |
| 4 | Role and permission model, admin API | **done** |
| 5 | Refresh rotation, revocation, reuse detection | **done** |
| 6 | `client-spring` starter and `demo` | next |
| 7 | Python verifier on PyPI | |
| 8 | Documentation and a live demo deployment | |

Phases 0–4 prove the concept end to end: sign in by email or Google, receive a token carrying your
permissions, and have another service verify it with a stock OIDC library.

## License

MIT — see [LICENSE](LICENSE).
