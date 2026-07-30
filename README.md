# authgate

[![CI](https://github.com/boskodjokic/authgate/actions/workflows/ci.yml/badge.svg)](https://github.com/boskodjokic/authgate/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-17-blue)](https://adoptium.net/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An identity service for applications that federate sign-in to one or more OpenID Connect
providers and want passwordless email sign-in, without running a password database.

```yaml
authgate:
  providers:
    - name: google
      issuer: https://accounts.google.com
      audience: ${GOOGLE_CLIENT_ID}
    - name: okta
      issuer: https://acme.okta.com/oauth2/default
      audience: api://default
    - name: email          # magic link, no password anywhere
      type: local
```

Adding a provider is a config block. There is no per-provider code path.

**Status: phase 2.** Passwordless email sign-in works end to end, and the resulting token verifies
against the published JWKS with any conforming client. Federation to Google, Azure and Okta is
phase 3. See [Roadmap](#roadmap).

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

# {"access_token":"eyJra...","token_type":"Bearer","expires_in":900}
```

Redemption is a POST rather than a GET on the emailed URL, which is the obvious design and does
not survive contact with real mail: link scanners and inbox prefetchers fetch every URL in a
message before the recipient sees it, and a single-use token is spent by the time it is clicked.
The token rides in the fragment, which browsers never send to a server — so it also stays out of
access logs and `Referer` headers.

Tokens are stored as SHA-256 hashes. A leaked table is not a set of usable sign-in links.

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

Neither container is used yet; Postgres is wired up in phase 1 and mail in phase 2.

## Roadmap

| Phase | Deliverable | State |
|---|---|---|
| 0 | Gradle scaffold, CI, container build, dev compose | **done** |
| 1 | Schema, tenants and accounts, RS256 issuer, JWKS + discovery | **done** |
| 2 | Magic-link sign-in | **done** |
| 3 | Federation: generic OIDC, plus Google/Azure/Okta configuration | next |
| 4 | Role and permission model, admin API | |
| 5 | Refresh rotation, revocation, reuse detection | |
| 6 | `client-spring` starter and `demo` | |
| 7 | Python verifier on PyPI | |
| 8 | Documentation and a live demo deployment | |

Phases 0–3 are the ones that prove the concept end to end: sign in by email or Google, receive a
token, verify it from another service.

## License

MIT — see [LICENSE](LICENSE).
