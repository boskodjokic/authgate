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

**Status: phase 0 — scaffold only.** The service starts and reports health. None of the
behaviour described below is implemented yet. See [Roadmap](#roadmap).

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

Local tokens are signed with a server-held Ed25519 key, rotated by `kid`, and every one carries a
`jti` so revocation is immediate rather than eventual.

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
| 1 | Schema, tenants and accounts, Ed25519 issuer, JWKS + discovery | next |
| 2 | Magic-link sign-in | |
| 3 | Federation: generic OIDC, plus Google/Azure/Okta configuration | |
| 4 | Role and permission model, admin API | |
| 5 | Refresh rotation, revocation, reuse detection | |
| 6 | `client-spring` starter and `demo` | |
| 7 | Python verifier on PyPI | |
| 8 | Documentation and a live demo deployment | |

Phases 0–3 are the ones that prove the concept end to end: sign in by email or Google, receive a
token, verify it from another service.

## License

MIT — see [LICENSE](LICENSE).
