package io.github.boskodjokic.authgate.server.federation;

/**
 * One external identity provider.
 *
 * <p>There is no per-vendor type here, and that is the point. Google, Microsoft Entra, Okta,
 * Auth0, Cognito and Keycloak all publish an OpenID Connect discovery document, so one verifier
 * driven by configuration covers every one of them. Adding a provider is a block of YAML, not a
 * branch in a chain of {@code if} statements.
 *
 * @param name identifier used in logs and errors, e.g. {@code google}
 * @param issuer the provider's {@code iss} value, and the base URL its discovery document hangs
 *     off. Inbound tokens are routed to a provider by matching this exactly.
 * @param audience the client id this service's tokens are issued to. Verified on every token —
 *     skipping it is the classic cross-application replay hole, where a token minted for another
 *     app in the same tenant is accepted here.
 * @param tenant slug of the tenant whose accounts this provider may sign in. A provider is scoped
 *     to one tenant so that configuring an IdP cannot reach accounts belonging to another.
 * @param enabled lets a provider be switched off without deleting its configuration.
 * @param subjectClaim claim holding the stable per-user identifier.
 * @param emailClaim claim holding the address. Providers disagree: Entra v1 tokens use
 *     {@code preferred_username}, most others use {@code email}.
 * @param emailVerifiedClaim claim asserting the address was verified.
 * @param linkByVerifiedEmail whether a first sign-in may attach itself to an existing account with
 *     a matching, provider-verified address. Off by default, because turning it on means trusting
 *     the provider's word about an address it does not own — anyone who can make an IdP assert
 *     {@code alice@example.com} can then reach Alice's account.
 */
public record FederatedProviderProperties(
        String name,
        String issuer,
        String audience,
        String tenant,
        Boolean enabled,
        String subjectClaim,
        String emailClaim,
        String emailVerifiedClaim,
        Boolean linkByVerifiedEmail) {

    public FederatedProviderProperties {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("authgate.federation.providers[].name must be set");
        }
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException(name + ": issuer must be set");
        }
        if (!issuer.startsWith("https://") && !issuer.startsWith("http://")) {
            throw new IllegalArgumentException(name + ": issuer must be an absolute URL, got " + issuer);
        }
        if (audience == null || audience.isBlank()) {
            throw new IllegalArgumentException(name + ": audience must be set");
        }
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException(name + ": tenant must be set");
        }
        issuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        enabled = enabled == null || enabled;
        subjectClaim = subjectClaim == null || subjectClaim.isBlank() ? "sub" : subjectClaim;
        emailClaim = emailClaim == null || emailClaim.isBlank() ? "email" : emailClaim;
        emailVerifiedClaim =
                emailVerifiedClaim == null || emailVerifiedClaim.isBlank() ? "email_verified" : emailVerifiedClaim;
        linkByVerifiedEmail = linkByVerifiedEmail != null && linkByVerifiedEmail;
    }
}
