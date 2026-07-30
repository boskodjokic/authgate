package io.github.boskodjokic.authgate.server.federation;

/**
 * A verified assertion from one external provider.
 *
 * <p>{@code issuer} and {@code subject} together identify the caller. {@code email} is advisory:
 * it is mutable at the provider and must never be the thing an account is looked up by, or two
 * providers asserting the same address become interchangeable.
 *
 * @param provider configured provider name that produced this
 * @param issuer the verified {@code iss}
 * @param subject the verified subject claim
 * @param email the asserted address, or null
 * @param emailVerified whether the provider claims to have verified that address
 */
public record Principal(String provider, String issuer, String subject, String email, boolean emailVerified) {}
