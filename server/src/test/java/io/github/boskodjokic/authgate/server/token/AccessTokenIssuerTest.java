package io.github.boskodjokic.authgate.server.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * These tests verify tokens the way a client would: parse the compact form, then check the
 * signature against the <em>public</em> JWK from the JWKS endpoint. Asserting on the claim set the
 * issuer built would only prove it can read its own variables back.
 */
class AccessTokenIssuerTest {

    private static final String ISSUER = "https://auth.example.test";
    private static final String AUDIENCE = "https://api.example.test";

    private SigningKeys keys;
    private AccessTokenIssuer issuer;
    private Account account;

    @BeforeEach
    void setUp() {
        AuthGateProperties properties = new AuthGateProperties(
                ISSUER, Duration.ofMinutes(15), new AuthGateProperties.Signing(null), null, null, null);
        keys = new SigningKeys(properties);
        issuer = new AccessTokenIssuer(properties, keys);
        account = new Account(new Tenant("acme", "Acme"), "Bosko@Example.test", "Bosko");
    }

    private JWTClaimsSet verifyAndParse(IssuedToken token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token.value());
        RSAKey publicKey = (RSAKey) keys.publicJwkSet().getKeys().get(0);

        assertThat(jwt.verify(new RSASSAVerifier(publicKey))).isTrue();
        return jwt.getJWTClaimsSet();
    }

    @Test
    void issuesATokenThatVerifiesAgainstThePublishedPublicKey() throws Exception {
        JWTClaimsSet claims = verifyAndParse(issuer.issue(account, AUDIENCE));

        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getSubject()).isEqualTo(account.getId().toString());
        assertThat(claims.getAudience()).containsExactly(AUDIENCE);
    }

    @Test
    void namesTheKeyItSignedWith() throws Exception {
        SignedJWT jwt = SignedJWT.parse(issuer.issue(account, AUDIENCE).value());

        // Without a kid a verifier holding more than one key has to try each in turn, and cannot
        // tell a rotated-away key from a forged one.
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(keys.keyId());
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    }

    @Test
    void carriesTenantAndEmailClaims() throws Exception {
        JWTClaimsSet claims = verifyAndParse(issuer.issue(account, AUDIENCE));

        assertThat(claims.getStringClaim("tenant"))
                .isEqualTo(account.getTenant().getId().toString());
        // Normalised on the way into the account, so the claim is lowercase even though the
        // account was created with mixed case.
        assertThat(claims.getStringClaim("email")).isEqualTo("bosko@example.test");
    }

    @Test
    void expiresAfterTheConfiguredTtl() throws Exception {
        Instant before = Instant.now();

        IssuedToken token = issuer.issue(account, AUDIENCE);
        JWTClaimsSet claims = verifyAndParse(token);

        Date expiry = claims.getExpirationTime();
        assertThat(expiry).isCloseTo(Date.from(before.plus(Duration.ofMinutes(15))), 5_000);
        assertThat(token.expiresAt()).isCloseTo(expiry.toInstant(), within(1, ChronoUnit.SECONDS));
    }

    @Test
    void givesEveryTokenADistinctId() throws Exception {
        // The jti is what a denylist names. Two tokens sharing one would mean revoking either
        // revokes both, and revoking a reused id revokes an unrelated session.
        String first = verifyAndParse(issuer.issue(account, AUDIENCE)).getJWTID();
        String second = verifyAndParse(issuer.issue(account, AUDIENCE)).getJWTID();

        assertThat(first).isNotBlank().isNotEqualTo(second);
    }

    @Test
    void refusesToIssueWithoutAnAudience() {
        assertThatThrownBy(() -> issuer.issue(account, "  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("audience");
    }

    @Test
    void refusesToIssueForADeactivatedAccount() {
        account.deactivate();

        assertThatThrownBy(() -> issuer.issue(account, AUDIENCE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("deactivated");
    }

    @Test
    void doesNotVerifyAgainstADifferentKey() throws Exception {
        SigningKeys other = new SigningKeys(new AuthGateProperties(
                ISSUER, Duration.ofMinutes(15), new AuthGateProperties.Signing(null), null, null, null));
        SignedJWT jwt = SignedJWT.parse(issuer.issue(account, AUDIENCE).value());

        assertThat(jwt.verify(new RSASSAVerifier(
                        (RSAKey) other.publicJwkSet().getKeys().get(0))))
                .isFalse();
    }
}
