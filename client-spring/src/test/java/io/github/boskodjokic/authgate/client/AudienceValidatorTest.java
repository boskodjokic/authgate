package io.github.boskodjokic.authgate.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The check Spring's resource server does not do for you.
 *
 * <p>Configure only {@code issuer-uri} and a service will accept every token that issuer ever
 * minted — including one issued to a different service entirely.
 */
class AudienceValidatorTest {

    private static final String US = "https://api.example.test";

    private final AudienceValidator validator = new AudienceValidator(US);

    private static Jwt withAudience(List<String> audience) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("account-1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900));
        if (audience != null) {
            builder.audience(audience);
        }
        return builder.build();
    }

    @Test
    void acceptsATokenNamingThisService() {
        assertThat(validator.validate(withAudience(List.of(US))).hasErrors()).isFalse();
    }

    @Test
    void acceptsATokenNamingThisServiceAmongOthers() {
        assertThat(validator
                        .validate(withAudience(List.of("https://other.example.test", US)))
                        .hasErrors())
                .isFalse();
    }

    @Test
    void rejectsATokenMeantForSomebodyElse() {
        // Correctly signed by the right issuer and unexpired. The audience is the only thing that
        // makes it not ours.
        assertThat(validator
                        .validate(withAudience(List.of("https://other.example.test")))
                        .hasErrors())
                .isTrue();
    }

    @Test
    void rejectsATokenWithNoAudienceAtAll() {
        assertThat(validator.validate(withAudience(null)).hasErrors()).isTrue();
    }

    @Test
    void configurationWithoutAnAudienceIsRefusedOutright() {
        // There is no safe default here. Accepting "any" is precisely the hole this closes, so the
        // property is required rather than optional with a permissive fallback.
        assertThatThrownBy(() -> new AuthGateClientProperties("https://auth.example.test", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("audience");
    }

    @Test
    void aTrailingSlashOnTheIssuerIsNormalisedAway() {
        // Otherwise the discovery URL becomes "https://auth.example.test//.well-known/..." and the
        // iss comparison fails on a difference nobody can see.
        assertThat(new AuthGateClientProperties("https://auth.example.test/", US).issuer())
                .isEqualTo("https://auth.example.test");
    }
}
