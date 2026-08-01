package io.github.boskodjokic.authgate.client;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Requires the token to name this service in {@code aud}.
 *
 * <p>This is the single most useful thing in the starter. Spring's resource server validates the
 * signature, the issuer and the expiry out of the box — but <em>not</em> the audience. A service
 * that only configures {@code issuer-uri} therefore accepts any token the issuer ever minted,
 * including one issued to a different service entirely. One compromised or merely careless
 * resource server becomes a way into all of them.
 *
 * <p>Skipping it is easy to do and invisible when you do, which is exactly why it belongs in a
 * starter rather than in everybody's copy-pasted configuration.
 */
final class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String audience;

    AudienceValidator(String audience) {
        this.audience = audience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (token.getAudience() != null && token.getAudience().contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                "invalid_token", "The token is not intended for this service (expected aud " + audience + ")", null));
    }
}
