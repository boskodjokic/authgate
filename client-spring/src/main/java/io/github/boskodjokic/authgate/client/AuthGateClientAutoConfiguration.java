package io.github.boskodjokic.authgate.client;

import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Configures a Spring resource server to accept AuthGate tokens.
 *
 * <p>Worth being plain about what this is and is not. Spring already verifies an AuthGate token
 * with nothing more than {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} — that is the
 * whole point of AuthGate publishing standard discovery and JWKS, and this starter is a
 * convenience, not a requirement.
 *
 * <p>What it adds is the two things a hand-written configuration usually gets wrong:
 *
 * <ul>
 *   <li><strong>Audience validation.</strong> Spring does not check {@code aud}. Without it, a
 *       service accepts every token the issuer ever minted, including ones meant for someone else.
 *   <li><strong>The permission model.</strong> Turning the {@code perms} claim into authorities so
 *       {@code @PreAuthorize("hasAuthority('material:update')")} works, and exposing a typed
 *       {@link Identity} rather than a claim map.
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthGateClientProperties.class)
public class AuthGateClientAutoConfiguration {

    /**
     * Reads AuthGate's discovery document to find its JWKS, then validates signature, issuer,
     * expiry and audience.
     */
    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    public JwtDecoder authGateJwtDecoder(AuthGateClientProperties properties) {
        NimbusJwtDecoder decoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(properties.issuer());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()),
                new AudienceValidator(properties.audience())));
        return decoder;
    }

    /** Turns a verified token into an authenticated caller carrying a typed {@link Identity}. */
    @Bean
    @ConditionalOnMissingBean(name = "authGateAuthenticationConverter")
    public Converter<Jwt, AbstractAuthenticationToken> authGateAuthenticationConverter() {
        return jwt -> {
            Identity identity = Identity.of(jwt);
            List<SimpleGrantedAuthority> authorities = identity.authorities().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList();
            return new AuthGateAuthenticationToken(jwt, authorities, identity);
        };
    }
}
