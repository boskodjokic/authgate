package io.github.boskodjokic.authgate.server.security;

import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import io.github.boskodjokic.authgate.server.token.AccessTokenIssuer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Protects the admin API with the service's own tokens.
 *
 * <p>AuthGate is its own first consumer here, and deliberately so: the admin API is verified by
 * Spring's standard {@code oauth2-resource-server}, reading the same {@code perms} claim any other
 * service would. If that arrangement did not work, the central claim of the project — that any
 * conforming client can consume these tokens — would be false, and this configuration is where it
 * would show.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    /** Authority granted to a superuser, checked alongside every specific permission. */
    public static final String SUPERUSER = "superuser";

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                // No cookies and no sessions: every request carries its own bearer token, which is
                // also why disabling CSRF here is safe rather than merely convenient.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        // A client that had to authenticate before it could discover how to
                        // authenticate would not be usable by any stock OIDC library.
                        .requestMatchers(HttpMethod.GET, "/.well-known/**")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health")
                        .permitAll()
                        // Spring forwards a failed request to /error. Without this, a 400 from
                        // bean validation is re-decided by the error dispatch and reaches the
                        // caller as a 401 — a misleading answer to a request that was permitted.
                        .requestMatchers("/error")
                        .permitAll()
                        // The sign-in routes are how a caller obtains a token in the first place.
                        // They defend themselves: see MagicLinkService and FederationService.
                        .requestMatchers(HttpMethod.POST, "/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }

    /**
     * Verifies our own tokens from the in-memory key rather than by fetching our own JWKS over
     * HTTP. Same validation, no round trip to ourselves, and no dependency on being able to reach
     * our own public URL from inside the container.
     */
    @Bean
    JwtDecoder jwtDecoder(SigningKeys keys, AuthGateProperties properties) {
        // One key, so the public key is handed over directly. When rotation lands and there are
        // several, this becomes a JWK source keyed by kid — the header already carries one.
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        // Issuer is checked as well as signature and expiry: a correctly signed token is not
        // automatically one we minted for this deployment.
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder;
    }

    /**
     * Turns the {@code perms} claim into authorities of the form {@code resource:action}, plus
     * {@code superuser} where the claim says so.
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();
            Map<String, Object> perms = jwt.getClaimAsMap("perms");
            if (perms != null) {
                AccessTokenIssuer.authorities(perms).stream()
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }
            if (Boolean.TRUE.equals(jwt.getClaim("superuser"))) {
                authorities.add(new SimpleGrantedAuthority(SUPERUSER));
            }
            return authorities;
        });
        return converter;
    }
}
