package io.github.boskodjokic.authgate.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;

/**
 * All the security configuration a consuming service needs.
 *
 * <p>Deliberately this short. The decoder, the audience check and the permission mapping all come
 * from the starter; what is left is saying which routes need a caller.
 */
@Configuration
@EnableMethodSecurity
public class DemoSecurityConfiguration {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> converter)
            throws Exception {
        return http.csrf(csrf -> csrf.disable())
                // Bearer tokens only; nothing ambient, so there is no CSRF surface to protect.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))
                .build();
    }
}
