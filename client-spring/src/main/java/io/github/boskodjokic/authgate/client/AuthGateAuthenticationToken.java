package io.github.boskodjokic.authgate.client;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * A verified caller, with {@link Identity} as the principal.
 *
 * <p>The only reason this exists is so a handler can write {@code @AuthenticationPrincipal Identity
 * caller} instead of taking a raw {@code Jwt} and digging through claims. The token itself is still
 * available via {@link #getToken()}.
 */
public class AuthGateAuthenticationToken extends JwtAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final transient Identity identity;

    AuthGateAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities, Identity identity) {
        super(jwt, authorities, identity.email());
        this.identity = identity;
    }

    @Override
    public Object getPrincipal() {
        return identity;
    }

    /** The caller, typed. */
    public Identity identity() {
        return identity;
    }
}
