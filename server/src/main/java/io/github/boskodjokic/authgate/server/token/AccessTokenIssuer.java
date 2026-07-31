package io.github.boskodjokic.authgate.server.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.PermissionEntry;
import io.github.boskodjokic.authgate.server.account.Role;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** Mints access tokens. The only place in the service that holds a signature-producing key. */
@Service
public class AccessTokenIssuer {

    private final AuthGateProperties properties;
    private final SigningKeys keys;

    public AccessTokenIssuer(AuthGateProperties properties, SigningKeys keys) {
        this.properties = properties;
        this.keys = keys;
    }

    /**
     * Issue an access token for an account.
     *
     * @param account the subject of the token; must be active
     * @param audience the API the token is meant for, carried in {@code aud}
     * @return the signed token and the moment it expires
     */
    public IssuedToken issue(Account account, String audience) {
        if (!account.isActive()) {
            throw new IllegalArgumentException("cannot issue a token for a deactivated account");
        }
        if (audience == null || audience.isBlank()) {
            // An access token without an audience is valid at every service that trusts this
            // issuer, which turns one compromised resource server into all of them.
            throw new IllegalArgumentException("audience must not be blank");
        }

        Instant now = Instant.now();
        Instant expiry = now.plus(properties.accessTokenTtl());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .subject(account.getId().toString())
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiry))
                // Every token gets an id so that revocation can name one. Without it the only
                // way to withdraw a token is to wait for it to expire.
                .jwtID(UUID.randomUUID().toString())
                .claim("tenant", account.getTenant().getId().toString())
                .claim("email", account.getEmail())
                // Permissions travel inside the token so a verifier needs no callback here. The
                // cost is staleness: a revoked role stays effective until the token expires, which
                // is why the default TTL is minutes rather than hours.
                .claim("perms", permissionsOf(account))
                .claim("superuser", account.isSuperuser())
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(SigningKeys.algorithm())
                        .keyID(keys.keyId())
                        .build(),
                claims);

        try {
            jwt.sign(new RSASSASigner(keys.signingKey()));
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not sign an access token", e);
        }

        return new IssuedToken(jwt.serialize(), expiry);
    }

    /**
     * Flattens every role's grants into {@code {resource: [actions]}}.
     *
     * <p>Sorted, and de-duplicated by construction, so two accounts with the same effective policy
     * produce byte-identical claims. That makes a token diffable in a bug report instead of
     * depending on whatever order the database happened to return roles in.
     */
    private static Map<String, Set<String>> permissionsOf(Account account) {
        Map<String, Set<String>> permissions = new TreeMap<>();
        for (Role role : account.getRoles()) {
            for (PermissionEntry entry : role.getPermissions()) {
                permissions
                        .computeIfAbsent(entry.getResource(), resource -> new TreeSet<>())
                        .add(entry.getAction());
            }
        }
        return permissions;
    }

    /** The authority strings a verifier derives from a {@code perms} claim. */
    public static List<String> authorities(Map<String, ?> perms) {
        return perms.entrySet().stream()
                .flatMap(entry -> ((java.util.Collection<?>) entry.getValue())
                        .stream().map(action -> entry.getKey() + ":" + action))
                .toList();
    }
}
