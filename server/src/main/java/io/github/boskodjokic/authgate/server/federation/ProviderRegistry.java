package io.github.boskodjokic.authgate.server.federation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import java.io.IOException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Routes an inbound token to the one provider that could have issued it.
 *
 * <p>The obvious implementation tries each provider in turn until one accepts. That makes
 * registration order load-bearing, and makes a token from the last provider in the list pay for a
 * failed network round trip against every provider ahead of it. Reading the unverified {@code iss}
 * first picks exactly one candidate.
 *
 * <p>Trusting an unverified claim to do so is safe, because it only selects a verifier. The chosen
 * provider still checks the signature, issuer and audience against its own configuration, so a
 * forged {@code iss} merely routes the token to something guaranteed to reject it.
 */
@Component
public class ProviderRegistry {

    private static final Logger log = LoggerFactory.getLogger(ProviderRegistry.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, OidcProvider> byIssuer = new LinkedHashMap<>();

    public ProviderRegistry(AuthGateProperties properties) {
        for (FederatedProviderProperties config : properties.federation().providers()) {
            if (!config.enabled()) {
                log.info("Federated provider '{}' is configured but disabled", config.name());
                continue;
            }
            OidcProvider existing = byIssuer.put(config.issuer(), new OidcProvider(config));
            if (existing != null) {
                // Two providers claiming one issuer means dispatch would be a coin toss, and the
                // losing one's audience check would never run.
                throw new IllegalStateException("Issuer '" + config.issuer() + "' is claimed by both '"
                        + existing.config().name() + "' and '" + config.name() + "'");
            }
            log.info("Federated provider '{}' registered for issuer {}", config.name(), config.issuer());
        }
    }

    /**
     * Verifies a token with whichever provider claims its issuer.
     *
     * @throws FederationException if the token is unparseable, from an unknown issuer, or invalid
     */
    public Principal authenticate(String token) {
        String issuer = peekIssuer(token);
        if (issuer == null) {
            throw new FederationException("token is not a JWT");
        }
        OidcProvider provider = byIssuer.get(issuer);
        if (provider == null) {
            // Named explicitly: an unconfigured issuer is by far the most common cause, and a
            // generic failure sends people looking at their keys instead of their config.
            throw new FederationException("no configured provider for issuer '" + issuer + "'");
        }
        return provider.verify(token);
    }

    /** Reads {@code iss} from the unverified payload. Null when the input is not a JWT at all. */
    static String peekIssuer(String token) {
        try {
            // Limit -1 keeps trailing empty fields. An unsigned token serialises as
            // "header.payload." with an empty signature, and the one-argument split would drop
            // that field and report two parts — so an alg:none token would be turned away here as
            // "not a JWT" instead of reaching the provider that rejects it for being unsigned.
            // Same 401 either way, but the second is the one that proves the verifier works.
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) {
                return null;
            }
            Map<?, ?> payload = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
            Object issuer = payload.get("iss");
            if (issuer == null) {
                return null;
            }
            String value = issuer.toString();
            return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        } catch (IOException | RuntimeException e) {
            // Anything unparseable is simply not a token we can route. The caller turns this into
            // the same 401 as a bad signature.
            return null;
        }
    }

    boolean isEmpty() {
        return byIssuer.isEmpty();
    }
}
