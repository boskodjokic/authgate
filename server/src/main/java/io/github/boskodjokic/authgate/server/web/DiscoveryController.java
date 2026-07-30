package io.github.boskodjokic.authgate.server.web;

import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the OpenID Connect discovery document.
 *
 * <p>This is the endpoint that makes the whole design work. A client pointed at the issuer URL
 * finds the JWKS from here and can verify tokens without a line of AuthGate-specific code.
 *
 * <p>The document advertises only what is actually implemented. Endpoints appear as the phases
 * that build them land — a discovery document that promises a token endpoint before one exists
 * would send well-behaved clients straight into a 404.
 */
@RestController
public class DiscoveryController {

    private final AuthGateProperties properties;

    public DiscoveryController(AuthGateProperties properties) {
        this.properties = properties;
    }

    @GetMapping(path = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> configuration() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("issuer", properties.issuer());
        document.put("jwks_uri", properties.issuer() + "/.well-known/jwks.json");
        document.put(
                "id_token_signing_alg_values_supported",
                List.of(SigningKeys.algorithm().getName()));
        document.put("subject_types_supported", List.of("public"));
        document.put("response_types_supported", List.of("code"));
        document.put("grant_types_supported", List.of());
        document.put("scopes_supported", List.of("openid", "email"));
        document.put("claims_supported", List.of("iss", "sub", "aud", "exp", "iat", "jti", "tenant", "email"));
        return document;
    }
}
