package io.github.boskodjokic.authgate.server.web;

import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the public half of the signing key.
 *
 * <p>This endpoint is what makes AuthGate consumable by clients that know nothing about it: a
 * verifier reads the {@code kid} from a token header and fetches the matching key from here.
 */
@RestController
public class JwksController {

    private final SigningKeys keys;

    public JwksController(SigningKeys keys) {
        this.keys = keys;
    }

    @GetMapping(path = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        // toJSONObject() on the public set — never the private one. Nimbus will happily serialise
        // private parameters if handed a key that has them, so the narrowing to public JWKs
        // happens in SigningKeys and this method has no key material to leak.
        return ResponseEntity.ok()
                // Verifiers cache by kid and refetch on a miss. A modest max-age keeps a rotation
                // from taking effect only after a client restart, without inviting a fetch per
                // request.
                .cacheControl(
                        CacheControl.maxAge(java.time.Duration.ofMinutes(5)).cachePublic())
                .body(keys.publicJwkSet().toJSONObject());
    }
}
