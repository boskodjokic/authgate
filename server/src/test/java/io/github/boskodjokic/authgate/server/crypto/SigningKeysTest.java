package io.github.boskodjokic.authgate.server.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SigningKeysTest {

    /**
     * Keys are generated per test rather than checked in as a fixture. A private key in the
     * repository is a private key in every clone, every fork and every secret scanner's report,
     * and "it is only for tests" is exactly what the leaked ones always said.
     */
    private static String generatePkcs8Pem() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'})
                .encodeToString(pair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----";
    }

    private static AuthGateProperties propertiesWith(String pem) {
        return new AuthGateProperties(
                "https://auth.example.test",
                Duration.ofMinutes(15),
                new AuthGateProperties.Signing(pem),
                null,
                null,
                null);
    }

    @Test
    void generatesAnEphemeralKeyWhenNoneIsConfigured() {
        SigningKeys keys = new SigningKeys(propertiesWith(null));

        assertThat(keys.keyId()).isNotBlank();
        assertThat(keys.signingKey().isPrivate()).isTrue();
    }

    @Test
    void loadsAConfiguredPkcs8Key() throws Exception {
        String pem = generatePkcs8Pem();

        SigningKeys keys = new SigningKeys(propertiesWith(pem));

        assertThat(keys.signingKey().isPrivate()).isTrue();
        assertThat(keys.signingKey().toPublicJWK().isPrivate()).isFalse();
    }

    @Test
    void derivesTheSameKeyIdForTheSameKey() throws Exception {
        String pem = generatePkcs8Pem();

        // The kid is an RFC 7638 thumbprint, so a redeploy that reuses the key keeps the same id
        // and every cached JWKS entry stays valid. A random id would invalidate them all.
        assertThat(new SigningKeys(propertiesWith(pem)).keyId())
                .isEqualTo(new SigningKeys(propertiesWith(pem)).keyId());
    }

    @Test
    void differentKeysGetDifferentKeyIds() throws Exception {
        assertThat(new SigningKeys(propertiesWith(generatePkcs8Pem())).keyId())
                .isNotEqualTo(new SigningKeys(propertiesWith(generatePkcs8Pem())).keyId());
    }

    @Test
    void publishedJwkSetCarriesNoPrivateKeyMaterial() throws Exception {
        SigningKeys keys = new SigningKeys(propertiesWith(generatePkcs8Pem()));

        Map<String, Object> published = keys.publicJwkSet().toJSONObject();
        String serialised = published.toString();

        // The RSA private exponent and the CRT parameters. If any of these ever appear on the
        // JWKS endpoint, the service has handed out its signing key.
        assertThat(serialised).doesNotContain("\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"");
        assertThat(published).containsKey("keys");
    }

    @Test
    void publishedJwkSetAdvertisesTheSigningAlgorithm() throws Exception {
        SigningKeys keys = new SigningKeys(propertiesWith(generatePkcs8Pem()));

        assertThat(keys.publicJwkSet().getKeys().get(0).getAlgorithm().getName())
                .isEqualTo("RS256");
    }

    @Test
    void rejectsGarbagePem() {
        assertThatThrownBy(() -> new SigningKeys(propertiesWith("-----BEGIN PRIVATE KEY-----\n!!!!\n")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAWellFormedKeyOfTheWrongType() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'})
                .encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----";

        assertThatThrownBy(() -> new SigningKeys(propertiesWith(pem))).isInstanceOf(IllegalArgumentException.class);
    }
}
