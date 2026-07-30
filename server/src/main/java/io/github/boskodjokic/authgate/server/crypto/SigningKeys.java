package io.github.boskodjokic.authgate.server.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Holds the key this service signs tokens with, and publishes its public half.
 *
 * <p><strong>Why RSA and not Ed25519.</strong> The design note for this project specified Ed25519,
 * and on cryptographic merit it is the better choice — smaller keys, smaller signatures, no
 * parameter footguns. It is not the choice made here, because the property this service sells is
 * that any conforming OIDC client can verify its tokens with no bespoke code. EdDSA does not
 * clear that bar: Nimbus needs an extra Tink dependency to sign with it, a good share of OIDC
 * client libraries still reject {@code alg: EdDSA}, and every major provider a caller has already
 * integrated — Google, Microsoft, Okta — signs with RS256. Picking the more elegant algorithm
 * would trade away the interoperability that is the entire point.
 *
 * <p>The algorithm is confined to this class and advertised through discovery, so adding ES256
 * later is additive rather than a migration.
 */
@Component
public class SigningKeys {

    private static final Logger log = LoggerFactory.getLogger(SigningKeys.class);
    private static final JWSAlgorithm ALGORITHM = JWSAlgorithm.RS256;
    private static final int GENERATED_KEY_SIZE = 2048;

    private final RSAKey key;

    public SigningKeys(AuthGateProperties properties) {
        String pem = properties.signing() == null ? null : properties.signing().privateKey();
        this.key = (pem == null || pem.isBlank()) ? generate() : load(pem);
    }

    /** The algorithm this service signs with, for the discovery document. */
    public static JWSAlgorithm algorithm() {
        return ALGORITHM;
    }

    /** The full key, private half included. Never leaves the signing path. */
    public RSAKey signingKey() {
        return key;
    }

    /** Stable identifier for this key, carried in the JWS header so verifiers can select it. */
    public String keyId() {
        return key.getKeyID();
    }

    /** The public half, in the shape {@code /.well-known/jwks.json} serves. */
    public JWKSet publicJwkSet() {
        return new JWKSet(key.toPublicJWK());
    }

    private static RSAKey generate() {
        // Loud, because a generated key means every token this instance issued becomes
        // unverifiable the moment it restarts, and two instances behind a load balancer will not
        // agree on what a valid token looks like.
        log.warn("No authgate.signing.private-key configured — generating an ephemeral RSA key. "
                + "Tokens issued now will not verify after a restart, and will not verify "
                + "against any other instance. Configure a key before deploying.");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(GENERATED_KEY_SIZE);
            KeyPair pair = generator.generateKeyPair();
            return build((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key generation is unavailable on this JVM", e);
        }
    }

    private static RSAKey load(String pem) {
        byte[] der = decodePem(pem);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(der));

            // A PKCS#8 blob carries the private key only; the public half is derived from it
            // rather than asked for separately, so the two cannot drift apart in configuration.
            if (!(privateKey instanceof java.security.interfaces.RSAPrivateCrtKey crt)) {
                throw new IllegalArgumentException(
                        "authgate.signing.private-key must be a PKCS#8 RSA key that includes CRT "
                                + "parameters, so the public key can be derived from it");
            }
            RSAPublicKey publicKey = (RSAPublicKey)
                    factory.generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            return build(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("authgate.signing.private-key is not a valid PKCS#8 RSA key", e);
        }
    }

    private static byte[] decodePem(String pem) {
        String body = pem.replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("authgate.signing.private-key is not valid PEM/base64", e);
        }
    }

    private static RSAKey build(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        RSAKey unidentified = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(ALGORITHM)
                .build();
        try {
            // RFC 7638 thumbprint rather than a random id: the same key always yields the same
            // kid, so a redeploy that reuses the key does not invalidate cached JWKS entries.
            return new RSAKey.Builder(unidentified)
                    .keyID(unidentified.computeThumbprint().toString())
                    .build();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not compute a thumbprint for the signing key", e);
        }
    }
}
