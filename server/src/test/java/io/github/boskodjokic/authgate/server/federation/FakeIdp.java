package io.github.boskodjokic.authgate.server.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * A real OpenID Connect provider, in-process.
 *
 * <p>It generates an actual RSA key pair, serves an actual discovery document and JWKS over an
 * actual socket, and signs actual tokens. Nothing here is mocked, so the verifier under test does
 * the same work it would against Google — discovery, key fetch, {@code kid} selection, signature
 * check — and every negative case is a few lines rather than a fixture nobody can regenerate.
 *
 * <p>This is what makes the awkward cases testable at all. Wrong audience, wrong issuer, expired,
 * unknown key, {@code alg: none} and RSA/HMAC confusion are the attacks a token verifier exists to
 * stop, and they are exactly the ones that go untested when signing a token requires a real IdP.
 */
final class FakeIdp implements AutoCloseable {

    private final HttpServer server;
    private final RSAKey key;
    private final String issuer;

    FakeIdp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAKey unidentified = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        this.key = new RSAKey.Builder(unidentified)
                .keyID(unidentified.computeThumbprint().toString())
                .build();

        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.issuer = "http://127.0.0.1:" + server.getAddress().getPort();

        server.createContext(
                "/.well-known/openid-configuration",
                exchange -> respond(
                        exchange,
                        """
                {"issuer":"%s","jwks_uri":"%s/jwks.json",\
                "response_types_supported":["code"],"subject_types_supported":["public"],\
                "id_token_signing_alg_values_supported":["RS256"]}"""
                                .formatted(issuer, issuer)));
        server.createContext("/jwks.json", exchange -> respond(exchange, new JWKSet(key.toPublicJWK()).toString()));
        server.start();
    }

    String issuer() {
        return issuer;
    }

    String keyId() {
        return key.getKeyID();
    }

    /**
     * The encoded public key — exactly what any caller can read from the JWKS endpoint.
     *
     * <p>Exposed so the algorithm-confusion test can use it as an HMAC secret, which is the actual
     * attack: a verifier that trusts the token's {@code alg} header will treat this public value as
     * a shared secret and accept anything forged with it.
     */
    byte[] publicKeyBytes() {
        try {
            return key.toRSAPublicKey().getEncoded();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A token that should verify: correct issuer, audience, subject and expiry. */
    String validToken(String audience, String subject, String email, boolean emailVerified) {
        return sign(claims(audience, subject)
                .claim("email", email)
                .claim("email_verified", emailVerified)
                .build());
    }

    JWTClaimsSet.Builder claims(String audience, String subject) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .jwtID(UUID.randomUUID().toString());
    }

    /** Signs with this provider's real key. */
    String sign(JWTClaimsSet claims) {
        return sign(claims, key.getKeyID());
    }

    /** Signs correctly but advertises a {@code kid} the JWKS does not contain. */
    String signWithUnknownKeyId(JWTClaimsSet claims) {
        return sign(claims, "not-a-real-key-id");
    }

    private String sign(JWTClaimsSet claims, String keyId) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
