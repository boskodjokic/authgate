package io.github.boskodjokic.authgate.server.federation;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.FederatedIdentity;
import io.github.boskodjokic.authgate.server.account.FederatedIdentityRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Federated sign-in against a real, in-process OpenID Connect provider. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class FederationExchangeTest {

    private static final String AUDIENCE = "authgate-client-id";
    private static final String SUBJECT = "provider-subject-12345";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    static final FakeIdp IDP;

    static {
        try {
            IDP = new FakeIdp();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void providerConfiguration(DynamicPropertyRegistry registry) {
        registry.add("authgate.federation.audience", () -> "http://localhost:8080");
        registry.add("authgate.federation.providers[0].name", () -> "fake");
        registry.add("authgate.federation.providers[0].issuer", IDP::issuer);
        registry.add("authgate.federation.providers[0].audience", () -> AUDIENCE);
        registry.add("authgate.federation.providers[0].tenant", () -> "acme");
        registry.add("authgate.federation.providers[0].link-by-verified-email", () -> "false");
    }

    @AfterAll
    static void stopIdp() {
        IDP.close();
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TenantRepository tenants;

    @Autowired
    private AccountRepository accounts;

    @Autowired
    private FederatedIdentityRepository identities;

    private Account account;

    @BeforeEach
    void setUp() {
        identities.deleteAll();
        accounts.deleteAll();
        tenants.deleteAll();

        Tenant acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
        account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
    }

    private void link() {
        identities.saveAndFlush(new FederatedIdentity(account, IDP.issuer(), SUBJECT));
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> exchange(String token) {
        return restTemplate.postForEntity(
                "http://localhost:" + port + "/auth/federated/exchange",
                Map.of("token", token),
                (Class<Map<String, Object>>) (Class<?>) Map.class);
    }

    // -- the happy path ---------------------------------------------------

    @Test
    void aLinkedIdentityIsExchangedForALocalToken() throws Exception {
        link();

        ResponseEntity<Map<String, Object>> response =
                exchange(IDP.validToken(AUDIENCE, SUBJECT, "bosko@example.test", true));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        SignedJWT issued = SignedJWT.parse((String) response.getBody().get("access_token"));
        // The local token names the local account, not the provider's subject: downstream services
        // should never have to know which IdP someone came through.
        assertThat(issued.getJWTClaimsSet().getSubject())
                .isEqualTo(account.getId().toString());
        assertThat(issued.getJWTClaimsSet().getIssuer()).isEqualTo("http://localhost:8080");
    }

    // -- token verification ------------------------------------------------

    @Test
    void aTokenForAnotherAudienceIsRejected() {
        link();

        // The cross-application replay case: a token the same provider minted for a different
        // client. It is correctly signed and unexpired, and accepting it would let any other app
        // in the same tenant mint sessions here.
        assertThat(exchange(IDP.validToken("some-other-client", SUBJECT, "bosko@example.test", true))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anExpiredTokenIsRejected() {
        link();
        Instant past = Instant.now().minus(Duration.ofHours(1));
        String expired = IDP.sign(IDP.claims(AUDIENCE, SUBJECT)
                .issueTime(Date.from(past))
                .expirationTime(Date.from(past.plus(Duration.ofMinutes(5))))
                .build());

        assertThat(exchange(expired).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aTokenFromAnUnconfiguredIssuerIsRejected() {
        link();
        String foreign = IDP.sign(IDP.claims(AUDIENCE, SUBJECT)
                .issuer("https://evil.example.test")
                .build());

        assertThat(exchange(foreign).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aTokenSignedWithAnUnknownKeyIsRejected() {
        link();

        assertThat(exchange(IDP.signWithUnknownKeyId(
                                IDP.claims(AUDIENCE, SUBJECT).build()))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anUnsignedTokenIsRejected() {
        link();
        // alg: none. Accepting it would mean anyone can mint any identity by typing it out.
        String unsigned = new PlainJWT(IDP.claims(AUDIENCE, SUBJECT).build()).serialize();

        assertThat(exchange(unsigned).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aTokenUsingTheProvidersPublicKeyAsAnHmacSecretIsRejected() throws Exception {
        link();
        // Algorithm confusion: re-sign with HS256, using the provider's *public* key as the
        // shared secret. A verifier that takes the algorithm from the token header will happily
        // check it and let anyone forge tokens from public information alone.
        byte[] secret = IDP.publicKeyBytes();
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(IDP.keyId()).build(),
                IDP.claims(AUDIENCE, SUBJECT).build());
        forged.sign(new MACSigner(secret));

        assertThat(exchange(forged.serialize()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aTamperedPayloadIsRejected() {
        link();
        String token = IDP.validToken(AUDIENCE, SUBJECT, "bosko@example.test", true);
        String[] parts = token.split("\\.", -1);
        String tampered = parts[0] + "."
                + java.util.Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(("{\"sub\":\"someone-else\",\"iss\":\"" + IDP.issuer() + "\"}")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + parts[2];

        assertThat(exchange(tampered).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void somethingThatIsNotAJwtIsRejected() {
        assertThat(exchange("not-a-token").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // -- account resolution ------------------------------------------------

    @Test
    void aValidTokenWithNoLinkedAccountIsRejected() {
        // Verified identity, no local account. The response is the same 401 as a bad signature:
        // saying "your token was fine but you have no account" confirms to a caller that their
        // token is genuine.
        assertThat(exchange(IDP.validToken(AUDIENCE, SUBJECT, "bosko@example.test", true))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aDeactivatedAccountIsRejected() {
        link();
        account.deactivate();
        accounts.saveAndFlush(account);

        assertThat(exchange(IDP.validToken(AUDIENCE, SUBJECT, "bosko@example.test", true))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anAccountIsReachedBySubjectRatherThanByAddress() {
        // Linked under this subject, but the provider now asserts a completely different address.
        // The account must still resolve: people change their email, and the subject is what is
        // stable.
        link();

        ResponseEntity<Map<String, Object>> response =
                exchange(IDP.validToken(AUDIENCE, SUBJECT, "changed@example.test", true));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void aMatchingAddressDoesNotSubstituteForALink() {
        // The mirror of the previous case, and the more important one: the provider asserts the
        // account's exact address but no link exists, and linking is off. Accepting this would
        // make an emailed address sufficient to reach an account.
        assertThat(exchange(IDP.validToken(AUDIENCE, "a-different-subject", "bosko@example.test", true))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(identities.findAll()).isEmpty();
    }
}
