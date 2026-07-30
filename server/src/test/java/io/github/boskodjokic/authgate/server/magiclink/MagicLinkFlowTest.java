package io.github.boskodjokic.authgate.server.magiclink;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** End-to-end magic-link sign-in, over HTTP, against a real database. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class MagicLinkFlowTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    /** Captures what would have been emailed, so the test can follow the link. */
    record SentMail(String recipient, String link) {}

    @TestConfiguration
    static class RecordingMailerConfiguration {

        @Bean
        @Primary
        MagicLinkMailer recordingMailer(List<SentMail> outbox) {
            return (recipient, link) -> outbox.add(new SentMail(recipient, link));
        }

        @Bean
        List<SentMail> outbox() {
            return new CopyOnWriteArrayList<>();
        }
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private List<SentMail> outbox;

    @Autowired
    private TenantRepository tenants;

    @Autowired
    private AccountRepository accounts;

    @Autowired
    private MagicLinkRepository links;

    private Account account;

    @BeforeEach
    void setUp() {
        outbox.clear();
        links.deleteAll();
        accounts.deleteAll();
        tenants.deleteAll();

        Tenant acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
        account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private ResponseEntity<Void> requestLink(String tenant, String email) {
        return restTemplate.postForEntity(
                url("/auth/magic-link"), Map.of("tenant", tenant, "email", email), Void.class);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> redeem(String token) {
        return restTemplate.postForEntity(
                url("/auth/magic-link/redeem"), Map.of("token", token), (Class<Map<String, Object>>)
                        (Class<?>) Map.class);
    }

    private String tokenFromLastMail() {
        String link = outbox.get(outbox.size() - 1).link();
        return link.substring(link.indexOf("#token=") + "#token=".length());
    }

    @Test
    void aRequestedLinkSignsTheAccountIn() throws Exception {
        assertThat(requestLink("acme", "bosko@example.test").getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(outbox).hasSize(1);

        ResponseEntity<Map<String, Object>> response = redeem(tokenFromLastMail());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKeys("access_token", "token_type", "expires_in");
        assertThat(response.getBody().get("token_type")).isEqualTo("Bearer");

        SignedJWT jwt = SignedJWT.parse((String) response.getBody().get("access_token"));
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(account.getId().toString());
    }

    @Test
    void theLinkIsSentToTheAccountAddress() {
        requestLink("acme", "bosko@example.test");

        assertThat(outbox.get(0).recipient()).isEqualTo("bosko@example.test");
        // The token travels in the fragment, which never reaches a server and so stays out of
        // access logs and Referer headers.
        assertThat(outbox.get(0).link()).contains("#token=");
    }

    @Test
    void theAddressIsMatchedRegardlessOfCase() {
        assertThat(requestLink("acme", "BOSKO@Example.TEST").getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

        assertThat(outbox).hasSize(1);
    }

    @Test
    void aLinkCannotBeRedeemedTwice() {
        requestLink("acme", "bosko@example.test");
        String token = tokenFromLastMail();

        assertThat(redeem(token).getStatusCode()).isEqualTo(HttpStatus.OK);
        // Single-use is the whole point: a link sitting in an inbox is a credential, and an inbox
        // outlives the session it was meant to start.
        assertThat(redeem(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anExpiredLinkIsRefused() {
        links.saveAndFlush(new MagicLink(
                MagicLinkService.hash("expired-token"),
                account,
                "http://localhost:8080",
                Instant.now().minus(Duration.ofMinutes(1))));

        assertThat(redeem("expired-token").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anUnknownTokenIsRefused() {
        assertThat(redeem("not-a-real-token").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anUnknownAddressIsAcceptedButSendsNothing() {
        // Same 202 as a real address. Any other answer turns this endpoint into an oracle for
        // discovering who holds an account.
        assertThat(requestLink("acme", "stranger@example.test").getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

        assertThat(outbox).isEmpty();
    }

    @Test
    void anUnknownTenantIsAcceptedButSendsNothing() {
        assertThat(requestLink("no-such-tenant", "bosko@example.test").getStatusCode())
                .isEqualTo(HttpStatus.ACCEPTED);

        assertThat(outbox).isEmpty();
    }

    @Test
    void aDeactivatedAccountGetsNoLink() {
        account.deactivate();
        accounts.saveAndFlush(account);

        assertThat(requestLink("acme", "bosko@example.test").getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

        assertThat(outbox).isEmpty();
    }

    @Test
    void theStoredTokenIsAHashRatherThanTheTokenItself() {
        requestLink("acme", "bosko@example.test");
        String token = tokenFromLastMail();

        // A leaked table must not be a set of usable sign-in links.
        assertThat(links.findAll()).hasSize(1).allSatisfy(link -> assertThat(link.getTokenHash())
                .isNotEqualTo(token)
                .doesNotContain(token));
        assertThat(links.findByTokenHash(MagicLinkService.hash(token))).isPresent();
    }

    @Test
    void aMalformedRequestIsRejected() {
        ResponseEntity<Void> response = restTemplate.postForEntity(
                url("/auth/magic-link"), Map.of("tenant", "acme", "email", "not-an-address"), Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
