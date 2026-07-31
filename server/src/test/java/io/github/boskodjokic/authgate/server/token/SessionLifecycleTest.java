package io.github.boskodjokic.authgate.server.token;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Rotation, reuse detection and revocation, over HTTP. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class SessionLifecycleTest {

    private static final String AUDIENCE = "http://localhost:8080";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void noBootstrap(DynamicPropertyRegistry registry) {
        registry.add("authgate.bootstrap.email", () -> "");
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
    private RefreshTokenRepository refreshTokens;

    @Autowired
    private RevokedTokenRepository revokedTokens;

    @Autowired
    private SessionService sessions;

    private Account account;

    @BeforeEach
    void setUp() {
        refreshTokens.deleteAll();
        revokedTokens.deleteAll();
        accounts.deleteAll();
        tenants.deleteAll();
        Tenant acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
        account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
    }

    private Session start() {
        return sessions.start(account, AUDIENCE);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> post(String path, Object body, String bearer) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        return restTemplate.exchange(
                "http://localhost:" + port + path, HttpMethod.POST, new HttpEntity<>(body, headers), (Class<
                                Map<String, Object>>)
                        (Class<?>) Map.class);
    }

    private ResponseEntity<Map<String, Object>> refresh(String refreshToken) {
        return post("/auth/refresh", Map.of("refresh_token", refreshToken), null);
    }

    private HttpStatus adminProbe(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        return (HttpStatus) restTemplate
                .exchange(
                        "http://localhost:" + port + "/admin/tenants",
                        HttpMethod.GET,
                        new HttpEntity<>(headers),
                        String.class)
                .getStatusCode();
    }

    // -- rotation ----------------------------------------------------------

    @Test
    void aRefreshTokenBuysANewPair() {
        Session session = start();

        ResponseEntity<Map<String, Object>> response = refresh(session.refresh());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKeys("access_token", "refresh_token", "expires_in");
        // Rotated, not returned unchanged: a refresh token that survives its own use is a
        // long-lived credential that replay detection can never notice.
        assertThat(response.getBody().get("refresh_token")).isNotEqualTo(session.refresh());
    }

    @Test
    void rotationKeepsTheTokenInTheSameFamily() {
        Session session = start();

        refresh(session.refresh());

        // One family, two members: the spent original and its replacement. The family is what
        // logout and reuse detection act on.
        assertThat(refreshTokens.findAll()).hasSize(2);
        assertThat(refreshTokens.findAll().stream()
                        .map(RefreshToken::getFamilyId)
                        .distinct())
                .hasSize(1);
    }

    @Test
    void theStoredRefreshTokenIsAHashRatherThanTheTokenItself() {
        Session session = start();

        // A leaked table must not be a set of usable sessions.
        assertThat(refreshTokens.findAll())
                .allSatisfy(token -> assertThat(token.getTokenHash()).isNotEqualTo(session.refresh()));
        assertThat(refreshTokens.findByTokenHash(SessionService.hash(session.refresh())))
                .isPresent();
    }

    // -- reuse detection ----------------------------------------------------

    @Test
    void replayingASpentRefreshTokenIsRefused() {
        Session session = start();
        refresh(session.refresh());

        assertThat(refresh(session.refresh()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void replayingASpentRefreshTokenKillsTheWholeFamily() {
        Session first = start();
        String rotated = (String) refresh(first.refresh()).getBody().get("refresh_token");

        // The stolen copy is presented. There is no way to tell the thief from the victim, so both
        // lose the session — the victim signs in again, the attacker cannot.
        refresh(first.refresh());

        assertThat(refresh(rotated).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refreshTokens.findAll())
                .allSatisfy(token -> assertThat(token.isRevoked()).isTrue());
    }

    @Test
    void oneSessionsReplayDoesNotDisturbAnother() {
        Session compromised = start();
        Session healthy = start();
        refresh(compromised.refresh());

        refresh(compromised.refresh());

        // Families are the blast radius. Signing in twice on two devices must not mean one
        // device's problem ends the other's session.
        assertThat(refresh(healthy.refresh()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void anUnknownRefreshTokenIsRefusedWithoutSideEffects() {
        Session session = start();

        assertThat(refresh("not-a-real-token").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        // A token that never existed is not evidence of a replay, so nothing may be revoked on the
        // strength of it — otherwise anyone could end a stranger's session by guessing.
        assertThat(refresh(session.refresh()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void aRefreshTokenForADeactivatedAccountIsRefused() {
        Session session = start();
        account.deactivate();
        accounts.saveAndFlush(account);

        assertThat(refresh(session.refresh()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // -- revocation ---------------------------------------------------------

    @Test
    void logoutEndsTheSession() {
        Session session = start();

        ResponseEntity<Map<String, Object>> response = post(
                "/auth/logout",
                Map.of("refresh_token", session.refresh()),
                session.access().value());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(refresh(session.refresh()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void logoutRevokesTheAccessTokenHereImmediately() {
        Session session = start();
        assertThat(adminProbe(session.access().value())).isEqualTo(HttpStatus.FORBIDDEN);

        post(
                "/auth/logout",
                Map.of("refresh_token", session.refresh()),
                session.access().value());

        // 403 before (authenticated, no permission) and 401 after (no longer authenticated at
        // all). This is the denylist working; a resource server verifying against JWKS alone
        // cannot see it, which is what the short access TTL bounds.
        assertThat(adminProbe(session.access().value())).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void logoutRequiresProvingYouHoldTheSession() {
        Session victim = start();

        // No bearer token: otherwise anyone could end anyone else's session by guessing at, or
        // stealing, a refresh token alone.
        assertThat(post("/auth/logout", Map.of("refresh_token", victim.refresh()), null)
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refresh(victim.refresh()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void aRevokedAccessTokenIsRecordedWithItsOwnExpiry() {
        Session session = start();

        post(
                "/auth/logout",
                Map.of("refresh_token", session.refresh()),
                session.access().value());

        // The expiry is kept so the row can be swept once the token would have lapsed anyway,
        // which is what stops the denylist growing without bound.
        assertThat(revokedTokens.findAll()).hasSize(1).allSatisfy(revoked -> assertThat(revoked.getExpiresAt())
                .isEqualTo(session.access().expiresAt().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)));
    }

    @Test
    void expiredDenylistEntriesCanBeSwept() {
        Session session = start();
        post(
                "/auth/logout",
                Map.of("refresh_token", session.refresh()),
                session.access().value());

        int swept = revokedTokens.deleteExpired(java.time.Instant.now().plus(java.time.Duration.ofDays(1)));

        assertThat(swept).isEqualTo(1);
        assertThat(revokedTokens.findAll()).isEmpty();
    }
}
