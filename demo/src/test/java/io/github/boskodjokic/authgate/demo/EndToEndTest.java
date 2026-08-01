package io.github.boskodjokic.authgate.demo;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.boskodjokic.authgate.server.AuthGateApplication;
import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.PermissionEntry;
import io.github.boskodjokic.authgate.server.account.Role;
import io.github.boskodjokic.authgate.server.account.RoleRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import io.github.boskodjokic.authgate.server.token.SessionService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Two services, two processes' worth of Spring context, one token.
 *
 * <p>This is the test the whole project exists to make pass. AuthGate issues a token; the demo
 * service — which shares no database, no session store and no code with it beyond the starter —
 * verifies that token by reading the published JWKS, and enforces the permissions inside it.
 *
 * <p>Nothing is stubbed. If AuthGate's discovery document, its JWKS, its claim shape or its
 * signature handling were wrong in any way that mattered to a real consumer, this fails.
 */
@Testcontainers(disabledWithoutDocker = true)
class EndToEndTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static ConfigurableApplicationContext authgate;
    private static ConfigurableApplicationContext demo;
    private static String issuer;
    private static int demoPort;

    private static final TestRestTemplate REST = new TestRestTemplate();

    /**
     * The issuer has to be known before AuthGate starts, because it goes into every token's
     * {@code iss} claim and the demo compares that to its own configuration exactly. So the port is
     * chosen first rather than assigned by the server.
     */
    private static int freePort() {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("could not find a free port", e);
        }
    }

    @BeforeAll
    static void startBothServices() {
        POSTGRES.start();

        int authgatePort = freePort();
        issuer = "http://localhost:" + authgatePort;

        // AuthGate's own application.yml is on this classpath but never read: the demo's
        // application.yml sits at the same classpath:/application.yml, and only one can win. That
        // is the price of putting a whole service on a test classpath, so its configuration is
        // stated here rather than inherited by luck.
        //
        // Passed as command-line arguments, not via builder.properties(): that sets *default*
        // properties, the lowest-precedence source of all, which an application.yml silently
        // overrides. Arguments outrank both.
        authgate = new SpringApplicationBuilder(AuthGateApplication.class)
                .run(
                        "--server.port=" + authgatePort,
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--spring.jpa.hibernate.ddl-auto=validate",
                        "--spring.flyway.enabled=true",
                        "--authgate.issuer=" + issuer,
                        "--authgate.access-token-ttl=15m",
                        "--authgate.refresh-token-ttl=30d",
                        "--authgate.bootstrap.email=");

        // The demo has no database and wants none. JPA is on this classpath only because the whole
        // AuthGate service is embedded here for the test, and Spring would otherwise autoconfigure
        // a datasource for the demo and fail for want of a URL. Excluding it keeps the demo in the
        // test exactly what it is in production: a service that holds no data of its own.
        demo = new SpringApplicationBuilder(DemoApplication.class)
                .run(
                        "--server.port=0",
                        "--spring.autoconfigure.exclude="
                                + "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                                + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                                + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration",
                        "--authgate.client.issuer=" + issuer,
                        "--authgate.client.audience=" + issuer);
        demoPort = Integer.parseInt(demo.getEnvironment().getProperty("local.server.port", "0"));
    }

    @AfterAll
    static void stopBothServices() {
        if (demo != null) {
            demo.close();
        }
        if (authgate != null) {
            authgate.close();
        }
    }

    private Account account;

    @BeforeEach
    void seedAnAccount() {
        TenantRepository tenants = authgate.getBean(TenantRepository.class);
        AccountRepository accounts = authgate.getBean(AccountRepository.class);
        RoleRepository roles = authgate.getBean(RoleRepository.class);

        accounts.deleteAll();
        roles.deleteAll();
        tenants.deleteAll();

        Tenant acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
        Role reader = new Role(acme, "reader");
        reader.setPermissions(List.of(new PermissionEntry("material", "read")));
        roles.saveAndFlush(reader);

        account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
        account.setRoles(List.of(reader));
        account = accounts.saveAndFlush(account);
    }

    private String tokenFor(Account subject, String audience) {
        return authgate.getBean(SessionService.class)
                .start(subject, audience)
                .access()
                .value();
    }

    private ResponseEntity<String> call(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return REST.exchange(
                "http://localhost:" + demoPort + path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    // -- the point of the whole exercise -----------------------------------

    @Test
    void anAuthGateTokenIsAcceptedByAServiceThatSharesNothingWithIt() {
        ResponseEntity<String> response = call("/materials", tokenFor(account, issuer));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("Brushed cotton");
    }

    @Test
    void theDemoReadsTheIdentityWithoutKnowingWhoTheCallerIs() {
        ResponseEntity<String> response = call("/materials/whoami", tokenFor(account, issuer));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        // The demo holds no user table. Everything it knows came out of the token.
        assertThat(response.getBody())
                .contains("bosko@example.test")
                .contains(account.getId().toString());
    }

    @Test
    void permissionsInsideTheTokenAreEnforcedByTheDemo() {
        String token = tokenFor(account, issuer);

        // The account holds material:read and nothing else, and the demo has never asked AuthGate
        // about it — the grant travelled in the token.
        assertThat(call("/materials", token).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(REST.exchange(
                                "http://localhost:" + demoPort + "/materials",
                                HttpMethod.POST,
                                new HttpEntity<>(bearer(token)),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void aTokenForAnotherAudienceIsRejected() {
        // Correctly signed by the right issuer, unexpired, and meant for someone else. Spring's
        // resource server would accept it on issuer-uri alone; the starter's audience check is the
        // only thing standing between this service and every other service's tokens.
        String foreign = tokenFor(account, "https://some-other-service.example");

        assertThat(call("/materials", foreign).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anAnonymousCallerIsRejected() {
        assertThat(call("/materials", null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aTokenSignedBySomebodyElseIsRejected() {
        // Same shape, different signer. The demo trusts one JWKS and nothing else.
        assertThat(call("/materials", forgedToken()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    private static String forgedToken() {
        try {
            java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            java.security.KeyPair pair = generator.generateKeyPair();
            com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(
                    new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                            .keyID("made-up")
                            .build(),
                    new com.nimbusds.jwt.JWTClaimsSet.Builder()
                            .issuer(issuer)
                            .subject("whoever")
                            .audience(issuer)
                            .issueTime(java.util.Date.from(java.time.Instant.now()))
                            .expirationTime(
                                    java.util.Date.from(java.time.Instant.now().plus(java.time.Duration.ofMinutes(10))))
                            .claim("perms", Map.of("material", List.of("read")))
                            .build());
            jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(pair.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
