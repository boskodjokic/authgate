package io.github.boskodjokic.authgate.server;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Whole-application smoke test, including Flyway and the JPA mapping.
 *
 * <p>Skips silently on a machine with no container runtime, which includes the primary development
 * machine for this project. CI has a Docker daemon and runs it on every push — so this file is the
 * one that actually proves the migration and the entities agree, given {@code ddl-auto: validate}.
 * Anything that must be verifiable locally belongs in a slice test instead.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class AuthGateApplicationTests {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void contextLoadsAndMigrationsApply() {
        assertThat(port).isPositive();
    }

    @Test
    void healthEndpointReportsUp() {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/actuator/health"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
    }

    @Test
    void healthEndpointHidesDetails() {
        // show-details: never is a deliberate setting, not a default. Asserting it here means a
        // later convenience change cannot quietly start narrating component names and disk paths
        // to unauthenticated callers.
        ResponseEntity<String> response = restTemplate.getForEntity(url("/actuator/health"), String.class);

        assertThat(response.getBody()).doesNotContain("components");
    }

    @Test
    void wellKnownEndpointsAreReachableWithoutAuthentication() {
        // These two must stay anonymous: a client that has to authenticate before it can learn
        // how to authenticate is not usable by any stock OIDC library.
        assertThat(restTemplate
                        .getForEntity(url("/.well-known/openid-configuration"), String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.OK);
        assertThat(restTemplate
                        .getForEntity(url("/.well-known/jwks.json"), String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }
}
