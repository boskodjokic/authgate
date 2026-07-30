package io.github.boskodjokic.authgate.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point for the AuthGate identity service.
 *
 * <p>AuthGate issues and verifies tokens for applications that federate their sign-in to one or
 * more OpenID Connect providers, and that additionally want passwordless email sign-in without
 * running a password database.
 *
 * <p>The service publishes a standards-compliant discovery document and JWKS, so any conforming
 * OIDC client can consume its tokens without a bespoke SDK.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthGateApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthGateApplication.class, args);
    }
}
