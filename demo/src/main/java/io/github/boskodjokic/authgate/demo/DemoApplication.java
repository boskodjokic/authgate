package io.github.boskodjokic.authgate.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * A service that trusts AuthGate and nothing else.
 *
 * <p>It holds no user table, no passwords, and no knowledge of which identity provider anyone
 * signed in through. It reads a bearer token, and the starter turns that into a caller with
 * permissions.
 */
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
