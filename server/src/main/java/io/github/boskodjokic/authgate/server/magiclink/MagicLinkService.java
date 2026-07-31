package io.github.boskodjokic.authgate.server.magiclink;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.token.Session;
import io.github.boskodjokic.authgate.server.token.SessionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Issues and redeems one-time sign-in links. */
@Service
public class MagicLinkService {

    private static final Logger log = LoggerFactory.getLogger(MagicLinkService.class);

    /** 256 bits. The token is the entire credential, so it is sized to be unguessable outright. */
    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final MagicLinkRepository links;
    private final AccountRepository accounts;
    private final TenantRepository tenants;
    private final MagicLinkMailer mailer;
    private final SessionService sessions;
    private final AuthGateProperties properties;

    public MagicLinkService(
            MagicLinkRepository links,
            AccountRepository accounts,
            TenantRepository tenants,
            MagicLinkMailer mailer,
            SessionService sessions,
            AuthGateProperties properties) {
        this.links = links;
        this.accounts = accounts;
        this.tenants = tenants;
        this.mailer = mailer;
        this.sessions = sessions;
        this.properties = properties;
    }

    /**
     * Sends a sign-in link, if there is anyone to send it to.
     *
     * <p>Returns nothing either way, and the caller must not learn which happened. An endpoint
     * that answers "no such account" is an account-enumeration oracle: anyone can discover who
     * holds an account by asking, one address at a time.
     */
    @Transactional
    public void request(String tenantSlug, String email) {
        Optional<Account> account = tenants.findBySlug(tenantSlug)
                .filter(Tenant::isActive)
                .flatMap(tenant -> accounts.findByTenantIdAndEmail(tenant.getId(), Account.normalizeEmail(email)))
                .filter(Account::isActive);

        if (account.isEmpty()) {
            // Logged, because an operator does need to see this; not returned, because the caller
            // must not.
            log.info("Magic link requested for an unknown or inactive account in tenant {}", tenantSlug);
            return;
        }

        String token = newToken();
        Instant expiresAt = Instant.now().plus(properties.magicLink().ttl());
        links.save(
                new MagicLink(hash(token), account.get(), properties.magicLink().audience(), expiresAt));

        mailer.send(account.get().getEmail(), buildLink(token));
    }

    /**
     * Redeems a link and starts a session.
     *
     * @return the session, or empty if the link is unknown, already used, or expired — the three
     *     are deliberately indistinguishable to the caller
     */
    @Transactional
    public Optional<Session> redeem(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        String tokenHash = hash(token);

        // The conditional update is the gate. Everything after it has already won the race.
        if (links.consume(tokenHash, Instant.now()) == 0) {
            return Optional.empty();
        }

        return links.findByTokenHash(tokenHash).map(link -> sessions.start(link.getAccount(), link.getAudience()));
    }

    private String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * SHA-256, unsalted and unstretched — correct here, unlike for a password. The input is 256
     * bits of uniform randomness, so there is no dictionary to attack and nothing for a work
     * factor to buy. What the hash prevents is a leaked table being directly presentable.
     */
    static String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", e);
        }
    }

    private String buildLink(String token) {
        // The token rides in the fragment, which browsers do not send to the server and which stays
        // out of access logs, Referer headers and proxy traces.
        return properties.magicLink().redirectBase() + "#token=" + token;
    }
}
