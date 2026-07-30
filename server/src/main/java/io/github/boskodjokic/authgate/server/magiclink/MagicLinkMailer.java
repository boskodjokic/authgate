package io.github.boskodjokic.authgate.server.magiclink;

/**
 * Delivers a sign-in link.
 *
 * <p>A port rather than a concrete sender: how mail leaves the building is a deployment concern,
 * and a host that already has SES, Postmark or an internal relay should not be made to configure
 * SMTP a second time.
 */
public interface MagicLinkMailer {

    void send(String recipient, String link);
}
