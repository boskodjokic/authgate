package io.github.boskodjokic.authgate.server.magiclink;

import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/** Chooses how sign-in links are delivered, based on whether mail is configured at all. */
@Configuration
public class MailerConfiguration {

    @Bean
    @ConditionalOnProperty(name = "spring.mail.host")
    MagicLinkMailer smtpMagicLinkMailer(JavaMailSender sender, AuthGateProperties properties) {
        return (recipient, link) -> {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(properties.magicLink().from());
            message.setTo(recipient);
            message.setSubject("Your sign-in link");
            message.setText("Sign in by opening this link:\n\n" + link
                    + "\n\nIt can be used once, and only for a short time. "
                    + "If you did not ask for it, you can ignore this message.");
            sender.send(message);
        };
    }

    /**
     * Fallback when no mail host is configured: writes the link to the log.
     *
     * <p>Convenient in development and dangerous anywhere else, so it says so on every use rather
     * than only at startup — a sign-in link in a log file is a usable credential for anyone who
     * can read logs.
     */
    @Bean
    @ConditionalOnMissingBean(MagicLinkMailer.class)
    MagicLinkMailer loggingMagicLinkMailer() {
        Logger log = LoggerFactory.getLogger("authgate.magiclink");
        return (recipient, link) -> log.warn(
                "No spring.mail.host configured — writing a sign-in link to the log instead of "
                        + "sending it. This is a usable credential. recipient={} link={}",
                recipient,
                link);
    }
}
