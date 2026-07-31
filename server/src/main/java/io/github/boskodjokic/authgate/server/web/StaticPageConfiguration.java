package io.github.boskodjokic.authgate.server.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Maps {@code /signin} onto the sign-in page.
 *
 * <p>Spring Boot serves {@code static/signin/index.html} at its literal path, but does not treat
 * {@code index.html} as a directory index for anything below the root — so {@code /signin/} is a
 * 404 while {@code /signin/index.html} is a 200. The emailed link has to be the tidy form, both
 * because it is what a recipient sees and because {@code redirect-base} is configuration an
 * integrator will copy.
 */
@Configuration
public class StaticPageConfiguration implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Both spellings: a link is as likely to be written without the trailing slash as with it.
        registry.addViewController("/signin").setViewName("forward:/signin/index.html");
        registry.addViewController("/signin/").setViewName("forward:/signin/index.html");
    }
}
