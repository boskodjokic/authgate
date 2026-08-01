package io.github.boskodjokic.authgate.demo;

import io.github.boskodjokic.authgate.client.Identity;
import java.util.List;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A protected resource, standing in for whatever a real service actually does.
 *
 * <p>Note what is absent. There is no user lookup, no session, no call back to AuthGate on the
 * request path, and nothing here knows whether the caller signed in with Google, with Okta or with
 * an emailed link. The bearer token carries the permissions and the starter turns them into
 * authorities; that is the entire integration.
 */
@RestController
@RequestMapping("/materials")
public class MaterialController {

    @GetMapping
    @PreAuthorize("hasAnyAuthority('superuser', 'material:read')")
    public List<Map<String, String>> list(@AuthenticationPrincipal Identity caller) {
        return List.of(Map.of("id", "m-1", "name", "Brushed cotton", "tenant", String.valueOf(caller.tenantId())));
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('superuser', 'material:update')")
    public Map<String, String> update(@AuthenticationPrincipal Identity caller) {
        return Map.of("updatedBy", caller.email());
    }

    /**
     * Anything authenticated may read this. Useful for showing what the token actually said, and
     * for proving the identity arrives typed rather than as a claim map.
     */
    @GetMapping("/whoami")
    public Identity whoami(@AuthenticationPrincipal Identity caller) {
        return caller;
    }
}
