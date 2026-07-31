package io.github.boskodjokic.authgate.server.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import io.github.boskodjokic.authgate.server.security.SecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Web-layer slice: no database, so this runs on a machine with no container runtime. The two
 * well-known endpoints are the entire public contract at this phase, and they are what a stock
 * OIDC client reads first.
 */
@WebMvcTest({DiscoveryController.class, JwksController.class})
@Import({SigningKeys.class, SecurityConfiguration.class})
@EnableConfigurationProperties(AuthGateProperties.class)
@TestPropertySource(properties = {"authgate.issuer=https://auth.example.test", "authgate.access-token-ttl=15m"})
class WellKnownEndpointsTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void discoveryDocumentIsServedAtTheSpecifiedPath() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.issuer").value("https://auth.example.test"));
    }

    @Test
    void discoveryPointsAtTheJwksEndpoint() throws Exception {
        // A client follows this link without asking; if it is wrong, nothing else works and the
        // failure looks like a signature problem rather than a URL problem.
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(jsonPath("$.jwks_uri").value("https://auth.example.test/.well-known/jwks.json"));
    }

    @Test
    void discoveryAdvertisesTheSigningAlgorithm() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(
                        jsonPath("$.id_token_signing_alg_values_supported[0]").value("RS256"));
    }

    @Test
    void jwksServesTheSigningKey() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty());
    }

    @Test
    void jwksNeverExposesPrivateKeyMaterial() throws Exception {
        // Belt and braces with SigningKeysTest: that one checks the object, this one checks what
        // actually crosses the wire.
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }
}
