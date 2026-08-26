package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.oauth.OAuthException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Gate on the administrative endpoints.
 *
 * <p>A shared header key is the honest minimum for a service that is deployed behind an internal
 * gateway: it keeps the control plane out of reach of the public OAuth endpoints without pretending
 * to be an authorization model. In a real deployment these endpoints sit behind mTLS or the
 * platform's own admin identity, which is why the check is isolated here rather than sprinkled
 * through the controllers.
 */
@Component
public class AdminGuard {

    private final IdentityProperties properties;

    public AdminGuard(IdentityProperties properties) {
        this.properties = properties;
    }

    public void require(String presentedKey) {
        if (presentedKey == null || !MessageDigest.isEqual(
                presentedKey.getBytes(StandardCharsets.UTF_8),
                properties.getAdminApiKey().getBytes(StandardCharsets.UTF_8))) {
            throw OAuthException.unauthorized(OAuthErrors.ACCESS_DENIED, "Administrative key required");
        }
    }
}
