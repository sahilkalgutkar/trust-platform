package com.sahilkalgutkar.trust.identity.web;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.jwt.JwtVerifier;
import com.sahilkalgutkar.trust.identity.oauth.OAuthException;
import com.sahilkalgutkar.trust.identity.oauth.Scopes;
import com.sahilkalgutkar.trust.identity.repo.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The OIDC UserInfo endpoint — and the one place in this service that consumes its own access
 * tokens, so it doubles as the worked example of how a resource server should validate them.
 */
@RestController
public class UserInfoController {

    private final JwtVerifier jwtVerifier;
    private final UserRepository userRepository;
    private final IdentityProperties properties;

    public UserInfoController(JwtVerifier jwtVerifier, UserRepository userRepository,
                              IdentityProperties properties) {
        this.jwtVerifier = jwtVerifier;
        this.userRepository = userRepository;
        this.properties = properties;
    }

    @GetMapping("/t/{tenant}/userinfo")
    public Map<String, Object> userInfo(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        String token = bearerToken(authorization);
        JWTClaimsSet claims = jwtVerifier.verify(token, properties.issuerFor(tenant))
                .orElseThrow(() -> OAuthException.unauthorized("invalid_token", "The access token is not valid"));

        if (!Scopes.parse(String.valueOf(claims.getClaim("scope"))).contains("openid")) {
            throw OAuthException.badRequest("insufficient_scope", "The openid scope is required");
        }

        // The user lookup is tenant-scoped by Hibernate, so a token whose subject exists in another
        // tenant resolves to nothing here even if its signature somehow checked out.
        return userRepository.findById(UUID.fromString(claims.getSubject()))
                .map(user -> {
                    Map<String, Object> response = new LinkedHashMap<>();
                    response.put("sub", user.getId().toString());
                    response.put("email", user.getEmail());
                    response.put("email_verified", false);
                    response.put("tid", user.getTenantId().toString());
                    return response;
                })
                .orElseThrow(() -> OAuthException.unauthorized(OAuthErrors.INVALID_GRANT,
                        "The subject of this token no longer exists"));
    }

    private static String bearerToken(String authorization) {
        return Optional.ofNullable(authorization)
                .filter(header -> header.regionMatches(true, 0, "Bearer ", 0, 7))
                .map(header -> header.substring(7).trim())
                .filter(token -> !token.isEmpty())
                .orElseThrow(() -> OAuthException.unauthorized("invalid_token",
                        "A Bearer access token is required"));
    }
}
