package com.sahilkalgutkar.trust.identity.web;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sahilkalgutkar.trust.common.hash.Tokens;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import com.sahilkalgutkar.trust.identity.domain.RefreshTokenEntity;
import com.sahilkalgutkar.trust.identity.jwt.JwtVerifier;
import com.sahilkalgutkar.trust.identity.oauth.ClientAuthenticator;
import com.sahilkalgutkar.trust.identity.oauth.TokenRequest;
import com.sahilkalgutkar.trust.identity.oauth.TokenResponse;
import com.sahilkalgutkar.trust.identity.oauth.TokenService;
import com.sahilkalgutkar.trust.identity.repo.RefreshTokenRepository;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@RestController
public class TokenController {

    private final TokenService tokenService;
    private final ClientAuthenticator clientAuthenticator;
    private final JwtVerifier jwtVerifier;
    private final RefreshTokenRepository refreshTokenRepository;
    private final IdentityProperties properties;
    private final Clock clock;

    public TokenController(TokenService tokenService, ClientAuthenticator clientAuthenticator,
                           JwtVerifier jwtVerifier, RefreshTokenRepository refreshTokenRepository,
                           IdentityProperties properties, Clock clock) {
        this.tokenService = tokenService;
        this.clientAuthenticator = clientAuthenticator;
        this.jwtVerifier = jwtVerifier;
        this.refreshTokenRepository = refreshTokenRepository;
        this.properties = properties;
        this.clock = clock;
    }

    @PostMapping(value = "/t/{tenant}/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<TokenResponse> token(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        OAuthClientEntity client = clientAuthenticator.authenticate(authorization, clientId, clientSecret);
        TokenResponse response = tokenService.exchange(
                new TokenRequest(grantType, code, redirectUri, codeVerifier, refreshToken, scope),
                client, tenant);

        // RFC 6749 §5.1: token responses must never be cached, by anything, ever.
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response);
    }

    /**
     * RFC 7662 introspection. Client-authenticated, and scoped to the tenant in the path — a token
     * from another tenant introspects as {@code active: false} rather than leaking its claims.
     */
    @PostMapping(value = "/t/{tenant}/oauth2/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> introspect(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam("token") String token,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        clientAuthenticator.authenticate(authorization, clientId, clientSecret);

        Optional<JWTClaimsSet> claims = jwtVerifier.verify(token, properties.issuerFor(tenant));
        if (claims.isPresent()) {
            return activeAccessToken(claims.get());
        }
        return refreshTokenRepository.findByTokenHash(Tokens.hash(token))
                .filter(entity -> entity.isUsable(clock.instant()))
                .map(TokenController::activeRefreshToken)
                .orElseGet(() -> Map.of("active", false));
    }

    /** RFC 7009 revocation. Always 200, even for an unknown token — see the comment below. */
    @PostMapping(value = "/t/{tenant}/oauth2/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> revoke(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam("token") String token,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret) {
        OAuthClientEntity client = clientAuthenticator.authenticate(authorization, clientId, clientSecret);
        tokenService.revokeRefreshToken(token, client);
        // RFC 7009 §2.2: an invalid token is reported as success, so that revocation cannot be used
        // to ask "does this token exist?".
        return ResponseEntity.ok().build();
    }

    private static Map<String, Object> activeAccessToken(JWTClaimsSet claims) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("active", true);
        response.put("token_type", "Bearer");
        response.put("sub", claims.getSubject());
        response.put("iss", claims.getIssuer());
        response.put("aud", claims.getAudience());
        response.put("scope", claims.getClaim("scope"));
        response.put("client_id", claims.getClaim("client_id"));
        response.put("tid", claims.getClaim("tid"));
        response.put("exp", claims.getExpirationTime().toInstant().getEpochSecond());
        response.put("iat", claims.getIssueTime().toInstant().getEpochSecond());
        return response;
    }

    private static Map<String, Object> activeRefreshToken(RefreshTokenEntity entity) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("active", true);
        response.put("token_type", "refresh_token");
        response.put("sub", entity.getUserId().toString());
        response.put("client_id", entity.getClientId());
        response.put("scope", entity.getScope());
        response.put("tid", entity.getTenantId().toString());
        response.put("exp", entity.getExpiresAt().getEpochSecond());
        response.put("iat", entity.getIssuedAt().getEpochSecond());
        return response;
    }
}
