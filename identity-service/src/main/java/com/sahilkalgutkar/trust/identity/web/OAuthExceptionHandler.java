package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.common.error.ApiError;
import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.common.tenant.MissingTenantException;
import com.sahilkalgutkar.trust.identity.oauth.OAuthException;
import com.sahilkalgutkar.trust.identity.oauth.RedirectableOAuthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestControllerAdvice
public class OAuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthExceptionHandler.class);

    /** Errors reported back to the client by redirect, per RFC 6749 §4.1.2.1. */
    @ExceptionHandler(RedirectableOAuthException.class)
    public ResponseEntity<Void> handleRedirectable(RedirectableOAuthException e) {
        UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(e.getRedirectUri())
                .queryParam("error", e.getError());
        if (e.getState() != null && !e.getState().isBlank()) {
            uri.queryParam("state", e.getState());
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(uri.build(true).toUriString()))
                .build();
    }

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<ApiError> handleOAuth(OAuthException e) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(e.getStatus());
        if (e.getStatus() == HttpStatus.UNAUTHORIZED) {
            // RFC 6749 §5.2: a 401 from the token endpoint has to say how to authenticate.
            response.header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"trust-platform\"");
        }
        return response.body(ApiError.of(e.getError(), e.getMessage()));
    }

    /**
     * Reached when tenant-scoped work runs with no tenant bound — a routing bug rather than a
     * caller's mistake, so it is logged and reported as a server error instead of being papered
     * over with an empty result.
     */
    @ExceptionHandler(MissingTenantException.class)
    public ResponseEntity<ApiError> handleMissingTenant(MissingTenantException e) {
        log.error("Tenant-scoped work ran with no tenant bound", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiError.of(OAuthErrors.SERVER_ERROR, "Tenant could not be determined"));
    }
}
