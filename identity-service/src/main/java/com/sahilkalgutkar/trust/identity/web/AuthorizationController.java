package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.common.error.ApiError;
import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.identity.oauth.AuthorizationChallenge;
import com.sahilkalgutkar.trust.identity.oauth.AuthorizationService;
import com.sahilkalgutkar.trust.identity.oauth.AuthorizeRequest;
import com.sahilkalgutkar.trust.identity.oauth.IssuedCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Optional;

/**
 * The authorization endpoint.
 *
 * <p>{@code GET} validates the request and returns what a login screen would need to render;
 * {@code POST} takes the credentials and redirects back with a code. A browser deployment would
 * swap the JSON for a template and add a session cookie, but the validation rules — which are the
 * part worth reading — would not change.
 */
@RestController
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping("/t/{tenant}/oauth2/authorize")
    public AuthorizationChallenge authorize(
            @PathVariable("tenant") String tenant,
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod) {
        return authorizationService.validate(new AuthorizeRequest(responseType, clientId, redirectUri,
                scope, state, nonce, codeChallenge, codeChallengeMethod));
    }

    @PostMapping(value = "/t/{tenant}/oauth2/authorize",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<ApiError> approve(
            @PathVariable("tenant") String tenant,
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password) {
        AuthorizeRequest request = new AuthorizeRequest(responseType, clientId, redirectUri, scope,
                state, nonce, codeChallenge, codeChallengeMethod);

        Optional<IssuedCode> issued = authorizationService.authorize(request, username, password);
        if (issued.isEmpty()) {
            // A failed login is not redirected back to the client: the client has no business
            // learning whether the account exists or the password was wrong.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiError.of(OAuthErrors.ACCESS_DENIED, "Authentication failed"));
        }

        UriComponentsBuilder location = UriComponentsBuilder.fromUriString(issued.get().redirectUri())
                .queryParam("code", issued.get().code());
        if (issued.get().state() != null && !issued.get().state().isBlank()) {
            location.queryParam("state", issued.get().state());
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(location.build(true).toUriString()))
                .build();
    }
}
