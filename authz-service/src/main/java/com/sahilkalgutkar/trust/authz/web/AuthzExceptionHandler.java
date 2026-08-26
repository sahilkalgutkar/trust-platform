package com.sahilkalgutkar.trust.authz.web;

import com.sahilkalgutkar.trust.authz.config.CallerContext;
import com.sahilkalgutkar.trust.authz.engine.CheckDepthExceededException;
import com.sahilkalgutkar.trust.authz.model.UnknownRelationException;
import com.sahilkalgutkar.trust.common.error.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.NoSuchElementException;

@RestControllerAdvice
public class AuthzExceptionHandler {

    /** A relation that does not exist is a caller error, never a denial. See UnknownRelationException. */
    @ExceptionHandler(UnknownRelationException.class)
    public ResponseEntity<ApiError> handleUnknownRelation(UnknownRelationException e) {
        return ResponseEntity.badRequest().body(ApiError.of("unknown_relation", e.getMessage()));
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ApiError> handleNotFound(NoSuchElementException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiError.of("not_found", e.getMessage()));
    }

    /**
     * 508 rather than 500: the request was well formed and the service is healthy — the namespace
     * describes a hierarchy too deep to evaluate, and saying so points at the actual fix.
     */
    @ExceptionHandler(CheckDepthExceededException.class)
    public ResponseEntity<ApiError> handleDepth(CheckDepthExceededException e) {
        return ResponseEntity.status(HttpStatus.LOOP_DETECTED)
                .body(ApiError.of("depth_exceeded", e.getMessage()));
    }

    @ExceptionHandler(CallerContext.InsufficientScopeException.class)
    public ResponseEntity<ApiError> handleScope(CallerContext.InsufficientScopeException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .header("WWW-Authenticate",
                        "Bearer error=\"insufficient_scope\", scope=\"" + e.getRequired() + "\"")
                .body(ApiError.of("insufficient_scope", e.getMessage()));
    }

    @ExceptionHandler(CallerContext.NotAuthenticatedException.class)
    public ResponseEntity<ApiError> handleUnauthenticated(CallerContext.NotAuthenticatedException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiError.of("invalid_token", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(ApiError.of("invalid_request", e.getMessage()));
    }
}
