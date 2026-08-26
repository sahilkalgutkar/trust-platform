package com.sahilkalgutkar.trust.audit.web;

import com.sahilkalgutkar.trust.common.error.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class AuditExceptionHandler {

    @ExceptionHandler(AdminGuard.NotAuthorizedException.class)
    public ResponseEntity<ApiError> handleUnauthorized(AdminGuard.NotAuthorizedException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiError.of("access_denied", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(ApiError.of("invalid_request", e.getMessage()));
    }
}
