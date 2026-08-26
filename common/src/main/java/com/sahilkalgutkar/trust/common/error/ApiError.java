package com.sahilkalgutkar.trust.common.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The error body every endpoint returns, shaped like an OAuth error response so the token endpoint
 * and the plain REST endpoints do not disagree about what an error looks like.
 *
 * <p>{@code error_description} is written for a developer reading a log, not for an attacker
 * probing: it says <em>that</em> a grant was rejected, never which half of the check failed.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription) {

    public static ApiError of(String error, String description) {
        return new ApiError(error, description);
    }
}
