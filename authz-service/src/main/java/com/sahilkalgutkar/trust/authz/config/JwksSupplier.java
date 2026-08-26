package com.sahilkalgutkar.trust.authz.config;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Supplies the signing keys this service verifies access tokens against.
 *
 * <p>An interface rather than a concrete HTTP call so the tests can hand the verifier a key they
 * generated themselves, instead of standing up the whole identity service to prove that a token
 * with a bad signature is rejected.
 */
public interface JwksSupplier {

    JWKSet forTenant(String tenantSlug);
}
