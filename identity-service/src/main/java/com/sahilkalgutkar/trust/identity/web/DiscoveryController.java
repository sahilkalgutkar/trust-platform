package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.jwt.SigningKeyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The OpenID Connect discovery document and JWKS, both scoped to one tenant.
 *
 * <p>Every URL in the document is under the tenant's own path, so a relying party configured from
 * {@code /t/acme/.well-known/openid-configuration} has no route to another tenant's endpoints even
 * by construction.
 */
@RestController
public class DiscoveryController {

    private final IdentityProperties properties;
    private final SigningKeyService signingKeyService;

    public DiscoveryController(IdentityProperties properties, SigningKeyService signingKeyService) {
        this.properties = properties;
        this.signingKeyService = signingKeyService;
    }

    @GetMapping("/t/{tenant}/.well-known/openid-configuration")
    public Map<String, Object> discovery(@PathVariable("tenant") String tenant) {
        String issuer = properties.issuerFor(tenant);
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("issuer", issuer);
        document.put("authorization_endpoint", issuer + "/oauth2/authorize");
        document.put("token_endpoint", issuer + "/oauth2/token");
        document.put("introspection_endpoint", issuer + "/oauth2/introspect");
        document.put("revocation_endpoint", issuer + "/oauth2/revoke");
        document.put("userinfo_endpoint", issuer + "/userinfo");
        document.put("jwks_uri", issuer + "/oauth2/jwks");
        document.put("response_types_supported", List.of("code"));
        document.put("grant_types_supported",
                List.of("authorization_code", "refresh_token", "client_credentials"));
        document.put("code_challenge_methods_supported", List.of("S256", "plain"));
        document.put("id_token_signing_alg_values_supported", List.of("RS256"));
        document.put("token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post", "none"));
        document.put("scopes_supported", List.of("openid", "profile", "email"));
        document.put("subject_types_supported", List.of("public"));
        return document;
    }

    @GetMapping("/t/{tenant}/oauth2/jwks")
    public Map<String, Object> jwks(@PathVariable("tenant") String tenant) {
        // toJSONObject() on a JWKSet emits public parameters only; the private halves never leave
        // SigningKeyService.
        return signingKeyService.publishedKeySet().toJSONObject();
    }
}
