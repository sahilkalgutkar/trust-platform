package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.common.hash.Tokens;
import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import com.sahilkalgutkar.trust.identity.domain.TenantEntity;
import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import com.sahilkalgutkar.trust.identity.jwt.SigningKeyService;
import com.sahilkalgutkar.trust.identity.oauth.OAuthException;
import com.sahilkalgutkar.trust.identity.repo.OAuthClientRepository;
import com.sahilkalgutkar.trust.identity.repo.TenantRepository;
import com.sahilkalgutkar.trust.identity.repo.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/** The control plane: provisioning tenants, users, clients, and key rotation. */
@RestController
public class AdminController {

    private static final String ADMIN_KEY_HEADER = "X-Admin-Key";

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final OAuthClientRepository clientRepository;
    private final SigningKeyService signingKeyService;
    private final PasswordEncoder passwordEncoder;
    private final AdminGuard adminGuard;

    public AdminController(TenantRepository tenantRepository, UserRepository userRepository,
                           OAuthClientRepository clientRepository, SigningKeyService signingKeyService,
                           PasswordEncoder passwordEncoder, AdminGuard adminGuard) {
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.clientRepository = clientRepository;
        this.signingKeyService = signingKeyService;
        this.passwordEncoder = passwordEncoder;
        this.adminGuard = adminGuard;
    }

    @PostMapping("/admin/tenants")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, String> createTenant(
            @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey,
            @Valid @RequestBody CreateTenantRequest request) {
        adminGuard.require(adminKey);
        tenantRepository.findBySlug(request.slug()).ifPresent(existing -> {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST, "That slug is already taken");
        });
        TenantEntity tenant = tenantRepository.save(
                new TenantEntity(UUID.randomUUID(), request.slug(), request.name()));
        return Map.of("id", tenant.getId().toString(), "slug", tenant.getSlug(), "name", tenant.getName());
    }

    @PostMapping("/t/{tenant}/admin/users")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, String> createUser(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey,
            @Valid @RequestBody CreateUserRequest request) {
        adminGuard.require(adminKey);
        String email = request.email().trim().toLowerCase();
        userRepository.findByEmail(email).ifPresent(existing -> {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST,
                    "That email already has an account in this tenant");
        });
        UserEntity user = userRepository.save(new UserEntity(UUID.randomUUID(), email,
                passwordEncoder.encode(request.password())));
        return Map.of("id", user.getId().toString(), "email", user.getEmail());
    }

    @PostMapping("/t/{tenant}/admin/clients")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, Object> createClient(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey,
            @Valid @RequestBody CreateClientRequest request) {
        adminGuard.require(adminKey);
        clientRepository.findByClientId(request.clientId()).ifPresent(existing -> {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST,
                    "That client_id is already registered in this tenant");
        });

        OAuthClientEntity client = new OAuthClientEntity(UUID.randomUUID(), request.clientId(), request.name());
        client.setRedirectUris(String.join(",", request.redirectUris()));
        client.setGrantTypes(String.join(",", request.grantTypes()));
        client.setScopes(String.join(",", request.scopes()));
        client.setRequirePkce(request.requirePkce());

        String secret = null;
        if (request.confidential()) {
            // Returned exactly once, at registration. Only the hash is kept, so a lost secret is
            // rotated rather than recovered.
            secret = Tokens.generate();
            client.setClientSecretHash(passwordEncoder.encode(secret));
        }
        clientRepository.save(client);

        return secret == null
                ? Map.of("client_id", client.getClientId(), "public", true)
                : Map.of("client_id", client.getClientId(), "client_secret", secret, "public", false);
    }

    @PostMapping("/t/{tenant}/admin/keys/rotate")
    @Transactional
    public Map<String, String> rotateKeys(
            @PathVariable("tenant") String tenant,
            @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey) {
        adminGuard.require(adminKey);
        return Map.of("kid", signingKeyService.rotate().getKeyID());
    }

    public record CreateTenantRequest(
            @NotBlank @Pattern(regexp = "[a-z0-9][a-z0-9-]{1,62}",
                    message = "slug must be lowercase alphanumeric with hyphens") String slug,
            @NotBlank String name) {
    }

    public record CreateUserRequest(
            @NotBlank @jakarta.validation.constraints.Email String email,
            @NotBlank @Size(min = 12, message = "password must be at least 12 characters") String password) {
    }

    public record CreateClientRequest(
            @NotBlank String clientId,
            @NotBlank String name,
            List<String> redirectUris,
            List<String> grantTypes,
            List<String> scopes,
            boolean confidential,
            boolean requirePkce) {

        public CreateClientRequest {
            redirectUris = redirectUris == null ? List.of() : List.copyOf(redirectUris);
            grantTypes = grantTypes == null || grantTypes.isEmpty()
                    ? List.of("authorization_code", "refresh_token")
                    : List.copyOf(grantTypes);
            scopes = scopes == null || scopes.isEmpty() ? List.of("openid", "profile") : List.copyOf(scopes);
        }
    }
}
