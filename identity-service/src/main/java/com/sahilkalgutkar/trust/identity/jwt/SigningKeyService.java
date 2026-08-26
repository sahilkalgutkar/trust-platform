package com.sahilkalgutkar.trust.identity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.SigningKeyEntity;
import com.sahilkalgutkar.trust.identity.repo.SigningKeyRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Owns each tenant's RSA signing keys: creation on first use, rotation, and what JWKS publishes.
 *
 * <p>Rotation is the part most hand-rolled providers get wrong. Retiring the old key immediately
 * would break every unexpired access token already in the wild, so a retired key keeps being
 * published — and keeps verifying — for {@code retiredKeyGracePeriod}, which only has to exceed the
 * access token TTL. New tokens are always signed by the single ACTIVE key.
 */
@Service
public class SigningKeyService {

    private final SigningKeyRepository repository;
    private final KeyEncryptor keyEncryptor;
    private final IdentityProperties properties;
    private final Clock clock;

    public SigningKeyService(SigningKeyRepository repository, KeyEncryptor keyEncryptor,
                             IdentityProperties properties, Clock clock) {
        this.repository = repository;
        this.keyEncryptor = keyEncryptor;
        this.properties = properties;
        this.clock = clock;
    }

    /** The key new tokens are signed with, generating one the first time a tenant needs it. */
    @Transactional
    public RSAKey activeSigningKey() {
        Optional<SigningKeyEntity> existing = repository.findFirstByStatus(SigningKeyEntity.ACTIVE);
        if (existing.isPresent()) {
            return toRsaKey(existing.get());
        }
        try {
            return toRsaKey(createActiveKey());
        } catch (DataIntegrityViolationException raceLostToAnotherInstance) {
            // The partial unique index on (tenant_id) WHERE status='ACTIVE' is what makes this
            // safe: whoever lost the race just reads the key the winner inserted.
            return repository.findFirstByStatus(SigningKeyEntity.ACTIVE)
                    .map(this::toRsaKey)
                    .orElseThrow(() -> raceLostToAnotherInstance);
        }
    }

    @Transactional
    public RSAKey rotate() {
        Instant now = clock.instant();
        repository.findFirstByStatus(SigningKeyEntity.ACTIVE).ifPresent(current -> {
            current.retire(now);
            repository.saveAndFlush(current);
        });
        return toRsaKey(createActiveKey());
    }

    /**
     * What {@code /oauth2/jwks} serves: the active key plus any retired key still inside its grace
     * period. Public halves only — {@link RSAKey#toPublicJWK()} is what stops this endpoint from
     * being the worst bug in the codebase.
     */
    @Transactional(readOnly = true)
    public JWKSet publishedKeySet() {
        Instant cutoff = clock.instant().minus(properties.getRetiredKeyGracePeriod());
        List<JWK> published = new ArrayList<>();
        for (SigningKeyEntity key : repository.findAllByOrderByCreatedAtDesc()) {
            if (key.isActive() || (key.getRetiredAt() != null && key.getRetiredAt().isAfter(cutoff))) {
                published.add(parsePublicJwk(key.getPublicJwk()));
            }
        }
        return new JWKSet(published);
    }

    /** Verification path: a token names its {@code kid}, and only a published key may verify it. */
    @Transactional(readOnly = true)
    public Optional<RSAKey> findVerificationKey(String kid) {
        return publishedKeySet().getKeys().stream()
                .filter(jwk -> jwk.getKeyID().equals(kid))
                .map(RSAKey.class::cast)
                .findFirst();
    }

    private SigningKeyEntity createActiveKey() {
        String kid = UUID.randomUUID().toString();
        RSAKey generated = generate(kid);
        try {
            byte[] pkcs8 = generated.toRSAPrivateKey().getEncoded();
            SigningKeyEntity entity = new SigningKeyEntity(
                    kid,
                    generated.toPublicJWK().toJSONString(),
                    keyEncryptor.wrap(pkcs8));
            return repository.saveAndFlush(entity);
        } catch (JOSEException e) {
            throw new IllegalStateException("Generated key has no usable private half", e);
        }
    }

    private static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Unable to generate an RSA signing key", e);
        }
    }

    private RSAKey toRsaKey(SigningKeyEntity entity) {
        RSAKey publicKey = parsePublicJwk(entity.getPublicJwk());
        byte[] pkcs8 = keyEncryptor.unwrap(entity.getPrivateKeyWrapped());
        try {
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            return new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("Stored private key for kid " + entity.getKid() + " is unusable", e);
        }
    }

    private static RSAKey parsePublicJwk(String json) {
        try {
            return RSAKey.parse(json);
        } catch (ParseException e) {
            throw new IllegalStateException("Stored public JWK is not parseable", e);
        }
    }
}
