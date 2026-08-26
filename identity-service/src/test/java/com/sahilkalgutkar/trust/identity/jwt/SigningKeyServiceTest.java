package com.sahilkalgutkar.trust.identity.jwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.SigningKeyEntity;
import com.sahilkalgutkar.trust.identity.repo.SigningKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SigningKeyServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");

    private final SigningKeyRepository repository = mock(SigningKeyRepository.class);
    private final IdentityProperties properties = new IdentityProperties();
    private final List<SigningKeyEntity> stored = new ArrayList<>();

    private SigningKeyService service;

    @BeforeEach
    void setUp() {
        properties.setMasterKey(java.util.Base64.getEncoder().encodeToString(new byte[32]));
        service = new SigningKeyService(repository, new KeyEncryptor(properties), properties,
                Clock.fixed(NOW, ZoneOffset.UTC));

        when(repository.findFirstByStatus(anyString())).thenAnswer(invocation -> stored.stream()
                .filter(key -> key.getStatus().equals(invocation.getArgument(0)))
                .findFirst());
        when(repository.findAllByOrderByCreatedAtDesc()).thenAnswer(invocation -> List.copyOf(stored));
        when(repository.saveAndFlush(any(SigningKeyEntity.class))).thenAnswer(invocation -> {
            SigningKeyEntity entity = invocation.getArgument(0);
            stored.removeIf(existing -> existing.getKid().equals(entity.getKid()));
            stored.add(entity);
            return entity;
        });
    }

    @Test
    void theFirstRequestGeneratesTheTenantsSigningKey() throws Exception {
        RSAKey key = service.activeSigningKey();

        assertThat(key.getKeyID()).isNotBlank();
        assertThat(key.toRSAPrivateKey()).isNotNull();
        assertThat(stored).hasSize(1);
        assertThat(stored.get(0).getStatus()).isEqualTo(SigningKeyEntity.ACTIVE);
    }

    @Test
    void laterRequestsReuseTheSameKey() {
        String first = service.activeSigningKey().getKeyID();

        assertThat(service.activeSigningKey().getKeyID()).isEqualTo(first);
        verify(repository, times(1)).saveAndFlush(any());
    }

    @Test
    void thePrivateKeyIsStoredWrappedAndTheStoredPublicJwkHasNoPrivateParameters() throws Exception {
        service.activeSigningKey();

        SigningKeyEntity entity = stored.get(0);
        assertThat(entity.getPublicJwk()).doesNotContain("\"d\"").doesNotContain("\"p\"");
        assertThat(entity.getPrivateKeyWrapped()).isNotBlank();
        assertThat(RSAKey.parse(entity.getPublicJwk()).isPrivate()).isFalse();
    }

    @Test
    void rotatingRetiresTheOldKeyAndActivatesANewOne() {
        String original = service.activeSigningKey().getKeyID();

        String rotated = service.rotate().getKeyID();

        assertThat(rotated).isNotEqualTo(original);
        assertThat(byKid(original).getStatus()).isEqualTo(SigningKeyEntity.RETIRED);
        assertThat(byKid(original).getRetiredAt()).isEqualTo(NOW);
        assertThat(byKid(rotated).isActive()).isTrue();
    }

    /** Rotation must not invalidate tokens already issued, so the old key keeps being published. */
    @Test
    void aRetiredKeyStaysPublishedForItsGracePeriod() {
        String original = service.activeSigningKey().getKeyID();
        String rotated = service.rotate().getKeyID();

        assertThat(service.publishedKeySet().getKeys())
                .extracting(JWK::getKeyID)
                .containsExactlyInAnyOrder(original, rotated);
    }

    @Test
    void aKeyRetiredBeyondTheGracePeriodIsNoLongerPublished() {
        String original = service.activeSigningKey().getKeyID();
        service.rotate();

        SigningKeyService muchLater = new SigningKeyService(repository, new KeyEncryptor(properties),
                properties, Clock.fixed(NOW.plus(Duration.ofHours(25)), ZoneOffset.UTC));

        assertThat(muchLater.publishedKeySet().getKeys())
                .extracting(JWK::getKeyID)
                .doesNotContain(original);
    }

    @Test
    void publishedKeysNeverCarryPrivateParameters() {
        service.activeSigningKey();

        assertThat(service.publishedKeySet().getKeys()).allSatisfy(jwk ->
                assertThat(jwk.isPrivate()).isFalse());
        assertThat(service.publishedKeySet().toJSONObject().toString()).doesNotContain("\"d\"");
    }

    @Test
    void onlyPublishedKeysCanVerify() {
        String kid = service.activeSigningKey().getKeyID();

        assertThat(service.findVerificationKey(kid)).isPresent();
        assertThat(service.findVerificationKey("kid-that-does-not-exist")).isEmpty();
    }

    /**
     * Two instances starting at once both find no active key. The database's partial unique index
     * lets exactly one insert win; the loser reads the winner's key instead of failing the request.
     */
    @Test
    void losingTheRaceToCreateTheFirstKeyFallsBackToTheKeyThatWon() {
        SigningKeyRepository racing = mock(SigningKeyRepository.class);
        SigningKeyEntity winner = generatedEntity();
        when(racing.findFirstByStatus(SigningKeyEntity.ACTIVE))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(winner));
        when(racing.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("duplicate key"));

        SigningKeyService racer = new SigningKeyService(racing, new KeyEncryptor(properties),
                properties, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(racer.activeSigningKey().getKeyID()).isEqualTo(winner.getKid());
    }

    @Test
    void aRaceThatLosesTwiceSurfacesTheOriginalFailure() {
        SigningKeyRepository racing = mock(SigningKeyRepository.class);
        when(racing.findFirstByStatus(SigningKeyEntity.ACTIVE)).thenReturn(Optional.empty());
        when(racing.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("duplicate key"));

        SigningKeyService racer = new SigningKeyService(racing, new KeyEncryptor(properties),
                properties, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThatThrownBy(racer::activeSigningKey).isInstanceOf(DataIntegrityViolationException.class);
    }

    private SigningKeyEntity byKid(String kid) {
        return stored.stream().filter(key -> key.getKid().equals(kid)).findFirst().orElseThrow();
    }

    private SigningKeyEntity generatedEntity() {
        service.activeSigningKey();
        SigningKeyEntity entity = stored.get(0);
        stored.clear();
        return entity;
    }
}
