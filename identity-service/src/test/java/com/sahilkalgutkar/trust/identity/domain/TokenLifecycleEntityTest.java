package com.sahilkalgutkar.trust.identity.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** The state machine both single-use credentials share: usable, then consumed or revoked. */
class TokenLifecycleEntityTest {

    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");

    @Test
    void aFreshCodeIsNeitherConsumedNorExpired() {
        AuthorizationCodeEntity code = code(NOW.plusSeconds(60));

        assertThat(code.isConsumed()).isFalse();
        assertThat(code.isExpiredAt(NOW)).isFalse();
    }

    @Test
    void aCodeExpiresAtItsExpiryInstantNotAfterIt() {
        AuthorizationCodeEntity code = code(NOW);

        assertThat(code.isExpiredAt(NOW)).isTrue();
        assertThat(code.isExpiredAt(NOW.minusMillis(1))).isFalse();
    }

    @Test
    void consumingACodeIsRecordedRatherThanErasingIt() {
        AuthorizationCodeEntity code = code(NOW.plusSeconds(60));

        code.consume(NOW);

        assertThat(code.isConsumed()).isTrue();
        assertThat(code.getConsumedAt()).isEqualTo(NOW);
    }

    @Test
    void aFreshRefreshTokenIsUsable() {
        assertThat(refreshToken(NOW.plusSeconds(3600)).isUsable(NOW)).isTrue();
    }

    @Test
    void aConsumedRevokedOrExpiredRefreshTokenIsNotUsable() {
        RefreshTokenEntity consumed = refreshToken(NOW.plusSeconds(3600));
        consumed.consume(NOW);
        assertThat(consumed.isUsable(NOW)).isFalse();

        RefreshTokenEntity revoked = refreshToken(NOW.plusSeconds(3600));
        revoked.revoke(NOW);
        assertThat(revoked.isUsable(NOW)).isFalse();

        assertThat(refreshToken(NOW).isUsable(NOW)).isFalse();
    }

    /** Revoking twice keeps the first timestamp: when the family died is the fact worth auditing. */
    @Test
    void revokingIsIdempotentAndKeepsTheEarliestTimestamp() {
        RefreshTokenEntity token = refreshToken(NOW.plusSeconds(3600));

        token.revoke(NOW);
        token.revoke(NOW.plusSeconds(60));

        assertThat(token.getRevokedAt()).isEqualTo(NOW);
    }

    @Test
    void anOutboxEntryStartsUnpublished() {
        AuditOutboxEntity entry = new AuditOutboxEntity(UUID.randomUUID(), UUID.randomUUID(), "{}");

        assertThat(entry.getPublishedAt()).isNull();

        entry.markPublished(NOW);
        assertThat(entry.getPublishedAt()).isEqualTo(NOW);
    }

    @Test
    void aSigningKeyStartsActiveAndRetiresWithATimestamp() {
        SigningKeyEntity key = new SigningKeyEntity("kid-1", "{}", "wrapped");

        assertThat(key.isActive()).isTrue();
        assertThat(key.getRetiredAt()).isNull();

        key.retire(NOW);
        assertThat(key.isActive()).isFalse();
        assertThat(key.getStatus()).isEqualTo(SigningKeyEntity.RETIRED);
        assertThat(key.getRetiredAt()).isEqualTo(NOW);
    }

    @Test
    void aTenantIsActiveUntilItsStatusSaysOtherwise() {
        TenantEntity tenant = new TenantEntity(UUID.randomUUID(), "acme", "Acme Inc");

        assertThat(tenant.isActive()).isTrue();

        tenant.setStatus("SUSPENDED");
        assertThat(tenant.isActive()).isFalse();
    }

    @Test
    void aUserIsActiveUntilItsStatusSaysOtherwise() {
        UserEntity user = new UserEntity(UUID.randomUUID(), "ada@acme.test", "hash");

        assertThat(user.isActive()).isTrue();

        user.setStatus("DISABLED");
        assertThat(user.isActive()).isFalse();
    }

    private static AuthorizationCodeEntity code(Instant expiresAt) {
        return new AuthorizationCodeEntity(UUID.randomUUID(), "hash", "web-app", UUID.randomUUID(),
                "https://app.acme.test/callback", "openid", expiresAt);
    }

    private static RefreshTokenEntity refreshToken(Instant expiresAt) {
        return new RefreshTokenEntity(UUID.randomUUID(), "hash", UUID.randomUUID(), "web-app",
                UUID.randomUUID(), "openid", expiresAt);
    }
}
