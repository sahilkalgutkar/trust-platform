package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.identity.audit.AuditRecorder;
import com.sahilkalgutkar.trust.identity.domain.AuthorizationCodeEntity;
import com.sahilkalgutkar.trust.identity.repo.AuthorizationCodeRepository;
import com.sahilkalgutkar.trust.identity.repo.RefreshTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Carries out the response to a detected replay, in its own transaction.
 *
 * <p>This exists because of a bug the integration tests caught and the unit tests could not. The
 * revocation used to run inline in {@code TokenService}, which then threw {@code invalid_grant} to
 * reject the request — and that exception rolled back the very transaction the revocation had just
 * been written in. The replay was detected, reported, and then quietly forgiven: the stolen token's
 * family stayed live, and the audit record of the detection vanished with it.
 *
 * <p>{@code REQUIRES_NEW} suspends the caller's transaction and commits this work on its own, so
 * the rejection and the revocation no longer share a fate. It is a separate bean for the same
 * reason: Spring's proxying means a self-invocation would silently reuse the caller's transaction
 * and reintroduce exactly the bug it is here to prevent.
 *
 * <p>For a replay, {@code TokenService} goes one step further and calls this only after its own
 * transaction has rolled back. A request that lost a race to redeem the same credential still
 * holds a lock on that credential's row, and revoking the family has to update it.
 */
@Component
public class CompromiseResponder {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthorizationCodeRepository codeRepository;
    private final AuditRecorder auditRecorder;

    public CompromiseResponder(RefreshTokenRepository refreshTokenRepository,
                               AuthorizationCodeRepository codeRepository,
                               AuditRecorder auditRecorder) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.codeRepository = codeRepository;
        this.auditRecorder = auditRecorder;
    }

    /**
     * Revokes every token descended from one grant, and records why.
     *
     * <p>The family's live token can be in the middle of a rotation while this runs: consumed, its
     * row locked, and a new token inserted but not committed. Reading the family and revoking what
     * was read misses that new token, so it stays live in a revoked family. A single update of the
     * family misses it too, because the update waits for the locked row but its snapshot was taken
     * before the new token existed. So the update runs until it revokes nothing: each pass waits
     * for the rotations holding a member, and the next pass sees what they issued. A rotation that
     * starts after a pass finds its token revoked, and is refused.
     *
     * <p>The update sets {@code revoked_at} and nothing else. Saving the entities read first wrote
     * every column back as it was read, which undid a consumption that committed in between.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(UUID familyId, Instant at, AuditEvent event) {
        int revoked;
        do {
            revoked = refreshTokenRepository.revokeUnrevoked(familyId, at);
        } while (revoked > 0);
        auditRecorder.record(event);
    }

    /**
     * Burns an authorization code presented by a client it was not issued to, so the holder does
     * not get a second attempt with the right client id.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void burnCode(UUID codeId, Instant at, AuditEvent event) {
        codeRepository.findById(codeId).ifPresent(code -> {
            code.consume(at);
            codeRepository.save(code);
        });
        auditRecorder.record(event);
    }
}
