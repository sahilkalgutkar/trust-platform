package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.identity.audit.AuditRecorder;
import com.sahilkalgutkar.trust.identity.domain.AuthorizationCodeEntity;
import com.sahilkalgutkar.trust.identity.domain.RefreshTokenEntity;
import com.sahilkalgutkar.trust.identity.repo.AuthorizationCodeRepository;
import com.sahilkalgutkar.trust.identity.repo.RefreshTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
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

    /** Revokes every token descended from one grant, and records why. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(UUID familyId, Instant at, AuditEvent event) {
        List<RefreshTokenEntity> family = refreshTokenRepository.findAllByFamilyId(familyId);
        family.forEach(token -> token.revoke(at));
        refreshTokenRepository.saveAll(family);
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
