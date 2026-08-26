package com.sahilkalgutkar.trust.identity.oauth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PkceValidatorTest {

    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private final PkceValidator validator = new PkceValidator();

    @Test
    void s256ChallengeAcceptsTheMatchingVerifier() {
        String challenge = PkceValidator.sha256Base64Url(VERIFIER);

        assertThatCode(() -> validator.verify(challenge, PkceValidator.METHOD_S256, VERIFIER))
                .doesNotThrowAnyException();
    }

    @Test
    void s256ChallengeRejectsADifferentVerifier() {
        String challenge = PkceValidator.sha256Base64Url(VERIFIER);
        String other = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, other))
                .isInstanceOf(OAuthException.class)
                .hasMessage("Grant rejected");
    }

    /**
     * The attack this exists for: an attacker who intercepts the code also controls the token
     * request, so if the method were read from that request they could claim {@code plain} and
     * present the challenge itself as the verifier. The stored method is authoritative.
     */
    @Test
    void anS256ChallengeCannotBeDowngradedByPresentingTheChallengeAsThePlainVerifier() {
        String challenge = PkceValidator.sha256Base64Url(VERIFIER);

        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, challenge))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void plainIsHonouredOnlyWhenItWasWhatTheClientCommittedTo() {
        assertThatCode(() -> validator.verify(VERIFIER, PkceValidator.METHOD_PLAIN, VERIFIER))
                .doesNotThrowAnyException();
    }

    @Test
    void aStoredChallengeWithoutAVerifierIsRejectedRatherThanSkipped() {
        String challenge = PkceValidator.sha256Base64Url(VERIFIER);

        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, null))
                .isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, ""))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aVerifierOutsideTheLengthRangeIsRejected() {
        String challenge = PkceValidator.sha256Base64Url(VERIFIER);

        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, "too-short"))
                .isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, "a".repeat(129)))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aVerifierContainingCharactersOutsideTheUnreservedSetIsRejected() {
        String challenge = PkceValidator.sha256Base64Url(VERIFIER);

        assertThatThrownBy(() -> validator.verify(challenge, PkceValidator.METHOD_S256, "!".repeat(43)))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aFlowStartedWithoutPkceAcceptsNoVerifier() {
        assertThatCode(() -> validator.verify(null, null, null)).doesNotThrowAnyException();
        assertThatCode(() -> validator.verify("", null, null)).doesNotThrowAnyException();
    }

    @Test
    void aFlowStartedWithoutPkceRejectsAVerifierThatArrivesAnyway() {
        assertThatThrownBy(() -> validator.verify(null, null, VERIFIER))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void validateChallengeRequiresAChallengeWhenTheClientMandatesPkce() {
        assertThatThrownBy(() -> validator.validateChallenge(null, PkceValidator.METHOD_S256))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("code_challenge is required");
    }

    @Test
    void validateChallengeRejectsAnUnknownMethod() {
        assertThatThrownBy(() -> validator.validateChallenge("challenge", "md5"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("S256 or plain");
    }

    @Test
    void validateChallengeAcceptsBothSupportedMethodsAndAnAbsentOne() {
        assertThatCode(() -> validator.validateChallenge("challenge", PkceValidator.METHOD_S256))
                .doesNotThrowAnyException();
        assertThatCode(() -> validator.validateChallenge("challenge", PkceValidator.METHOD_PLAIN))
                .doesNotThrowAnyException();
        assertThatCode(() -> validator.validateChallenge("challenge", null)).doesNotThrowAnyException();
    }

    @Test
    void theS256TransformMatchesTheWorkedExampleInRfc7636() {
        // RFC 7636 Appendix B.
        assertThat(PkceValidator.sha256Base64Url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
                .isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
}
