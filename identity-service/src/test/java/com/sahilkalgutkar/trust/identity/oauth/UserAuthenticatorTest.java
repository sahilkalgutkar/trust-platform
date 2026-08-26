package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import com.sahilkalgutkar.trust.identity.repo.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserAuthenticatorTest {

    private final UserRepository repository = mock(UserRepository.class);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final UserAuthenticator authenticator = new UserAuthenticator(repository, encoder);

    private UserEntity user;

    @BeforeEach
    void setUp() {
        user = new UserEntity(UUID.randomUUID(), "ada@acme.test", encoder.encode("correct horse battery"));
        when(repository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(repository.findByEmail("ada@acme.test")).thenReturn(Optional.of(user));
    }

    @Test
    void theRightPasswordAuthenticates() {
        assertThat(authenticator.authenticate("ada@acme.test", "correct horse battery")).contains(user);
    }

    @Test
    void emailIsNormalisedBeforeLookup() {
        assertThat(authenticator.authenticate("  ADA@Acme.test  ", "correct horse battery")).contains(user);
    }

    @Test
    void theWrongPasswordDoesNotAuthenticate() {
        assertThat(authenticator.authenticate("ada@acme.test", "guess")).isEmpty();
    }

    @Test
    void anUnknownAccountDoesNotAuthenticate() {
        assertThat(authenticator.authenticate("nobody@acme.test", "anything")).isEmpty();
    }

    @Test
    void aDeactivatedAccountDoesNotAuthenticateEvenWithTheRightPassword() {
        user.setStatus("DISABLED");

        assertThat(authenticator.authenticate("ada@acme.test", "correct horse battery")).isEmpty();
    }

    @Test
    void nullsAreTreatedAsAFailedLoginRatherThanAnError() {
        assertThat(authenticator.authenticate(null, "x")).isEmpty();
        assertThat(authenticator.authenticate("ada@acme.test", null)).isEmpty();
    }
}
