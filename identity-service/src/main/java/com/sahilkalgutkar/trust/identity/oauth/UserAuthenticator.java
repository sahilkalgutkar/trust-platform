package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import com.sahilkalgutkar.trust.identity.repo.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/** Resolves a username and password to a user inside the currently bound tenant. */
@Component
public class UserAuthenticator {

    /**
     * A valid BCrypt hash of a value nobody knows, used to spend the same work when the account
     * does not exist as when it does. Without it, "no such user" returns in microseconds while a
     * wrong password takes ~50ms, and the login endpoint becomes a user-enumeration oracle for
     * anyone with a stopwatch.
     */
    private static final String DUMMY_HASH =
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserAuthenticator(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public Optional<UserEntity> authenticate(String email, String password) {
        if (email == null || password == null) {
            return Optional.empty();
        }
        Optional<UserEntity> candidate = userRepository.findByEmail(email.trim().toLowerCase());
        if (candidate.isEmpty()) {
            passwordEncoder.matches(password, DUMMY_HASH);
            return Optional.empty();
        }
        UserEntity user = candidate.get();
        if (!passwordEncoder.matches(password, user.getPasswordHash()) || !user.isActive()) {
            return Optional.empty();
        }
        return Optional.of(user);
    }
}
