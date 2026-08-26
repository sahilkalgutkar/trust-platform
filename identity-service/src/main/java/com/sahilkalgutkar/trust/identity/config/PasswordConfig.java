package com.sahilkalgutkar.trust.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    /**
     * Cost 10 rather than the default 10-with-a-shrug: it is the number this service was load
     * tested at, and a cost factor that has never been thought about is a cost factor that will
     * still be 4 in five years.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
