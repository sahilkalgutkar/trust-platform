package com.sahilkalgutkar.trust.identity.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Everything that reads the current time takes this bean rather than calling
 * {@code Instant.now()} directly — token expiry, code expiry, and the refresh grace window are all
 * behaviour worth testing, and none of it is testable if the clock cannot be moved.
 */
@Configuration
public class ClockConfig {

    @Bean
    @ConditionalOnMissingBean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
