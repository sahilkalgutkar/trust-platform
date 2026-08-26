package com.sahilkalgutkar.trust.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.sahilkalgutkar.trust.identity.config.IdentityProperties;

@SpringBootApplication
@EnableConfigurationProperties(IdentityProperties.class)
@EnableScheduling
public class IdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }
}
