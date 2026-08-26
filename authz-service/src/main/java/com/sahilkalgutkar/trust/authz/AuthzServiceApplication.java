package com.sahilkalgutkar.trust.authz;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableConfigurationProperties(AuthzProperties.class)
@EnableScheduling
public class AuthzServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthzServiceApplication.class, args);
    }
}
