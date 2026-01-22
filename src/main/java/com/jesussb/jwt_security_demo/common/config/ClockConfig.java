package com.jesussb.jwt_security_demo.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
class ClockConfig {
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
