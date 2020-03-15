package io.mixeway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.UUID;

@Configuration
public class JwtSecretConfig {

    @Bean
    String jwtSecret(){
        return UUID.randomUUID().toString();
    }
}
