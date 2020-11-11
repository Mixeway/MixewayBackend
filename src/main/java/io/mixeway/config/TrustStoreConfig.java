package io.mixeway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import javax.annotation.PostConstruct;

@Configuration
@Profile("!test")
public class TrustStoreConfig {
    @Value("${server.ssl.trust-store}")
    private String trustStorePath;
    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    @PostConstruct
    private void configureSSL() {
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword",trustStorePassword);

    }
}
