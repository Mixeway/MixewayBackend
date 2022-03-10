package io.mixeway.scanmanager.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;

import static java.time.LocalDateTime.now;

public class TokenValidator {
    private static final Logger log = LoggerFactory.getLogger(TokenValidator.class);

    public boolean isTokenValid(String fortifyToken, LocalDateTime fortifyTokenExpiration) {
        if (fortifyToken == null) {
            return false;
        } else {
            return fortifyTokenExpiration.isBefore(now());
        }
    }
}
