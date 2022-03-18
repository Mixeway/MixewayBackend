package io.mixeway.scanmanager.model;

import java.time.LocalDateTime;

import static java.time.LocalDateTime.now;

public class TokenValidator {

    public boolean isTokenValid(String fortifyToken, LocalDateTime fortifyTokenExpiration) {
        if (fortifyToken == null) {
            return false;
        } else {
            return fortifyTokenExpiration.isBefore(now());
        }
    }
}
