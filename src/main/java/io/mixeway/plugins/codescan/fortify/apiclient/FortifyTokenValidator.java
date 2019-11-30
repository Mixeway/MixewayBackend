package io.mixeway.plugins.codescan.fortify.apiclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;

import static java.time.LocalDateTime.now;

public class FortifyTokenValidator {
    private static final Logger log = LoggerFactory.getLogger(FortifyTokenValidator.class);

    public boolean isTokenValid(String fortifyToken, LocalDateTime fortifyTokenExpiration) {
        if (fortifyToken == null) {
            return false;
        } else {
            return fortifyTokenExpiration.isBefore(now());
        }
    }
}
