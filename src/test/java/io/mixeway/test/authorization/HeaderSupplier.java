package io.mixeway.test.authorization;

import io.restassured.http.Header;

public class HeaderSupplier {

    public static Header jwtHeader() {
        return new Header("apikey", "da12412c-7376-4eff-a1e8-4569349154a1");
    }
}
