package io.mixeway.utils;

import io.mixeway.db.entity.Scanner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RestTemplateBasicAuth {
    public HttpEntity<String> prepareTemplateHedersBasicAndJson(Scanner scanner, VaultHelper vaultHelper){
        HttpEntity<String> entity = new HttpEntity<String>(getPasswordEncodedString(vaultHelper, scanner));
        return entity;
    }
    public HttpEntity<Object> prepareTemplateWithBasicAuthAndBody(Scanner scanner, VaultHelper vaultHelper, Object body){

        HttpEntity<Object> entity = new HttpEntity<Object>(body,getPasswordEncodedString(vaultHelper,scanner));
        return entity;
    }
    public HttpHeaders getPasswordEncodedString(VaultHelper vaultHelper, Scanner scanner){
        HttpHeaders headers = new HttpHeaders();
        final String passwordToEncode = scanner.getUsername()+":"+vaultHelper.getPassword(scanner.getPassword());
        final byte[] passwordToEncodeBytes = passwordToEncode.getBytes(StandardCharsets.UTF_8);
        headers.set("Authorization", "Basic "+ Base64.getEncoder().encodeToString(passwordToEncodeBytes));
        headers.set("Content-Type", "application/json");
        return headers;
    }
}
