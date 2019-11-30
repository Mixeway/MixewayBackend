package io.mixeway.pojo;

import io.mixeway.db.entity.Scanner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public class RestTemplateBasicAuth {
    public HttpEntity<String> prepareTemplateHedersBasicAndJson(Scanner scanner, VaultOperations operations){
        HttpEntity<String> entity = new HttpEntity<String>(getPasswordEncodedString(operations, scanner));
        return entity;
    }
    public HttpEntity<Object> prepareTemplateWithBasicAuthAndBody(Scanner scanner, VaultOperations operations, Object body){

        HttpEntity<Object> entity = new HttpEntity<Object>(body,getPasswordEncodedString(operations,scanner));
        return entity;
    }
    public HttpHeaders getPasswordEncodedString(VaultOperations operations, Scanner scanner){
        HttpHeaders headers = new HttpHeaders();
        VaultResponseSupport<Map<String,Object>> password = operations.read("secret/"+scanner.getPassword());
        final String passwordToEncode = scanner.getUsername()+":"+password.getData().get("password").toString();
        final byte[] passwordToEncodeBytes = passwordToEncode.getBytes(StandardCharsets.UTF_8);
        headers.set("Authorization", "Basic "+ Base64.getEncoder().encodeToString(passwordToEncodeBytes));
        headers.set("Content-Type", "application/json");
        return headers;
    }
}
