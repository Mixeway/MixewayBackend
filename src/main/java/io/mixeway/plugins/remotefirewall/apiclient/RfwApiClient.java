package io.mixeway.plugins.remotefirewall.apiclient;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.client.RestTemplate;
import io.mixeway.db.entity.Scanner;
import io.mixeway.plugins.remotefirewall.model.Rule;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import io.mixeway.pojo.SecureRestTemplate;

@Component
public class RfwApiClient {

    @Autowired
    VaultOperations operations;
    final static Logger log = LoggerFactory.getLogger(RfwApiClient.class);
    @Autowired
    public SecureRestTemplate secureRestTemplate;

    public void operateOnRfwRule(Scanner scanner, String ipAddress,HttpMethod operation) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
        ResponseEntity<String> response = restTemplate.exchange(scanner.getRfwUrl() + "/accept/forward/any/"+scanner.getRfwScannerIp()+"/any/"+ ipAddress, operation, prepareAuthHeader(scanner), String.class);
        if (response.getStatusCode() != HttpStatus.OK)
            log.warn("RFW rule for {} was not set - error occured",ipAddress);
    }
    public List<Rule> getListOfRules(Scanner scanner) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
        List<Rule> rules = null;
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
        //RestTemplate restTemplate = secureRestTemplate.noVerificationClient(null);
        try {
            ResponseEntity<String> response = restTemplate.exchange(scanner.getRfwUrl() + "/list", HttpMethod.GET, prepareAuthHeader(scanner), String.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                ObjectMapper mapper = new ObjectMapper();
                rules = mapper.readValue(response.getBody(), new TypeReference<List<Rule>>() {
                });
            }
            return rules;
        } catch (Exception pe){
            throw new ProtocolException();
        }

    }

    public HttpEntity<String> prepareAuthHeader(Scanner scanner){
        VaultResponseSupport<Map<String,Object>> password = operations.read("secret/"+scanner.getRfwPassword());
        final String passwordToEncode = scanner.getRfwUser()+":"+password.getData().get("password").toString();
        final byte[] passwordToEncodeBytes = passwordToEncode.getBytes(StandardCharsets.UTF_8);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic "+ Base64.getEncoder().encodeToString(passwordToEncodeBytes));
        HttpEntity<String> entity = new HttpEntity<String>(headers);
        return entity;
    }


}