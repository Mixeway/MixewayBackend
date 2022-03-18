package io.mixeway.scanmanager.integrations.remotefirewall.apiclient;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mixeway.db.entity.Scanner;
import io.mixeway.scanmanager.integrations.remotefirewall.model.Rule;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

@Component
@Log4j2
@RequiredArgsConstructor
public class RfwApiClient {

    private final VaultHelper vaultHelper;
    private final SecureRestTemplate secureRestTemplate;


    public void operateOnRfwRule(Scanner scanner, String ipAddress,HttpMethod operation) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        try {
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
            ResponseEntity<String> response = restTemplate.exchange(scanner.getRfwUrl() + "/accept/forward/any/" + scanner.getRfwScannerIp() + "/any/" + ipAddress, operation, prepareAuthHeader(scanner), String.class);
            if (response.getStatusCode() != HttpStatus.OK)
                log.warn("RFW rule for {} was not set - error occured", ipAddress);

        } catch (HttpClientErrorException e){
            log.warn("Got Http exception while calling RFW with operation {} and ip {} message is {}", operation.toString(),ipAddress,e.getLocalizedMessage());
        }
    }
    public List<Rule> getListOfRules(Scanner scanner) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        List<Rule> rules = null;
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(null);
        //RestTemplate restTemplate = secureRestTemplate.noVerificationClient(null);
        try {
            ResponseEntity<String> response = restTemplate.exchange(scanner.getRfwUrl() + "/list", HttpMethod.GET, prepareAuthHeader(scanner), String.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                ObjectMapper mapper = new ObjectMapper();
                rules = mapper.readValue(Objects.requireNonNull(response.getBody()), new TypeReference<List<Rule>>() {
                });
            }
            return rules;
        } catch (Exception pe){
            log.warn("Get Exception during get list of rules from RFW {}", pe.getLocalizedMessage());
        }
        return null;
    }

    private HttpEntity<String> prepareAuthHeader(Scanner scanner){
        final String passwordToEncode = scanner.getRfwUser()+":"+ vaultHelper.getPassword(scanner.getRfwPassword());
        final byte[] passwordToEncodeBytes = passwordToEncode.getBytes(StandardCharsets.UTF_8);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic "+ Base64.getEncoder().encodeToString(passwordToEncodeBytes));
        return new HttpEntity<>(headers);
    }


}
