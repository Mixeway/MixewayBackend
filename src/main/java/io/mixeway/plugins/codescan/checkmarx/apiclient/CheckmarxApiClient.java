package io.mixeway.plugins.codescan.checkmarx.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.plugins.codescan.checkmarx.model.CxLoginResponse;
import io.mixeway.plugins.codescan.model.CodeRequestHelper;
import io.mixeway.plugins.codescan.model.TokenValidator;
import io.mixeway.plugins.codescan.service.CodeScanClient;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.client.RestTemplate;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;



@Component
public class CheckmarxApiClient implements CodeScanClient, SecurityScanner {
    DateTimeFormatter sdf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final Logger log = LoggerFactory.getLogger(CheckmarxApiClient.class);
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final VaultOperations operations;
    private final SecureRestTemplate secureRestTemplate;
    private TokenValidator tokenValidator = new TokenValidator();
    @Autowired
    CheckmarxApiClient(ScannerTypeRepository scannerTypeRepository, ScannerRepository scannerRepository,
                       VaultOperations operations, SecureRestTemplate secureRestTemplate){
        this.operations = operations;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.secureRestTemplate = secureRestTemplate;
    }
    @Override
    public void loadVulnerabilities(Scanner scanner, CodeGroup codeGroup, String urlToGetNext, Boolean single, CodeProject codeProject, List<CodeVuln> codeVulns) throws ParseException, JSONException {

    }

    @Override
    public Boolean runScan(CodeGroup cg, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return null;
    }

    @Override
    public boolean isScanDone(CodeGroup cg) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ParseException, JSONException {
        return false;
    }

    @Override
    public boolean canProcessRequest(CodeGroup cg) {
        return false;
    }

    @Override
    public boolean initialize(Scanner scanner) throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException, Exception {

        return false;
    }

    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return false;
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return false;
    }

    @Override
    public void saveScanner(ScannerModel scannerModel) {
        ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
        Scanner checkmarx = new io.mixeway.db.entity.Scanner();
        checkmarx.setApiUrl(scannerModel.getApiUrl());
        checkmarx.setPassword(UUID.randomUUID().toString());
        checkmarx.setUsername(scannerModel.getUsername());
        checkmarx.setStatus(false);
        checkmarx.setScannerType(scannerType);
        // api key put to vault
        Map<String, String> passwordKeyMap = new HashMap<>();
        passwordKeyMap.put("password", scannerModel.getPassword());
        operations.write("secret/" + checkmarx.getPassword(), passwordKeyMap);
        scannerRepository.save(checkmarx);
    }

    /**
     * Function calling Checkmarx rest API login function
     *
     * @param scanner
     */
    private boolean generateToken(io.mixeway.db.entity.Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        Map<String, String> formEncodedForLogin = createFormForLogin(scanner);
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        HttpEntity<Map<String, String>> entity = new HttpEntity<>(formEncodedForLogin, headers);
        String API_GET_TOKEN = "/cxrestapi/auth/identity/connect/token";
        ResponseEntity<CxLoginResponse> response = restTemplate.exchange(scanner.getApiUrl() + API_GET_TOKEN, HttpMethod.POST, entity, CxLoginResponse.class);
        if (response.getStatusCode() == HttpStatus.CREATED) {
            Date dt = new Date();
            LocalDateTime ldt = LocalDateTime.from(dt.toInstant()).plusSeconds(Objects.requireNonNull(response.getBody()).getExpires_in());
            scanner.setFortifytokenexpiration(ldt.format(sdf));
            scanner.setFortifytoken(response.getBody().getAccess_token());
            if(!scanner.getStatus()){
                scanner.setStatus(true);
            }
            scannerRepository.save(scanner);
            return true;
        } else {
            log.error("Checkmarx Authorization failure");
            return false;
        }
    }

    private Map<String, String> createFormForLogin(Scanner scanner) {
        VaultResponseSupport<Map<String, Object>> password = operations.read("secret/" + scanner.getPassword());
        assert password != null;
        Map<String, String> form = new HashMap<>();
        form.put(Constants.CHECKMARX_LOGIN_FORM_USERNAME, scanner.getUsername());
        form.put(Constants.CHECKMARX_LOGIN_FORM_PASSWORD, Objects.requireNonNull(password.getData()).get("password").toString());
        form.put(Constants.CHECKMARX_LOGIN_FORM_GRANT_TYPE, Constants.CHECKMARX_LOGIN_FORM_GRANT_TYPE_VALUE);
        form.put(Constants.CHECKMARX_LOGIN_FORM_SCOPE,Constants.CHECKMARX_LOGIN_FORM_SCOPE_VALUE);
        form.put(Constants.CHECKMARX_LOGIN_FORM_CLIENTID, Constants.CHECKMARX_LOGIN_FORM_CLIENTID_VALUE);
        form.put(Constants.CHECKMARX_LOGIN_FORM_CLIENTSECRET, Constants.CHECKMARX_LOGIN_FORM_CLIENTSECRET_VALUE);
        return form;
    }
    private CodeRequestHelper prepareRestTemplate(io.mixeway.db.entity.Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        if (tokenValidator.isTokenValid(scanner.getFortifytoken(), LocalDateTime.parse(scanner.getFortifytokenexpiration()))) {
            generateToken(scanner);
        }
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = new HttpHeaders();
        headers.set(Constants.HEADER_AUTHORIZATION, Constants.BEARER_TOKEN + " " + scanner.getFortifytoken());
        HttpEntity entity = new HttpEntity(headers);

        return new CodeRequestHelper(restTemplate,entity);
    }

}
