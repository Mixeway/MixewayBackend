package io.mixeway.integrations.webappscan.plugin.burpee.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.integrations.webappscan.plugin.burpee.model.*;
import io.mixeway.integrations.webappscan.service.WebAppScanClient;
import io.mixeway.pojo.ApiClientException;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.model.ScannerModel;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Component
public class BurpEEApiClient implements SecurityScanner, WebAppScanClient {
    private final ScannerTypeRepository scannerTypeRepository;
    private final ProxiesRepository proxiesRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final VaultHelper vaultHelper;
    private final ScannerRepository scannerRepository;
    private final SecureRestTemplate secureRestTemplate;

    public BurpEEApiClient(ScannerTypeRepository scannerTypeRepository, ProxiesRepository proxiesRepository,
                           RoutingDomainRepository routingDomainRepository, ScannerRepository scannerRepository,
                           VaultHelper vaultHelper, SecureRestTemplate secureRestTemplate){
        this.scannerTypeRepository = scannerTypeRepository;
        this.proxiesRepository = proxiesRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.vaultHelper = vaultHelper;
        this.scannerRepository = scannerRepository;
        this.secureRestTemplate = secureRestTemplate;
    }

    /**
     * Method is executing Burp EE API in order to configure scan and run it.
     * It use WebApp.url as target, and Scanner.apiKey as authorization method.
     * Scan Configuration is created based on ScanTemplates for given scanner.
     *
     * @param webApp to run scan based on
     * @param scanner to execute scan
     */
    @Override
    @Transactional
    public void runScan(WebApp webApp, Scanner scanner) throws Exception {
        ScanRequest scanRequest = new ScanRequest(webApp,scanner);
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpEntity<ScanRequest> entity = new HttpEntity<>(scanRequest);
        ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/"+vaultHelper.getPassword(scanner.getApiKey())+"/v0.1/scan",
                HttpMethod.GET, entity, String.class);
        if (response.getStatusCode().equals(HttpStatus.CREATED)){
            if (StringUtils.isBlank(webApp.getScanId())){
                getScanIdForWebApp(webApp, scanner);
            }
            webApp.setRunning(true);
        } else {
            throw new ApiClientException("Unable to Create scan for given target");
        }
    }

    /**
     * Getting list of sites on Burp EE, and then filter through it and filter for site with name of a webapp.url
     * then save scanId for later use.
     *
     * @param webApp subject
     * @param scanner on which requests will be executed
     */
    private void getScanIdForWebApp(WebApp webApp, Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ApiClientException {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeader(scanner));
        ResponseEntity<GetSites> response = restTemplate.exchange(scanner.getApiUrl() + "/api-internal/sites/",
                HttpMethod.GET, entity, GetSites.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            webApp.setScanId(Objects.requireNonNull(response.getBody()).getSiteList().stream().filter(site -> site.getName().equals(webApp.getUrl())).findFirst().orElse(null).getId());
        } else {
            throw new ApiClientException("Unable to get scanIds");
        }
    }

    /**
     * Required for WebAppScanClient, but in scope of Burp EE api client method is not applicible.
     * Each time scan is being configured it is being executed at a same moment, thus there is only one method - runScan
     * to configure and run scan.
     */
    @Override
    public void configureWebApp(WebApp webApp, Scanner scanner) throws Exception {

    }

    @Override
    public Boolean isScanDone(Scanner scanner, WebApp webApp) throws Exception {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeader(scanner));
        ResponseEntity<ScanSummaries> response = restTemplate.exchange(scanner.getApiUrl() + "/api-internal/sites/"+webApp.getScanId()+"/scan_summaries",
                HttpMethod.GET, entity, ScanSummaries.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            // TODO process response
        } else {
            throw new ApiClientException("Unable to get scan statuses for given WebApp");
        }
        return false;
    }

    private HttpHeaders prepareAuthHeader(Scanner scanner) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(Constants.HEADER_AUTHORIZATION, vaultHelper.getPassword(scanner.getApiKey()));
        return httpHeaders;
    }

    /**
     * Method which load vulnerabilities for ended scan. First it load IssueDefinitions. Then it call api to get scan details for particular
     * webapp. Finally it get issuedetails for given detected vulnerabilities.
     *
     * @param scanner on which request is being executed
     * @param webApp of which to load vulnerabilities
     * @param paginator vulneariblitiy paginator
     * @param oldVulns old vulns to set statuses
     * @return information about status of operation
     */
    @Override
    public Boolean loadVulnerabilities(Scanner scanner, WebApp webApp, String paginator, List<WebAppVuln> oldVulns) throws Exception {
        return null;
    }

    /**
     * Method which get issueDetails from Burp API. this is reusable list that create connection with scan results and issue in order to
     * create description for WebAppVuln.
     * @param scanner on which details will be loaded
     * @return list of details
     */
    private List<IssueDetail> getIssueDetailsFromBurp(Scanner scanner) throws ApiClientException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeader(scanner));
        ResponseEntity<GetIssueDetails> response = restTemplate.exchange(scanner.getApiUrl() + "/api-internal/issue_definitions",
                HttpMethod.GET, entity, GetIssueDetails.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            return Objects.requireNonNull(response.getBody()).getIssueDetails();
        } else {
            throw new ApiClientException("Cannot get issue details");
        }
    }

    /**
     * Method is calling Burp API to get scan configuration and then it saves it. If scan configuration is not accessible
     * Method returns false.
     *
     * @param scanner scanner to initialize
     * @return info about result of a operation
     */
    @Override
    public boolean initialize(Scanner scanner) throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException, Exception {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeader(scanner));
        ResponseEntity<ScanConfiguration> response = restTemplate.exchange(scanner.getApiUrl() + "/api-internal/scan-configurations",
                HttpMethod.GET, entity, ScanConfiguration.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            // TODO process response
        } else {
            throw new ApiClientException("Unable to get scan statuses for given WebApp");
        }
        return false;
    }

    /**
     * Method verify if scannerType.name eqials predefined name of Burp EE scanner and if scanner is initialized
     *
     * @param scanner of a scanner to check
     * @return decision wether particular client can execute request or not
     */

    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_BURP) && scanner.getStatus();
    }

    /**
     * Method verify if scannerType.name eqials predefined name of Burp EE scanner
     *
     * @param scanner to check
     * @return decision wether particular client can execute request or not
     */
    @Override
    public boolean canProcessInitRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_BURP);
    }

    /**
     * Method verify if scannerType.name eqials predefined name of Burp EE scanner
     *
     * @param scannerType of a scanner to check
     * @return decision wether particular client can execute request or not
     */
    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_BURP);
    }

    /**
     * Saving scanner from GUI. ScannerModel is form from frontend app.
     * Use proxies repo and routingDomain in order to set proper connections.
     *
     * @param scannerModel model from GUI to create scanner
     */
    @Override
    public void saveScanner(ScannerModel scannerModel) {
        if (StringUtils.isNotBlank(scannerModel.getApiUrl()) && StringUtils.isNotBlank(scannerModel.getApiKey()) && scannerModel.getScannerType().equals(Constants.SCANNER_TYPE_BURP)){
            Scanner burp = new Scanner();
            ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
            Proxies proxy = null;
            if(scannerModel.getRoutingDomain() != 0)
                burp.setRoutingDomain(routingDomainRepository.getOne(scannerModel.getRoutingDomain()));
            if (scannerModel.getProxy() != 0)
                proxy = proxiesRepository.getOne(scannerModel.getProxy());
            burp.setProxies(proxy);
            burp.setApiUrl(scannerModel.getApiUrl());
            burp.setStatus(false);
            burp.setScannerType(scannerType);
            // api key put to vault
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(scannerModel.getApiKey(), uuidToken )) {
                burp.setApiKey(uuidToken);
            } else {
                burp.setApiKey(scannerModel.getApiKey());
            }
            scannerRepository.save(burp);
        }
    }
}
