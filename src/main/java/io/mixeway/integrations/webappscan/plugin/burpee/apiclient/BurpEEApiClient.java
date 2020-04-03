package io.mixeway.integrations.webappscan.plugin.burpee.apiclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.webappscan.plugin.acunetix.apiclient.AcunetixApiClient;
import io.mixeway.integrations.webappscan.plugin.burpee.model.*;
import io.mixeway.integrations.webappscan.service.WebAppScanClient;
import io.mixeway.pojo.ApiClientException;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.model.ScannerModel;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.Predicate;

/**
 * @author gsiewruk
 */
@Component
public class BurpEEApiClient implements SecurityScanner, WebAppScanClient {
    private final static Logger log = LoggerFactory.getLogger(AcunetixApiClient.class);
    private final ScannerTypeRepository scannerTypeRepository;
    private final ProxiesRepository proxiesRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final VaultHelper vaultHelper;
    private final ScannerRepository scannerRepository;
    private final SecureRestTemplate secureRestTemplate;
    private final NessusScanTemplateRepository nessusScanTemplateRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final StatusRepository statusRepository;
    private final WebAppRepository webAppRepository;
    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public BurpEEApiClient(ScannerTypeRepository scannerTypeRepository, ProxiesRepository proxiesRepository,
                           RoutingDomainRepository routingDomainRepository, ScannerRepository scannerRepository,
                           VaultHelper vaultHelper, SecureRestTemplate secureRestTemplate,
                           NessusScanTemplateRepository nessusScanTemplateRepository, WebAppVulnRepository webAppVulnRepository,
                           StatusRepository statusRepository, WebAppRepository webAppRepository){
        this.scannerTypeRepository = scannerTypeRepository;
        this.proxiesRepository = proxiesRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.vaultHelper = vaultHelper;
        this.scannerRepository = scannerRepository;
        this.secureRestTemplate = secureRestTemplate;
        this.nessusScanTemplateRepository = nessusScanTemplateRepository;
        this.statusRepository = statusRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.webAppRepository = webAppRepository;
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
        try {
            ScanRequest scanRequest = new ScanRequest(webApp, scanner);
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
            HttpEntity<ScanRequest> entity = new HttpEntity<>(scanRequest);
            ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() + "/api/"+vaultHelper.getPassword(scanner.getApiKey()) + "/v0.1/scan",
                    HttpMethod.POST, entity, String.class);
            if (response.getStatusCode().equals(HttpStatus.CREATED)) {
                if (StringUtils.isBlank(webApp.getScanId())) {
                    webApp.setScanId(response.getHeaders().getLocation().toString());
                }
                webApp.setRunning(true);
                log.info("Web Application scan for {} started on {} ({}) scanId <{}>", webApp.getUrl(),scanner.getScannerType().getName(),scanner.getApiUrl(),webApp.getScanId());
            }
        } catch (HttpClientErrorException e){
            log.error("Cannot run scan for {} - {}", webApp.getUrl(), e.getStatusCode());
        }
    }

    /**
     * Required for WebAppScanClient, but in scope of Burp EE api client method is not applicable.
     * Each time scan is being configured it is being executed at a same moment, thus there is only one method - runScan
     * to configure and run scan.
     */
    @Override
    public void configureWebApp(WebApp webApp, Scanner scanner) {

    }

    /**
     * Cheacking if scan is finished.
     * Get Scan Summaries from burp, then veryfiy if there is at least one scan in state QUEUED or RUNNING and if so return false
     *
     * @param scanner use for scanner REST API
     * @param webApp to be checked
     * @return  true if scan is done
     */
    @Override
    public Boolean isScanDone(Scanner scanner, WebApp webApp) throws Exception {
        try {
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
            ResponseEntity<ScanResults> response = restTemplate.exchange(scanner.getApiUrl() + "/api/"+ vaultHelper.getPassword(scanner.getApiKey()) + "/v0.1/scan/"+ webApp.getScanId(),
                    HttpMethod.GET, null, ScanResults.class);
            return (response.getStatusCode().equals(HttpStatus.OK) &&
                    (Objects.requireNonNull(response.getBody()).getScan_status().equals(Constants.BURP_STATUS_FAILED)
                            || response.getBody().getScan_status().equals(Constants.BURP_STATUS_SUCCEEDED)));
        } catch (HttpClientErrorException e){
            log.error("Cannot check status of scan for {} - {}", webApp.getUrl(),e.getStatusCode());
        }
        return false;
    }

    /**
     * Configuring Headers for Burp API, Setting Authorization: apiKey
     *
     * @param scanner config header for given scanner
     * @return prepared HttpHeaders
     */
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
        try {
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
            ResponseEntity<ScanResults> response = restTemplate.exchange(scanner.getApiUrl() + "/api/"+ vaultHelper.getPassword(scanner.getApiKey()) + "/v0.1/scan/"+ webApp.getScanId(),
                    HttpMethod.GET, null, ScanResults.class);
            if (response.getStatusCode().equals(HttpStatus.OK)) {
                for (IssueEvents issue : Objects.requireNonNull(response.getBody()).getIssue_events()) {
                    WebAppVuln vuln = new WebAppVuln(webApp, issue.getIssue());
                    Optional<WebAppVuln> webAppVulnOptional = oldVulns.stream().filter(webAppVuln -> webAppVuln.getSeverity().equals(vuln.getSeverity()) &&
                            webAppVuln.getLocation().equals(vuln.getLocation()) && webAppVuln.getName().equals(vuln.getName())).findFirst();
                    if (webAppVulnOptional.isPresent())
                        vuln.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
                    else
                        vuln.setStatus(statusRepository.findByName(Constants.STATUS_NEW));
                    webAppVulnRepository.save(vuln);
                }
                webApp.setLastExecuted(sdf.format(new Date()));
                webApp.setRunning(false);
                webAppRepository.save(webApp);
                log.info("Successfully loaded vulnerabilities for {}", webApp.getUrl());
                return true;
            }
        } catch (HttpClientErrorException e){
            log.error("Cannot get issue details for {}", scanner.getApiUrl());
        }
        return false;
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
        try {
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
            HttpEntity<String> entity = new HttpEntity<>(prepareAuthHeader(scanner));
            ResponseEntity<ScanConfiguration> response = restTemplate.exchange(scanner.getApiUrl() + "/api-internal/scan-configurations",
                    HttpMethod.GET, entity, ScanConfiguration.class);
            if (response.getStatusCode().equals(HttpStatus.OK)) {
                for (Configuration configuration : response.getBody().getScan_configurations()){
                    if (configuration.getName().equals(Constants.BURP_CONFIG_CRAWL) || configuration.getName().equals(Constants.BURP_CONFIG_AUDIT)) {
                        NessusScanTemplate nst = new NessusScanTemplate(configuration.getName(), configuration.getId(), scanner);
                        nessusScanTemplateRepository.save(nst);
                    }
                }
                scanner.setStatus(true);
                return true;
            }
        } catch (HttpClientErrorException e){
            log.error("Cannot initialize scanner {} - {}", scanner.getApiUrl(), e.getStatusCode());
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
