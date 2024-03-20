package io.mixeway.scanmanager.integrations.nexusiq.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.scannertype.FindScannerTypeService;
import io.mixeway.domain.service.softwarepackage.GetOrCreateSoftwarePacketService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.burpee.model.Scan;
import io.mixeway.scanmanager.integrations.dependencytrack.model.DTrackVuln;
import io.mixeway.scanmanager.integrations.nexusiq.model.*;
import io.mixeway.scanmanager.model.Projects;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanClient;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.UnknownContentTypeException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
@Log4j2
public class NexusIqApiClient implements SecurityScanner, OpenSourceScanClient {
    private final VaultHelper vaultHelper;
    private final GetScannerService getScannerService;
    private final FindScannerTypeService findScannerTypeService;
    private final ScannerRepository scannerRepository;
    private final ProxiesRepository proxiesRepository;
    private final SecureRestTemplate secureRestTemplate;
    private final FindCodeProjectService findCodeProjectService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final GetOrCreateSoftwarePacketService getOrCreateSoftwarePacketService;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final CiOperationsRepository ciOperationsRepository;

    private HttpHeaders prepareAuthHeader(Scanner scanner) {
        HttpHeaders headers = new HttpHeaders();
        String auth = scanner.getUsername() + ":" + vaultHelper.getPassword(scanner.getPassword());
        byte[] encodedAuth = Base64.encodeBase64(
                auth.getBytes(StandardCharsets.US_ASCII) );
        String authHeader = "Basic " + new String( encodedAuth );
        headers.set(Constants.HEADER_AUTHORIZATION, authHeader);
        return headers;
    }
    @Override
    public boolean initialize(Scanner scanner) throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException, Exception {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = prepareAuthHeader(scanner);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(scanner.getApiUrl() +
                "/api/v2/organizations", HttpMethod.GET, entity, String.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            scanner.setStatus(true);
            scannerRepository.save(scanner);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXUS_IQ);
    }

    @Override
    public boolean canProcessInitRequest(Scanner scanner) {
        return  scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXUS_IQ);
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_NEXUS_IQ);
    }

    @Override
    public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
        if (getScannerService.getScannerByApiUrlAndType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ), scannerModel.getApiUrl() ).isPresent()){
            log.info("[NexusIq] Scanner already exists with apiUrl {}", scannerModel.getApiKey());
        } else {
            String uuid = UUID.randomUUID().toString();
            Scanner scanner = new Scanner();
            scanner.setApiUrl(scannerModel.getApiUrl());
            scanner.setScannerType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
            scanner.setUsername(scannerModel.getUsername());
            scanner.setStatus(false);
            Proxies proxy = null;
            if (scannerModel.getProxy() != 0) {
                proxy = proxiesRepository.getOne(scannerModel.getProxy());
                scanner.setProxies(proxy);
            }
            if (vaultHelper.savePassword(scannerModel.getApiKey(), uuid)){
                scanner.setPassword(uuid);
            } else {
                scanner.setPassword(scannerModel.getPassword());
            }
            scannerRepository.save(scanner);
            log.info("[NexusIq] Successfully saved scanner with api {}", scanner.getApiUrl());
            return scanner;
        }
        return null;
    }

    @Override
    public boolean canProcessRequest(CodeProject codeProject) {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        return scanner !=null && scanner.getStatus() && StringUtils.isNotBlank(codeProject.getdTrackUuid()) && StringUtils.isNotBlank(codeProject.getRemotename());
    }

    @Override
    public boolean canProcessRequest() {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        return scanner !=null && scanner.getStatus();
    }

    @Override
    public void loadVulnerabilities(CodeProject codeProject, CodeProjectBranch codeProjectBranch) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        if (scanner!=null) {
            String getRawDataReportUrl = getRawDataUrl(scanner, codeProject);
            RawReport rawReport = getRawReport(scanner, getRawDataReportUrl);
            try {
                if (rawReport != null )
                    saveVulnerabilities(codeProject, rawReport, codeProjectBranch);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            updateCiOperations(codeProject);
        }
    }

    //TODO move it to domain
    private void updateCiOperations(CodeProject codeProject) {
        Optional<CiOperations> operations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (operations.isPresent()){
            CiOperations operation = operations.get();
            operation.setOpenSourceScan(true);
            List<ProjectVulnerability> vulnsForCp = vulnTemplate.projectVulnerabilityRepository
                    .getSoftwareVulnsForCodeProject(codeProject.getId());
            int highVulns = (int) vulnsForCp.stream().filter(v -> v.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
            int critVulns = (int) vulnsForCp.stream().filter(v -> v.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
            operation.setOpenSourceCrit(critVulns);
            operation.setOpenSourceHigh(highVulns);
            operation.setResult((critVulns > 3 || highVulns > 10) ? "Not Ok" : "Ok");
            ciOperationsRepository.save(operation);
        }
    }


    private void saveVulnerabilities(CodeProject codeProject, RawReport rawReport, CodeProjectBranch codeProjectBranch) throws URISyntaxException {
        List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository
                .findByVulnerabilitySourceAndCodeProject(vulnTemplate.SOURCE_OPENSOURCE, codeProject);
        List<ProjectVulnerability> projectVulnerabilitiesFromReport = new ArrayList<>();
        for (ReportEntry reportEntry : rawReport.getComponents()) {
            String componentName = "";
            String componentVersion = "";
            try {
                componentName = reportEntry.getComponentIdentifier().getFormat().equals(Constants.NPM) ?
                        reportEntry.getComponentIdentifier().getCoordinates().getPackageId() :
                        reportEntry.getComponentIdentifier().getCoordinates().getGroupId()+":"+reportEntry.getComponentIdentifier().getCoordinates().getArtifactId();
                componentVersion = reportEntry.getComponentIdentifier().getCoordinates().getVersion();
                componentName = "null:null".equals(componentName) ? reportEntry.getDisplayName().split(" ")[0] : componentName;
            } catch (NullPointerException e) {
                componentName = reportEntry.getDisplayName();
                componentVersion = "unknown";
            }
            try {
                SoftwarePacket softwarePacket = getOrCreateSoftwarePacketService.getOrCreateSoftwarePacket(componentName, componentVersion);

                try {
                    if (reportEntry.getSecurityData() != null && !reportEntry.getSecurityData().getSecurityIssues().isEmpty()) {
                        for (SecurityIssues securityIssues : reportEntry.getSecurityData().getSecurityIssues()) {
                            Vulnerability vulnerability = createOrGetVulnerabilityService.createOrGetVulnerability(securityIssues.getReference());
                            if (vulnerability.getSeverity() != null && vulnerability.getSeverity().equals(Constants.SKIP_VULENRABILITY)){
                                continue;
                            }
                            ProjectVulnerability projectVulnerability = new ProjectVulnerability(softwarePacket,
                                    codeProject,
                                    vulnerability,
                                    "Read more: " + securityIssues.getUrl(),
                                    "",
                                    setSeverity(securityIssues.getSeverity()),
                                    null,
                                    null,
                                    null,
                                    vulnTemplate.SOURCE_OPENSOURCE,
                                    null,
                                    codeProjectBranch);
                            projectVulnerability.setStatus(vulnTemplate.STATUS_NEW);
                            projectVulnerabilitiesFromReport.add(projectVulnerability);
                        }
                    }
                } catch (NullPointerException e) {
                    log.info("test");
                }
            } catch (IncorrectResultSizeDataAccessException e) {
                log.info("[Nexus-IQ] IncorrectResultSizeDataAccessException for SoftwarePacket {} : {} during loading of app {}",componentName, componentVersion, codeProject.getName());
            }
        }
        vulnTemplate.vulnerabilityPersistListSoftware(oldVulns,projectVulnerabilitiesFromReport);
        if (codeProject.getEnableJira()) {
            vulnTemplate.processBugTracking(codeProject, vulnTemplate.SOURCE_OPENSOURCE);
        }
        log.debug("[Nexus-IQ] Loaded {} vulnerabilities for {}", projectVulnerabilitiesFromReport.size(), codeProject.getName());
    }

    private String setSeverity(Double severity) {
        if (severity >= 9){
            return Constants.API_SEVERITY_CRITICAL;
        } else if (severity < 9 && severity >= 7.5){
            return Constants.API_SEVERITY_HIGH;
        } else if (severity < 7.5 && severity >= 5){
            return Constants.API_SEVERITY_MEDIUM;
        } else
            return Constants.API_SEVERITY_LOW;
    }

    private RawReport getRawReport(Scanner scanner, String getRawDataReportUrl) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = prepareAuthHeader(scanner);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<RawReport> response = restTemplate.exchange(scanner.getApiUrl() +
                    "/" + getRawDataReportUrl, HttpMethod.GET, entity, RawReport.class);
            if (response.getStatusCode().equals(HttpStatus.OK)) {
                return response.getBody();
            } else {
                return null;
            }
        } catch (HttpClientErrorException e){
            log.warn("[Nexus-IQ] HTTP Error {} during getting report for {}", e.getStatusCode(), getRawDataReportUrl);
            return null;
        }
    }

    private String getRawDataUrl(Scanner scanner, CodeProject codeProject) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        try {
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
            HttpHeaders headers = prepareAuthHeader(scanner);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<List<GetReports>> response = restTemplate.exchange(scanner.getApiUrl() +
                    "/api/v2/reports/applications/" + codeProject.getdTrackUuid(), HttpMethod.GET, entity, new ParameterizedTypeReference<List<GetReports>>() {
            });
            if (response.getStatusCode().equals(HttpStatus.OK)) {
                if (response.getBody().size() > 1) {
                    GetReports getReports = response.getBody().stream().filter(gr -> gr.getStage().equals(Constants.NEXUS_STAGE_BUILD)).findFirst().orElse(new GetReports());
                    if (getReports.getReportDataUrl() == null) {
                        getReports = response.getBody().stream().filter(gr -> gr.getStage().equals(Constants.NEXUS_STAGE_SOURCE)).findFirst().orElse(new GetReports());
                    }
                    return getReports.getReportDataUrl();
                } else if (response.getBody().size() == 1) {
                    return response.getBody().get(0).getReportDataUrl();
                } else {
                    return null;
                }
            }
        } catch (UnknownContentTypeException | HttpClientErrorException e){
            log.warn("[Nexus-IQ] Problem in getting raw data URL for {}", codeProject.getName());
        }
        return null;
    }

    @Override
    public boolean createProject(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        this.autoDiscoveryProject(codeProject);
        return true;
    }

    @Override
    public List<Projects> getProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        List<Projects> projects = new ArrayList<>();
        if (scanner!=null) {
            List<Synchro> synchroList = loadNexusDataSimplified(scanner);
            for(Synchro synchro : synchroList){
                projects.add(
                        Projects.builder()
                        .name(synchro.getName())
                        .uuid(synchro.getId())
                        .build()
                );
            }
            return projects;
        }
        return null;
    }

    @Override
    public void autoDiscovery() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        if (scanner != null) {
            List<CodeProject> codeProjectsToSynchro = findCodeProjectService.findProjectWithoutOSIntegration();
            log.info("[Nexus-IQ] Found {} project to perform auto discovery on", codeProjectsToSynchro.size());
            if (codeProjectsToSynchro.size() == 0) {
                log.info("[Nexus-IQ] Nothing to synchro");
                return;
            }

            List<Synchro> synchroList = loadNexusData(scanner);
            log.info("[Nexus-IQ] Starting synchronization, found {} resources on remote nexus", synchroList.size());
            for (CodeProject codeProject : codeProjectsToSynchro){
                Synchro sync = synchroList.stream().filter(s -> s.getRepoUrl().replace(".git","").equals(codeProject.getRepoUrl().replace(".git","")))
                        .findAny().orElse(null);
                if (sync != null){
                    updateCodeProjectService.updateOpenSourceSettings(codeProject,sync.getId(), sync.getName());
                    log.info("[Nexus-IQ] Synchronized infos for {} with {} and {}", codeProject.getName(), sync.getId(), sync.getName());
                }
            }
        }
        log.info("[Nexus-IQ] Synchronization completed.");
    }
    public void autoDiscoveryProject(CodeProject codeProject) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        if (scanner != null) {

            List<Synchro> synchroList = loadNexusData(scanner);
            log.info("[Nexus-IQ] Starting synchronization, found {} resources on remote nexus", synchroList.size());
            Synchro sync = synchroList.stream().filter(s -> s.getRepoUrl().replace(".git","").equals(codeProject.getRepoUrl().replace(".git","")))
                    .findAny().orElse(null);
            if (sync != null){
                updateCodeProjectService.updateOpenSourceSettings(codeProject,sync.getId(), sync.getName());
                log.info("[Nexus-IQ] Synchronized infos for {} with {} and {}", codeProject.getName(), sync.getId(), sync.getName());
            }
        }
        log.info("[Nexus-IQ] Synchronization completed.");
    }

    private List<Synchro> loadNexusData(Scanner scanner) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        List<Synchro> synchroList = new ArrayList<>();
        for (Application application : getApplications(scanner).getApplications()){
            try {
                Synchro synchroEntry = new Synchro();
                synchroEntry.setId(application.getId());
                synchroEntry.setName(application.getPublicId());
                synchroEntry.setRepoUrl(getSourceControl(application.getId(), scanner).getRepositoryUrl());
                synchroList.add(synchroEntry);
            } catch (HttpClientErrorException e){
                log.warn("[Nexus-IQ] Application {} on nexus has no repourl, HTTP_STATUS {}", application.getPublicId(), e.getStatusCode());
            }
        }
        return synchroList;
    }
    // NO Repo URL
    private List<Synchro> loadNexusDataSimplified(Scanner scanner) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        List<Synchro> synchroList = new ArrayList<>();
        for (Application application : getApplications(scanner).getApplications()){
            try {
                Synchro synchroEntry = new Synchro();
                synchroEntry.setId(application.getId());
                synchroEntry.setName(application.getPublicId());
                synchroList.add(synchroEntry);
            } catch (HttpClientErrorException e){
                log.debug("[Nexus-IQ] Application {} on nexus has no repourl, HTTP_STATUS {}", application.getPublicId(), e.getStatusCode());
            }
        }
        return synchroList;
    }

    private Applications getApplications(Scanner scanner) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = prepareAuthHeader(scanner);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<Applications> response = restTemplate.exchange(scanner.getApiUrl() +
                "/api/v2/applications", HttpMethod.GET, entity, Applications.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
           return response.getBody();
        } else {
            return null;
        }
    }
    private SourceControl getSourceControl(String id, Scanner scanner) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = prepareAuthHeader(scanner);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<SourceControl> response = restTemplate.exchange(scanner.getApiUrl() +
                "/api/v2/sourceControl/application/"+id, HttpMethod.GET, entity, SourceControl.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            return response.getBody();
        } else {
            return null;
        }
    }
}
