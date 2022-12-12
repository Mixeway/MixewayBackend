package io.mixeway.scanmanager.integrations.nexusiq.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Proxies;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.scannertype.FindScannerTypeService;
import io.mixeway.scanmanager.integrations.burpee.model.Scan;
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
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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
        return false;
    }

    @Override
    public boolean canProcessRequest() {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        return scanner !=null;
    }

    @Override
    public void loadVulnerabilities(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        if (scanner!=null) {

        }
    }

    @Override
    public boolean createProject(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return false;
    }

    @Override
    public List<Projects> getProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Scanner scanner = getScannerService.getScannerByType(findScannerTypeService.findByName(Constants.SCANNER_TYPE_NEXUS_IQ));
        List<Projects> projects = new ArrayList<>();
        if (scanner!=null) {
            List<Synchro> synchroList = loadNexusData(scanner);
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
