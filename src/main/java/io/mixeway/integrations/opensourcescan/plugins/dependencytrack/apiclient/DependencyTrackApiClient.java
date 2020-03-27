package io.mixeway.integrations.opensourcescan.plugins.dependencytrack.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.opensourcescan.plugins.dependencytrack.model.*;
import io.mixeway.integrations.opensourcescan.model.Projects;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanClient;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class DependencyTrackApiClient implements SecurityScanner, OpenSourceScanClient {
    private final static Logger log = LoggerFactory.getLogger(DependencyTrackApiClient.class);
    private DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final SecureRestTemplate secureRestTemplate;
    private final VaultHelper vaultHelper;
    private final ProxiesRepository proxiesRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final SoftwarePacketRepository softwarePacketRepository;
    private final StatusRepository statusRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CiOperationsRepository ciOperationsRepository;

    public DependencyTrackApiClient(ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository, StatusRepository statusRepository,
                                    SecureRestTemplate secureRestTemplate, VaultHelper vaultHelper, CodeProjectRepository codeProjectRepository,
                                    ProxiesRepository proxiesRepository, RoutingDomainRepository routingDomainRepository,
                                    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository, SoftwarePacketRepository softwarePacketRepository,
                                    CiOperationsRepository ciOperationsRepository){
        this.scannerRepository = scannerRepository;
        this.vaultHelper = vaultHelper;
        this.statusRepository = statusRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.ciOperationsRepository = ciOperationsRepository;
        this.secureRestTemplate = secureRestTemplate;
        this.scannerTypeRepository = scannerTypeRepository;
        this.proxiesRepository = proxiesRepository;
        this.softwarePacketRepository = softwarePacketRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
    }

    @Override
    public boolean canProcessRequest(CodeProject codeProject) {
        List<Scanner> openSourceScanners = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        return (openSourceScanners.size() == 1 );
    }

    @Override
    public boolean canProcessRequest() {
        List<Scanner> openSourceScanners = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        return (openSourceScanners.size() == 1 );
    }

    @Transactional
    @Override
    public void loadVulnerabilities(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        List<Scanner> dTrack = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        //Multiple dTrack instances not yet supported
        if (dTrack.size() == 1 && codeProject.getdTrackUuid() != null){
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(dTrack.get(0));
            HttpHeaders headers = prepareAuthHeader(dTrack.get(0));
            HttpEntity<String> entity = new HttpEntity<>(headers);
            try {
                ResponseEntity<List<DTrackVuln>> response = restTemplate.exchange(dTrack.get(0).getApiUrl() +
                        "/api/v1/vulnerability/project/" + codeProject.getdTrackUuid(), HttpMethod.GET, entity, new ParameterizedTypeReference<List<DTrackVuln>>() {
                });
                if (response.getStatusCode() == HttpStatus.OK) {
                    createVulns(codeProject, Objects.requireNonNull(response.getBody()));
                    updateCiOperations(codeProject);
                } else {
                    log.error("Unable to get Findings from Dependency Track for project {}", codeProject.getdTrackUuid());
                }
            } catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e){
                log.error("Error during OpenSource loading vulnerabilities for {} with code {}", codeProject.getName(), e.getLocalizedMessage());
            }
        }

    }

    private void updateCiOperations(CodeProject codeProject) {
        Optional<CiOperations> operations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (operations.isPresent()){
            CiOperations operation = operations.get();
            operation.setOpenSourceScan(true);
            int highVulns = (int) softwarePacketVulnerabilityRepository
                    .getSoftwareVulnsForCodeProject(codeProject.getId()).stream().filter(v -> v.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
            int critVulns = (int) softwarePacketVulnerabilityRepository
                    .getSoftwareVulnsForCodeProject(codeProject.getId()).stream().filter(v -> v.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
            operation.setOpenSourceCrit(critVulns);
            operation.setOpenSourceHigh(highVulns);
            ciOperationsRepository.save(operation);
        }
    }

    @Override
    public boolean createProject(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        List<Scanner> dTrack = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        //Multiple dTrack instances not yet supported
        if (dTrack.size() == 1 && (codeProject.getdTrackUuid() == null || codeProject.getdTrackUuid().isEmpty())){
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(dTrack.get(0));
            HttpHeaders headers = prepareAuthHeader(dTrack.get(0));
            HttpEntity<DTrackCreateProject> entity = new HttpEntity<>(new DTrackCreateProject(codeProject.getName()),headers);

            try {
                ResponseEntity<DTrackCreateProjectResponse> response = restTemplate.exchange(dTrack.get(0).getApiUrl() +
                        "/api/v1/project", HttpMethod.PUT, entity, DTrackCreateProjectResponse.class);
                if (response.getStatusCode() == HttpStatus.CREATED) {
                   codeProject.setdTrackUuid(Objects.requireNonNull(response.getBody()).getUuid());
                   codeProjectRepository.save(codeProject);
                   log.info("Successfully created Dependency Track project for {} with UUID {}", codeProject.getName(),codeProject.getdTrackUuid());
                   return true;
                } else {
                    log.error("Unable to to create project Dependency Track for project {}", codeProject.getdTrackUuid());
                }
            } catch (HttpClientErrorException | HttpServerErrorException e){
                log.error("Error during Creation of project for {} with code {}", codeProject.getName(), e.getStatusCode());
            }
        }

        return false;
    }
    @Override
    public List<Projects> getProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        List<Scanner> dTrack = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        //Multiple dTrack instances not yet supported
        if (dTrack.size() == 1 ){
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(dTrack.get(0));
            HttpHeaders headers = prepareAuthHeader(dTrack.get(0));
            HttpEntity<String> entity = new HttpEntity<>(headers);

            try {
                ResponseEntity<List<Projects>> response = restTemplate.exchange(dTrack.get(0).getApiUrl() +
                        "/api/v1/project", HttpMethod.GET, entity, new ParameterizedTypeReference<List<Projects>>() {});
                if (response.getStatusCode() == HttpStatus.OK) {
                    return response.getBody();
                } else {
                    log.error("Unable to load Dependency Track projects");
                }
            } catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e){
                log.error("Error during getting Dependency Track project list {}", e.getLocalizedMessage());
            }
        }

        return null;
    }

    public void createVulns(CodeProject codeProject, List<DTrackVuln> body) {
        codeProject.getSoftwarePackets().removeAll(codeProject.getSoftwarePackets());
        codeProjectRepository.saveAndFlush(codeProject);
        for(DTrackVuln dTrackVuln : body){
            List<SoftwarePacket> softwarePackets = new ArrayList<>();
            for(Component component : dTrackVuln.getComponents()){
                Optional<SoftwarePacket> softPacket = softwarePacketRepository.findByName(component.getName()+":"+component.getVersion());
                if (softPacket.isPresent()){
                    codeProject.getSoftwarePackets().add(softPacket.get());
                    softwarePackets.add(softPacket.get());
                } else {
                    SoftwarePacket softwarePacket = new SoftwarePacket();
                    softwarePacket.setName(component.getName()+":"+component.getVersion());
                    softwarePacketRepository.save(softwarePacket);
                    codeProject.getSoftwarePackets().add(softwarePacket);
                    softwarePackets.add(softwarePacket);
                }
                for (SoftwarePacket sPacket : softwarePackets){
                    Optional<SoftwarePacketVulnerability> softwarePacketVulnerability = softwarePacketVulnerabilityRepository.findBySoftwarepacketAndName(sPacket,dTrackVuln.getVulnId());
                    if (!softwarePacketVulnerability.isPresent()){
                        SoftwarePacketVulnerability vulnerability = new SoftwarePacketVulnerability();
                        vulnerability.setSoftwarepacket(sPacket);
                        vulnerability.setName(dTrackVuln.getVulnId());
                        vulnerability.setDescription(dTrackVuln.getDescription());
                        vulnerability.setSeverity(dTrackVuln.getSeverity());
                        vulnerability.setInserted(dateFormat.format(new Date()));
                        vulnerability.setProject(codeProject.getCodeGroup().getProject());
                        vulnerability.setScore(createScore(dTrackVuln.getSeverity()));
                        vulnerability.setStatus(statusRepository.findByName(Constants.STATUS_EXISTING));
                        softwarePacketVulnerabilityRepository.saveAndFlush(vulnerability);
                    }
                }
            }
            codeProjectRepository.saveAndFlush(codeProject);
        }
    }

    private Double createScore(String severity) {
        if (severity.equals(Constants.API_SEVERITY_CRITICAL.toUpperCase())){
            return 10.0;
        } else if (severity.equals(Constants.API_SEVERITY_HIGH.toUpperCase())){
            return 7.0;
        } else if (severity.equals(Constants.API_SEVERITY_MEDIUM.toUpperCase())){
            return 4.0;
        } else
            return 1.0;
    }

    private HttpHeaders prepareAuthHeader(Scanner scanner) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(Constants.DTRACK_AUTH_HEADER, vaultHelper.getPassword(scanner.getApiKey()));
        return headers;
    }

    @Override
    public boolean initialize(Scanner scanner) throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException, Exception {
        List<Scanner> dTrack = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        //Multiple dTrack instances not yet supported
        if (dTrack.size() == 1 ){
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(dTrack.get(0));
            HttpHeaders headers = prepareAuthHeader(dTrack.get(0));
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(dTrack.get(0).getApiUrl() +
                    "/api/version", HttpMethod.GET, entity, String.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                return true;
            }
            else {
                log.error("Unable to initialize scanner {}",scanner.getApiUrl());
                return false;
            }
        }
        return false;
    }

    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_DEPENDENCYTRACK) && scanner.getStatus();
    }

    @Override
    public boolean canProcessInitRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_DEPENDENCYTRACK);
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_DEPENDENCYTRACK);
    }

    @Override
    public void saveScanner(ScannerModel scannerModel) throws Exception {
        Scanner scanner = new Scanner();
        ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
        Proxies proxy = null;
        if (scannerModel.getProxy() != 0)
            proxy = proxiesRepository.getOne(scannerModel.getProxy());
        if(scannerModel.getRoutingDomain() == 0)
            throw new Exception("Null Domain");
        else
            scanner.setRoutingDomain(routingDomainRepository.getOne(scannerModel.getRoutingDomain()));
        scanner.setProxies(proxy);
        scanner.setApiUrl(scannerModel.getApiUrl());
        String uuid = UUID.randomUUID().toString();
        scanner.setStatus(false);
        scanner.setScannerType(scannerType);
        if (vaultHelper.savePassword(scannerModel.getApiKey(), uuid)){
            scanner.setApiKey(uuid);
        } else {
            scanner.setApiKey(scannerModel.getApiKey());
        }
        scannerRepository.save(scanner);

    }
}
