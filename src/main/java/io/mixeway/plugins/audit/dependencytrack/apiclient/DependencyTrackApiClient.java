package io.mixeway.plugins.audit.dependencytrack.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.audit.dependencytrack.model.*;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
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
public class DependencyTrackApiClient implements SecurityScanner {
    private final static Logger log = LoggerFactory.getLogger(DependencyTrackApiClient.class);
    private DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final SecureRestTemplate secureRestTemplate;
    private final VaultOperations operations;
    private final ProxiesRepository proxiesRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final SoftwarePacketRepository softwarePacketRepository;
    private final StatusRepository statusRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    private final CodeProjectRepository codeProjectRepository;
    @Autowired
    public DependencyTrackApiClient(ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository, StatusRepository statusRepository,
                                    SecureRestTemplate secureRestTemplate, VaultOperations operations, CodeProjectRepository codeProjectRepository,
                                    ProxiesRepository proxiesRepository, RoutingDomainRepository routingDomainRepository,
                                    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository, SoftwarePacketRepository softwarePacketRepository){
        this.scannerRepository = scannerRepository;
        this.operations = operations;
        this.statusRepository = statusRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.secureRestTemplate = secureRestTemplate;
        this.scannerTypeRepository = scannerTypeRepository;
        this.proxiesRepository = proxiesRepository;
        this.softwarePacketRepository = softwarePacketRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
    }

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
                } else {
                    log.error("Unable to get Findings from Dependency Track for project {}", codeProject.getdTrackUuid());
                }
            } catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e){
                log.error("Error during OpenSource loading vulnerabilities for {} with code {}", codeProject.getName(), e.getLocalizedMessage());
            }
        }

    }
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

    private void createVulns(CodeProject codeProject, List<DTrackVuln> body) {
        codeProject.getSoftwarePackets().removeAll(codeProject.getSoftwarePackets());
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
                        softwarePacketVulnerabilityRepository.save(vulnerability);
                    }
                }
            }
            codeProjectRepository.save(codeProject);
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
        VaultResponseSupport<Map<String,Object>> password = operations.read("secret/"+scanner.getApiKey());
        HttpHeaders headers = new HttpHeaders();
        assert password != null;
        headers.set(Constants.DTRACK_AUTH_HEADER, Objects.requireNonNull(password.getData()).get("password").toString());
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
        scanner.setApiKey(UUID.randomUUID().toString());
        scanner.setStatus(false);
        scanner.setScannerType(scannerType);
        // api key put to vault
        Map<String, String> apiKeyMap = new HashMap<>();
        apiKeyMap.put("password", scannerModel.getApiKey());
        operations.write("secret/"+scanner.getApiKey(), apiKeyMap);
        scannerRepository.save(scanner);

    }
}
