package io.mixeway.integrations.opensourcescan.plugins.dependencytrack.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.opensourcescan.plugins.dependencytrack.model.*;
import io.mixeway.integrations.opensourcescan.model.Projects;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanClient;
import io.mixeway.pojo.SecureRestTemplate;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.model.ScannerModel;
import io.mixeway.rest.project.model.SASTProject;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

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
    private final CodeProjectRepository codeProjectRepository;
    private final CiOperationsRepository ciOperationsRepository;
    private final VulnTemplate vulnTemplate;

    public DependencyTrackApiClient(ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository,
                                    SecureRestTemplate secureRestTemplate, VaultHelper vaultHelper, CodeProjectRepository codeProjectRepository,
                                    ProxiesRepository proxiesRepository, RoutingDomainRepository routingDomainRepository,
                                    VulnTemplate vulnTemplate, SoftwarePacketRepository softwarePacketRepository,
                                    CiOperationsRepository ciOperationsRepository){
        this.scannerRepository = scannerRepository;
        this.vaultHelper = vaultHelper;
        this.codeProjectRepository = codeProjectRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.ciOperationsRepository = ciOperationsRepository;
        this.secureRestTemplate = secureRestTemplate;
        this.scannerTypeRepository = scannerTypeRepository;
        this.proxiesRepository = proxiesRepository;
        this.softwarePacketRepository = softwarePacketRepository;
        this.vulnTemplate = vulnTemplate;
    }

    @Override
    public boolean canProcessRequest(CodeProject codeProject) {
        List<Scanner> openSourceScanners = scannerRepository.findByScannerTypeAndStatus(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK), true);
        return (openSourceScanners.size() == 1 );
    }

    @Override
    public boolean canProcessRequest() {
        List<Scanner> openSourceScanners = scannerRepository.findByScannerTypeAndStatus(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK),true);
        return (openSourceScanners.size() == 1 );
    }

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

    @Override
    public boolean createProject(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        List<Scanner> dTrack = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        //Multiple dTrack instances not yet supported
        if (dTrack.size() == 1 && !isProjectAlreadyDefined(codeProject,dTrack.get(0)) && (codeProject.getdTrackUuid() == null || codeProject.getdTrackUuid().isEmpty())){
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

        return StringUtils.isNotBlank(codeProject.getdTrackUuid());
    }
    private boolean isProjectAlreadyDefined(CodeProject codeProject, Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        List<Projects> sastProjects = getProjects();
        List<Projects> filteredProject = sastProjects.stream().filter(p -> p.getName().equals(codeProject.getName())).collect(Collectors.toList());
        if (filteredProject.size() == 1){
            codeProject.setdTrackUuid(filteredProject.get(0).getUuid());
            codeProjectRepository.save(codeProject);
            log.info("[DependencyTrack] No need to create new project on Dtrack - project {} already exists", codeProject.getName());
            return true;
        } else if (filteredProject.size() == 0){
            return false;
        } else {
            log.warn("[DependencyTrack] Something strage durign project creation, list of project with name `{}` is size of: {}", codeProject.getName(), filteredProject.size());
            return true;
        }
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
                        "/api/v1/project?excludeInactive=true&searchText=&sortOrder=asc&pageSize=500&pageNumber=1", HttpMethod.GET, entity, new ParameterizedTypeReference<List<Projects>>() {});
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

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void createVulns(CodeProject codeProject, List<DTrackVuln> body) {
        List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository
                .findByVulnerabilitySourceAndCodeProject(vulnTemplate.SOURCE_OPENSOURCE, codeProject);
        List<ProjectVulnerability> vulnsToPersist = new ArrayList<>();
        for(DTrackVuln dTrackVuln : body){
            List<SoftwarePacket> softwarePackets = new ArrayList<>();
            for(Component component : dTrackVuln.getComponents()){
                Optional<SoftwarePacket> softPacket = softwarePacketRepository.findByName(component.getName()+":"+component.getVersion());
                if (softPacket.isPresent()){
                    //codeProject.getSoftwarePackets().add(softPacket.get());
                    softwarePackets.add(softPacket.get());
                } else {
                    SoftwarePacket softwarePacket = new SoftwarePacket();
                    softwarePacket.setName(component.getName()+":"+component.getVersion());
                    softwarePacketRepository.save(softwarePacket);
                    softwarePackets.add(softwarePacket);
                }

                for (SoftwarePacket sPacket : softwarePackets){
                    Vulnerability vuln = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerabilityWithDescAndReferences(dTrackVuln.getVulnId(), dTrackVuln.getDescription(),
                            dTrackVuln.getReferences(), dTrackVuln.getRecommendation());
                    Optional<ProjectVulnerability> softwarePacketVulnerability = vulnTemplate.projectVulnerabilityRepository
                            .findBySoftwarePacketAndVulnerabilityAndCodeProject(sPacket,vuln, codeProject);
                    if (!softwarePacketVulnerability.isPresent()){
                        ProjectVulnerability projectVulnerability = new ProjectVulnerability(sPacket,codeProject,vuln,dTrackVuln.getDescription(),dTrackVuln.getRecommendation(),
                                dTrackVuln.getSeverity(), null, null, null,vulnTemplate.SOURCE_OPENSOURCE,null);
                        projectVulnerability.setStatus(vulnTemplate.STATUS_NEW);
                        vulnsToPersist.add(projectVulnerability);
                    } else {
                        softwarePacketVulnerability.get().setCodeProject(codeProject);
                        softwarePacketVulnerability.get().setInserted(dateFormat.format(new Date()));
                        softwarePacketVulnerability.get().setStatus(vulnTemplate.STATUS_EXISTING);
                        vulnsToPersist.add(softwarePacketVulnerability.get()) ;
                    }

                }
            }
            //codeProjectRepository.saveAndFlush(codeProject);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulns,vulnsToPersist);
    }

    private HttpHeaders prepareAuthHeader(Scanner scanner) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(Constants.DTRACK_AUTH_HEADER, vaultHelper.getPassword(scanner.getApiKey()));
        return headers;
    }

    @Override
    @Transactional
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
                scanner.setStatus(true);
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
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_DEPENDENCYTRACK) && scanner.getStatus();
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_DEPENDENCYTRACK);
    }

    @Override
    public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
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
        return scannerRepository.save(scanner);

    }
}
