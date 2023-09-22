package io.mixeway.scanmanager.integrations.nexpose.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.nexpose.model.*;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.scanmanager.service.network.NetworkScanClient;
import io.mixeway.utils.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Component
@Log4j2
@RequiredArgsConstructor
public class NexposeApiClient implements NetworkScanClient, SecurityScanner {
    private final VaultHelper vaultHelper;
    private final SecureRestTemplate secureRestTemplate;
    private final ScannerRepository scannerRepository;
    private final ScanHelper scanHelper;
    private final InfraScanRepository infraScanRepository;
    private final InterfaceRepository interfaceRepository;
    private final InterfaceOperations interfaceOperations;
    private final AssetRepository assetRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final ProxiesRepository proxiesRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final VulnTemplate vulnTemplate;


    private boolean saveEngineForScanner(Scanner scanner) throws  NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scanner);
        ResponseEntity<ScanEnginesResponseDTO> response = restTemplate.exchange(scanner.getApiUrl() + "/api/3/scan_engines",
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scanner,vaultHelper),ScanEnginesResponseDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            scanner.setEngineId(Objects.requireNonNull(Objects.requireNonNull(response.getBody()).getResources()
                    .stream()
                    .filter(resource -> resource.getName().equals(Constants.NEXPOSE_ENGINE_NAME))
                    .findFirst()
                    .orElse(null))
                    .getId());
            scannerRepository.save(scanner);
            return true;
        } else return false;
    }
    private boolean saveTemplateForScanner(Scanner scanner) throws  NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scanner);
        ResponseEntity<ScanTemplateResponseDTO> response = restTemplate.exchange(scanner.getApiUrl() + "/api/3/scan_templates",
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scanner,vaultHelper),ScanTemplateResponseDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            scanner.setTemplate(Objects.requireNonNull(Objects.requireNonNull(response.getBody()).getResources()
                    .stream()
                    .filter(template -> template.getName().equals(Constants.NEXPOSE_TEMPLATE_NAME))
                    .findFirst()
                    .orElse(null))
                    .getId());
            scannerRepository.save(scanner);
            return true;
        }else
            return false;
    }
    private void createSiteForScan(InfraScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        CreateSiteRequestDTO request = createRequest(scan);
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<CreateSiteResponseDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/sites",
                HttpMethod.POST, templateBasicAuth.prepareTemplateWithBasicAuthAndBody(scan.getNessus(),vaultHelper, request), CreateSiteResponseDTO.class);
        if (response.getStatusCode().equals(HttpStatus.CREATED)){
            scan.setTaskId(String.valueOf(Objects.requireNonNull(response.getBody()).getId()));
            infraScanRepository.save(scan);
            log.info("Created nexpose Site for {}", scan.getProject().getName());
        }
    }
    private void modifyTargetsForSite(InfraScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<CreateSiteResponseDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/sites/"+scan.getTaskId()+"/included_targets",
                HttpMethod.PUT, templateBasicAuth.prepareTemplateWithBasicAuthAndBody(scan.getNessus(),vaultHelper, scanHelper.prepareTargetsForScan(scan,true)),CreateSiteResponseDTO.class);
        response.getStatusCode();
    }

    public void loadVulnerabilities(InfraScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        //Pobierz assety i dla kazdego z nich
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<SiteAssetsDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/sites/"+scan.getTaskId()+"/assets?page=0&size=500&sort=id,asc",
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scan.getNessus(),vaultHelper),SiteAssetsDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            for (SiteAssetsResources a: Objects.requireNonNull(response.getBody()).getResources()){
                Interface intf = verifyAndCreateAsset(scan,a);
                List<ProjectVulnerability> oldVulns = deleteVulnsForInterface(intf);
                loadVulnerabilitiesForAsset(scan,intf,a.getId(),0, oldVulns);
            }
        }
    }

    private List<ProjectVulnerability> deleteVulnsForInterface(Interface intf) {
        List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository.findByAnInterface(intf);
        vulnTemplate.projectVulnerabilityRepository.deleteByAnInterface(intf);
        return oldVulns;
    }

    @Override
    public boolean initialize(Scanner scanner) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if( this.saveTemplateForScanner(scanner) && this.saveEngineForScanner(scanner)){
            scanner.setStatus(true);
            scannerRepository.save(scanner);
            return true;
        }
        return false;
    }

    private void loadVulnerabilitiesForAsset(InfraScan scan, Interface intf, int id, int page, List<ProjectVulnerability> oldVulns) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<AssetVulnerabilitiesResponseDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/assets/"+id+"/vulnerabilities?page="+page+"&size=500&sort=id,asc",
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scan.getNessus(),vaultHelper),AssetVulnerabilitiesResponseDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            for (AssetVulnerabilitiesResource avr : Objects.requireNonNull(response.getBody()).getResources()){
                VulnerabilityDetailsDTO vulnDetails = getVulnDetailsForId(scan,avr.getId());
                for(Result result : avr.getResults()){
                    Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(vulnDetails.getTitle());
                    ProjectVulnerability projectVulnerability = new ProjectVulnerability(intf, null,vulnerability,"<br/><b>Vulnerability satus: "+result.getStatus()+"</b><br/>" +
                            "<b>Categories: "+ StringUtils.join(vulnDetails.getCategories(),", ")+"</b><br/>" +
                            "<br/><br/>Proof:<br/>"+result.getProof()+
                            "<br/>Description:<br/>"+vulnDetails.getDescription().getHtml(),null,
                            setNexposeThreat(vulnDetails.getSeverity()),String.valueOf(result.getPort()),null,null, vulnTemplate.SOURCE_NETWORK,null,null);

                    projectVulnerability.updateStatusAndGrade(oldVulns, vulnTemplate);
                    vulnTemplate.projectVulnerabilityRepository.save(projectVulnerability);
                }
            }
            if (response.getBody().getPage().getTotalPages() > (response.getBody().getPage().getNumber() + 1)){
                this.loadVulnerabilitiesForAsset(scan,intf,id, page+1, oldVulns );
            }

        }

    }

    private String setNexposeThreat(String severity) {
        if (severity.equals(Constants.NEXPOSE_SEVERITY_SEVERE))
            return Constants.IF_VULN_THREAT_HIGH;
        else if (severity.equals(Constants.NEXPOSE_SEVERITY_MODERATE))
            return Constants.IF_VULN_THREAT_MEDIUM;
        else
            return severity;
    }

    private VulnerabilityDetailsDTO getVulnDetailsForId(InfraScan scan, String id) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<VulnerabilityDetailsDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/vulnerabilities/"+id,
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scan.getNessus(),vaultHelper),VulnerabilityDetailsDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            return response.getBody();
        }
        return null;
    }

    private Interface verifyAndCreateAsset(InfraScan scan, SiteAssetsResources a) {
        Optional<Interface> i = interfaceRepository.findByAssetInAndPrivateip(scan.getProject().getAssets(), a.getIp());
        if (!i.isPresent()){
            Asset asset = new Asset();
            asset.setProject(scan.getProject());
            asset.setRoutingDomain(scan.getNessus().getRoutingDomain());
            asset.setActive(true);
            asset.setName(a.getHostName()!=null? a.getHostName():"Unknown asset downloaded from nexpose");
            assetRepository.save(asset);
            Interface inter = new Interface();
            inter.setActive(true);
            inter.setRoutingDomain(scan.getNessus().getRoutingDomain());
            inter.setPrivateip(a.getIp());
            inter.setAsset(asset);
            interfaceRepository.save(inter);
            return inter;
        }
        return i.get();
    }

    private CreateSiteRequestDTO createRequest(InfraScan scan) {
        Scan nexposeScan = new Scan();
        Assets assets = new Assets();
        IncludedTargets targets = new IncludedTargets();
        targets.setAddresses(scanHelper.prepareTargetsForScan(scan,true));
        assets.setIncludedTargets(targets);
        nexposeScan.setAssets(assets);
        CreateSiteRequestDTO createSiteRequestDTO = new CreateSiteRequestDTO();
        createSiteRequestDTO.setDescription(Constants.NEXPOSE_SITE_DESCRIPTION);
        createSiteRequestDTO.setEngineId(scan.getNessus().getEngineId());
        createSiteRequestDTO.setImportance(Constants.NEXPOSE_IMPORTANCE_HIGH);
        createSiteRequestDTO.setName(scan.getIsAutomatic()? "Automatic scan for "+scan.getProject().getName() : "Manual scan for "+scan.getProject().getName());
        createSiteRequestDTO.setScan(nexposeScan);
        return createSiteRequestDTO;
    }
    private boolean runScanForSite(InfraScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth= new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<ScanResponse> response = restTemplate.exchange(scan.getNessus().getApiUrl()+"/api/3/sites/"+scan.getTaskId()+"/scans", HttpMethod.POST,
                templateBasicAuth.prepareTemplateWithBasicAuthAndBody(scan.getNessus(),vaultHelper,"{}"),ScanResponse.class);
        if (response.getStatusCode().equals(HttpStatus.CREATED)){
            scan.setRunning(true);
            scan.setScanId(Objects.requireNonNull(response.getBody()).getId());
            log.info("Nexpose Scan for {} started",scan.getProject().getName());
            infraScanRepository.save(scan);
            return true;
        }
        return false;
    }

    @Override
    public boolean runScan(InfraScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        if (scan.getTaskId() != null && !scan.getTaskId().equals(""))
            this.modifyTargetsForSite(scan);
        else
            this.createSiteForScan(scan);
        if (scan.getTaskId() != null && !scan.getTaskId().equals(""))
            return this.runScanForSite(scan);
        return false;
    }

    @Override
    public void runScanManual(InfraScan infraScan) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException {
        if (infraScan.getTaskId() != null && !infraScan.getTaskId().equals(""))
            this.modifyTargetsForSite(infraScan);
        else
            this.createSiteForScan(infraScan);

        if (infraScan.getTaskId() != null && !infraScan.getTaskId().equals(""))
            this.runScanForSite(infraScan);
    }

    @Override
    public boolean isScanDone(InfraScan infraScan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        if (infraScan.getScanId() > 0){
            RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
            RestTemplate restTemplate = secureRestTemplate.noVerificationClient(infraScan.getNessus());
            ResponseEntity<ScanStatusResponse> response = restTemplate.exchange(infraScan.getNessus().getApiUrl() + "/api/3/scans/"+ infraScan.getScanId(),
                    HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(infraScan.getNessus(),vaultHelper),ScanStatusResponse.class);
            if(response.getStatusCode().equals(HttpStatus.OK)){
                return Objects.requireNonNull(response.getBody()).getStatus().equals(Constants.NEXPOSE_STATUS_END);
            }
        }
        return false;
    }
    @Override
    public boolean canProcessRequest(InfraScan infraScan) {
        return infraScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXPOSE);
    }
    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXPOSE) && scanner.getStatus();
    }

    @Override
    public boolean canProcessInitRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXPOSE);
    }

    @Override
    public boolean canProcessRequest(RoutingDomain routingDomain) {
        try {
            List<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
            return scanner != null && !scanner.isEmpty() && scanner.get(0).getRoutingDomain().getId().equals(routingDomain.getId());
        } catch (Exception e) {
            return false;
        }

    }

    @Override
    public Scanner getScannerFromClient(RoutingDomain routingDomain) {
        List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE), routingDomain);
        return scanner.stream().findFirst().orElse(null);

    }

    @Override
    public String printInfo() {
        return "Nexpose Scanner";
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_NEXPOSE);
    }

    @Override
    public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
        ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
        Proxies proxy = null;
        if (scannerModel.getProxy() != 0)
            proxy = proxiesRepository.getOne(scannerModel.getProxy());
        if (scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS) || scannerType.getName().equals(Constants.SCANNER_TYPE_NEXPOSE) ||
                scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET)) {
            Scanner nessus = new Scanner();
            nessus.setUsername(scannerModel.getUsername());
            nessus = nessusOperations(scannerModel.getRoutingDomain(), nessus, proxy, scannerModel.getApiUrl(), scannerType);
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(scannerModel.getPassword(),uuidToken)){
                nessus.setPassword(uuidToken);
            } else {
                nessus.setPassword(scannerModel.getPassword());
            }
            return scannerRepository.save(nessus);
        }
        return null;
    }
    private Scanner nessusOperations(Long domainId, Scanner nessus, Proxies proxy, String apiurl, ScannerType scannerType) throws Exception{
        if(domainId == 0)
            throw new Exception("Null domain");
        else
            nessus.setRoutingDomain(routingDomainRepository.getOne(domainId));
        nessus.setProxies(proxy);
        nessus.setStatus(false);
        nessus.setApiUrl(apiurl);
        nessus.setScannerType(scannerType);
        nessus.setUsePublic(false);
        scannerRepository.save(nessus);

        return nessus;
    }
}
