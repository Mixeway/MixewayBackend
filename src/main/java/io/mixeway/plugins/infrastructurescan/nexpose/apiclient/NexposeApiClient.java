package io.mixeway.plugins.infrastructurescan.nexpose.apiclient;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.infrastructurescan.nexpose.model.*;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanClient;
import io.mixeway.pojo.*;
import io.mixeway.rest.model.ScannerModel;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

@Component
public class NexposeApiClient implements NetworkScanClient, SecurityScanner {
    private final static Logger log = LoggerFactory.getLogger(NexposeApiClient.class);
    private final VaultHelper vaultHelper;
    private final SecureRestTemplate secureRestTemplate;
    private final ScannerRepository scannerRepository;
    private final ScanHelper scanHelper;
    private final NessusScanRepository nessusScanRepository;
    private final InterfaceRepository interfaceRepository;
    private final AssetRepository assetRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final ProxiesRepository proxiesRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    @Autowired
    NexposeApiClient(VaultHelper vaultHelper, SecureRestTemplate secureRestTemplate, ScannerRepository scannerRepository,
                     ScanHelper scanHelper, NessusScanRepository nessusScanRepository, InterfaceRepository interfaceRepository,
                     AssetRepository assetRepository,InfrastructureVulnRepository infrastructureVulnRepository, ScannerTypeRepository scannerTypeRepository,
                     ProxiesRepository proxiesRepository, RoutingDomainRepository routingDomainRepository){
        this.vaultHelper = vaultHelper;
        this.secureRestTemplate = secureRestTemplate;
        this.scannerRepository = scannerRepository;
        this.scanHelper = scanHelper;
        this.nessusScanRepository = nessusScanRepository;
        this.interfaceRepository = interfaceRepository;
        this.assetRepository = assetRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.proxiesRepository = proxiesRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.scannerTypeRepository = scannerTypeRepository;

    }

    private boolean saveEngineForScanner(io.mixeway.db.entity.Scanner scanner) throws  NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
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
    private boolean saveTemplateForScanner(io.mixeway.db.entity.Scanner scanner) throws  NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
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
    private void createSiteForScan(NessusScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        CreateSiteRequestDTO request = createRequest(scan);
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<CreateSiteResponseDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/sites",
                HttpMethod.POST, templateBasicAuth.prepareTemplateWithBasicAuthAndBody(scan.getNessus(),vaultHelper, request),CreateSiteResponseDTO.class);
        if (response.getStatusCode().equals(HttpStatus.CREATED)){
            scan.setTaskId(String.valueOf(Objects.requireNonNull(response.getBody()).getId()));
            nessusScanRepository.save(scan);
            log.info("Created nexpose Site for {}", scan.getProject().getName());
        }
    }
    private void modifyTargetsForSite(NessusScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<CreateSiteResponseDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/sites/"+scan.getTaskId()+"/included_targets",
                HttpMethod.PUT, templateBasicAuth.prepareTemplateWithBasicAuthAndBody(scan.getNessus(),vaultHelper, scanHelper.prepareTargetsForScan(scan,true)),CreateSiteResponseDTO.class);
        response.getStatusCode();
    }

    public void loadVulnerabilities(NessusScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        //Pobierz assety i dla kazdego z nich
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<SiteAssetsDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/sites/"+scan.getTaskId()+"/assets?page=0&size=500&sort=id,asc",
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scan.getNessus(),vaultHelper),SiteAssetsDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            for (SiteAssetsResources a: Objects.requireNonNull(response.getBody()).getResources()){
                Interface intf = verifyAndCreateAsset(scan,a);
                loadVulnerabilitiesForAsset(scan,intf,a.getId(),0);
            }
        }
    }

    @Override
    public boolean initialize(io.mixeway.db.entity.Scanner scanner) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if( this.saveTemplateForScanner(scanner) && this.saveEngineForScanner(scanner)){
            scanner.setStatus(true);
            scannerRepository.save(scanner);
            return true;
        }
        return false;
    }

    private void loadVulnerabilitiesForAsset(NessusScan scan, Interface intf, int id, int page) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<AssetVulnerabilitiesResponseDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/assets/"+id+"/vulnerabilities?page="+page+"&size=500&sort=id,asc",
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scan.getNessus(),vaultHelper),AssetVulnerabilitiesResponseDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            for (AssetVulnerabilitiesResource avr : Objects.requireNonNull(response.getBody()).getResources()){
                VulnerabilityDetailsDTO vulnDetails = getVulnDetailsForId(scan,avr.getId());
                for(Result result : avr.getResults()){
                    InfrastructureVuln iv = new InfrastructureVuln();
                    iv.setIntf(intf);
                    iv.setInserted(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
                    assert vulnDetails != null;
                    iv.setName(vulnDetails.getTitle());
                    iv.setPort(String.valueOf(result.getPort()));
                    iv.setSeverity(setNexposeThreat(vulnDetails.getSeverity()));
                    iv.setDescription("<br/><b>Vulnerability satus: "+result.getStatus()+"</b><br/>" +
                            "<b>Categories: "+ StringUtils.join(vulnDetails.getCategories(),", ")+"</b><br/>" +
                            "<br/><br/>Proof:<br/>"+result.getProof()+
                            "<br/>Description:<br/>"+vulnDetails.getDescription().getHtml());
                    infrastructureVulnRepository.save(iv);
                }
            }
            if (response.getBody().getPage().getTotalPages() > (response.getBody().getPage().getNumber() + 1)){
                this.loadVulnerabilitiesForAsset(scan,intf,id, page+1 );
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

    private VulnerabilityDetailsDTO getVulnDetailsForId(NessusScan scan,String id) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<VulnerabilityDetailsDTO> response = restTemplate.exchange(scan.getNessus().getApiUrl() + "/api/3/vulnerabilities/"+id,
                HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(scan.getNessus(),vaultHelper),VulnerabilityDetailsDTO.class);
        if (response.getStatusCode().equals(HttpStatus.OK)){
            return response.getBody();
        }
        return null;
    }

    private Interface verifyAndCreateAsset(NessusScan scan, SiteAssetsResources a) {
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

    private CreateSiteRequestDTO createRequest(NessusScan scan) {
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
    private boolean runScanForSite(NessusScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        RestTemplateBasicAuth templateBasicAuth= new RestTemplateBasicAuth();
        RestTemplate restTemplate = secureRestTemplate.noVerificationClient(scan.getNessus());
        ResponseEntity<ScanResponse> response = restTemplate.exchange(scan.getNessus().getApiUrl()+"/api/3/sites/"+scan.getTaskId()+"/scans", HttpMethod.POST,
                templateBasicAuth.prepareTemplateWithBasicAuthAndBody(scan.getNessus(),vaultHelper,"{}"),ScanResponse.class);
        if (response.getStatusCode().equals(HttpStatus.CREATED)){
            scan.setRunning(true);
            scan.setScanId(Objects.requireNonNull(response.getBody()).getId());
            log.info("Nexpose Scan for {} started",scan.getProject().getName());
            nessusScanRepository.save(scan);
            return true;
        }
        return false;
    }

    @Override
    public boolean runScan(NessusScan scan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        if (scan.getTaskId() != null && !scan.getTaskId().equals(""))
            this.modifyTargetsForSite(scan);
        else
            this.createSiteForScan(scan);
        if (scan.getTaskId() != null && !scan.getTaskId().equals(""))
            return this.runScanForSite(scan);
        return false;
    }

    @Override
    public void runScanManual(NessusScan nessusScan) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException {
        if (nessusScan.getTaskId() != null && !nessusScan.getTaskId().equals(""))
            this.modifyTargetsForSite(nessusScan);
        else
            this.createSiteForScan(nessusScan);

        if (nessusScan.getTaskId() != null && !nessusScan.getTaskId().equals(""))
            this.runScanForSite(nessusScan);
    }

    @Override
    public boolean isScanDone(NessusScan nessusScan) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        if (nessusScan.getScanId() > 0){
            RestTemplateBasicAuth templateBasicAuth = new RestTemplateBasicAuth();
            RestTemplate restTemplate = secureRestTemplate.noVerificationClient(nessusScan.getNessus());
            ResponseEntity<ScanStatusResponse> response = restTemplate.exchange(nessusScan.getNessus().getApiUrl() + "/api/3/scans/"+nessusScan.getScanId(),
                    HttpMethod.GET, templateBasicAuth.prepareTemplateHedersBasicAndJson(nessusScan.getNessus(),vaultHelper),ScanStatusResponse.class);
            if(response.getStatusCode().equals(HttpStatus.OK)){
                return Objects.requireNonNull(response.getBody()).getStatus().equals(Constants.NEXPOSE_STATUS_END);
            }
        }
        return false;
    }
    @Override
    public boolean canProcessRequest(NessusScan nessusScan) {
        return nessusScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXPOSE);
    }
    @Override
    public boolean canProcessRequest(io.mixeway.db.entity.Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_NEXPOSE);
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_NEXPOSE);
    }

    @Override
    public void saveScanner(ScannerModel scannerModel) throws Exception {
        ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerModel.getScannerType());
        Proxies proxy = null;
        if (scannerModel.getProxy() != 0)
            proxy = proxiesRepository.getOne(scannerModel.getProxy());
        if (scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS) || scannerType.getName().equals(Constants.SCANNER_TYPE_NEXPOSE) ||
                scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET)) {
            io.mixeway.db.entity.Scanner nessus = new io.mixeway.db.entity.Scanner();
            nessus.setUsername(scannerModel.getUsername());
            nessus = nessusOperations(scannerModel.getRoutingDomain(), nessus, proxy, scannerModel.getApiUrl(), scannerType);
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(scannerModel.getPassword(),uuidToken)){
                nessus.setPassword(uuidToken);
            } else {
                nessus.setPassword(scannerModel.getPassword());
            }
        }
    }
    private io.mixeway.db.entity.Scanner nessusOperations(Long domainId, Scanner nessus, Proxies proxy, String apiurl, ScannerType scannerType) throws Exception{
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
