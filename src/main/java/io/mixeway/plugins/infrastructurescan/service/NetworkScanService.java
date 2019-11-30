package io.mixeway.plugins.infrastructurescan.service;


import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.infrastructurescan.model.NetworkScanRequestModel;
import io.mixeway.plugins.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.pojo.AssetToCreate;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.pojo.Status;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.transaction.Transactional;
import javax.xml.bind.JAXBException;

@Service
@Transactional
public class NetworkScanService {

    private static final int EXECUTE_ONCE = 1;
    private static final String NESSUS_TEMPLATE = "Basic Network Scan";
    private static final Logger log = LoggerFactory.getLogger(NetworkScanService.class);
    private final ProjectRepository projectRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final NessusScanTemplateRepository nessusScanTemplateRepository;
    private final NessusScanRepository nessusScanRepository;
    private final ScannerRepository nessusRepository;
    private final InterfaceRepository interfaceRepository;
    private final AssetRepository assetRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final List<NetworkScanClient> networkScanClients;
    private final ScanHelper scanHelper;
    private final RfwApiClient rfwApiClient;

    public NetworkScanService(ProjectRepository projectRepository, ScannerTypeRepository scannerTypeRepository, ScanHelper scanHelper,
                              List<NetworkScanClient> networkScanClients, NessusScanTemplateRepository nessusScanTemplateRepository, NessusScanRepository nessusScanRepository,
                              ScannerRepository nessusRepository, InterfaceRepository interfaceRepository, AssetRepository assetRepository,
                              RoutingDomainRepository routingDomainRepository, RfwApiClient rfwApiClient) {
        this.projectRepository = projectRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.nessusRepository = nessusRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.nessusScanTemplateRepository = nessusScanTemplateRepository;
        this.interfaceRepository = interfaceRepository;
        this.assetRepository = assetRepository;
        this.nessusScanRepository = nessusScanRepository;
        this.networkScanClients = networkScanClients;
        this.rfwApiClient = rfwApiClient;
        this.scanHelper =scanHelper;
    }

    public ResponseEntity<Status> checkScanStatusForCiid(String ciid){
        Optional<List<Project>> project = projectRepository.findByCiid(ciid);
        if (project.isPresent()){
            for (Project p :project.get()){
                List<NessusScan> nessusScans = nessusScanRepository.findByProjectAndIsAutomatic(p,false).stream().filter(NessusScan::getRunning).collect(Collectors.toList());
                if (nessusScans.size()>0){
                    return new ResponseEntity<>(new Status("At least one scan for "+p.getName()+" is running."), HttpStatus.LOCKED);
                }
            }
            return new ResponseEntity<>(new Status("Can't find running network scan for ciid "+ciid), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("Project not found"), HttpStatus.NOT_FOUND);
        }
    }
    public ResponseEntity<Status> createAndRunNetworkScan(NetworkScanRequestModel req) throws JSONException, KeyManagementException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, JAXBException {
        log.info("Got request for scan from koordynator - system {}, asset no: {}",req.getProjectName(),req.getIpAddresses().size());
        Optional<List<Project>> projectFromReq = projectRepository.findByCiid(req.getCiid());
        Project project;
        if (projectFromReq.isPresent()) {
            project = projectFromReq.get().get(0);
        } else {
            project = new Project();
            project.setName(req.getProjectName());
            project.setCiid(req.getCiid());
            projectRepository.save(project);
        }
        List<Interface> intfs = updateAssetsAndPrepareInterfacesForScan(req, project);
        //GET RUNNING MANUAL SCANS AND CHECK IF INTERFACE ON LIST
        if (verifyInterfacesBeforeScan(intfs))
            return new ResponseEntity<>(new Status("Request containts IP with running test. Omitting.."),
                    HttpStatus.EXPECTATION_FAILED);
        //CONFIGURE MANUAL SCAN
        NessusScan ns;
        try {
            ns = configureKoordynatorScan(project, intfs);
        } catch (IndexOutOfBoundsException e){
            return new ResponseEntity<>(new Status("One or more hosts does not have Routing domain or no scanner avaliable in given Routing Domain. Omitting.."),
                    HttpStatus.EXPECTATION_FAILED);
        }
        //RUN MANUAL SCAN
        if (!ns.getRunning()) {
            for (NetworkScanClient networkScanClient :networkScanClients){
                if (networkScanClient.canProcessRequest(ns)){
                    networkScanClient.runScan(ns);
                }
            }
        }
        return new ResponseEntity<>(new Status("ok"), HttpStatus.CREATED);
    }
    private NessusScan configureKoordynatorScan(Project project, List<Interface> intfs) throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException, JAXBException {

        io.mixeway.db.entity.Scanner nessus = findNessusForInterfaces(new HashSet<>(intfs));
        NessusScan scan = new NessusScan();
        // TODO wsparcie dla nessusowych
        scan = configureScan(scan, nessus, project,false);
        scan.setInterfaces(new HashSet<>(intfs));
        scan.setRequestId(UUID.randomUUID().toString());
        scan.setScanFrequency(EXECUTE_ONCE);
        scan.setScheduled(false);
        for (Interface i: intfs){
            i.getAsset().setRequestId(scan.getRequestId());
            assetRepository.save(i.getAsset());
        }
        nessusScanRepository.save(scan);
        for (NetworkScanClient networkScanClient :networkScanClients) {
            if (networkScanClient.canProcessRequest(scan)) {
                networkScanClient.runScanManual(scan);
            }
        }
        return scan;
    }

    private NessusScan configureScan(NessusScan scan, io.mixeway.db.entity.Scanner nessus, Project project, Boolean auto){
        scan.setIsAutomatic(auto);
        scan.setNessus(nessus);
        scan.setNessusScanTemplate(nessusScanTemplateRepository.findByNameAndNessus(NESSUS_TEMPLATE, nessus));
        scan.setProject(project);
        scan.setPublicip(false);
        scan.setRunning(false);
        return scan;
    }
    //Założenie, że jest tylko jedna domena routingowa w jednym projekcie
    public io.mixeway.db.entity.Scanner findNessusForInterfaces(Set<Interface> intfs) {
        List<io.mixeway.db.entity.Scanner> nessuses = new ArrayList<>();
        List<ScannerType> types = new ArrayList<>();
        types.add(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS));
        types.add(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
        List<RoutingDomain> uniqueDomainInProjectAssets = intfs.stream().map(Interface::getRoutingDomain).distinct().collect(Collectors.toList());
        for (RoutingDomain rd : uniqueDomainInProjectAssets) {
            nessuses.addAll(nessusRepository.findByRoutingDomainAndScannerTypeIn(rd, types));
        }
        Optional<io.mixeway.db.entity.Scanner> scanner = nessuses.stream()
                .filter(s -> s.getScannerType() == scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS))
                .findFirst();
        return scanner.orElseGet(() -> nessuses.get(0));
    }
    private List<Interface> updateAssetsAndPrepareInterfacesForScan(NetworkScanRequestModel req, Project project) {
        List<Interface> listtoScan = new ArrayList<>();
        for (AssetToCreate atc : req.getIpAddresses()){

            Optional<Asset> asset = assetRepository.findByNameAndProject(atc.getHostname(), project);

            if (asset.isPresent() ) {
                Optional<Interface> intf = interfaceRepository.findByAssetAndPrivateip(asset.get(), atc.getIp());
                if (intf.isPresent()) {
                    listtoScan.add(intf.get());
                }
                else {
                    Interface interf = new Interface();
                    interf.setActive(true);
                    interf.setPrivateip(atc.getIp());
                    interf.setAsset(asset.get());
                    interf.setRoutingDomain(asset.get().getRoutingDomain());
                    interfaceRepository.save(interf);
                    listtoScan.add(interf);
                }
            } else {
                Asset a = new Asset();
                a.setName(atc.getHostname());
                a.setActive(true);
                a.setProject(project);
                a.setOrigin("manual");
                a.setRoutingDomain(routingDomainRepository.findByName(atc.getRoutingDomain()));
                assetRepository.save(a);
                Interface interf = new Interface();
                interf.setActive(true);
                interf.setPrivateip(atc.getIp());
                interf.setAsset(a);
                interf.setAutoCreated(false);
                interf.setRoutingDomain(a.getRoutingDomain());
                interfaceRepository.save(interf);
                log.info("adding {} to scope", interf.getPrivateip());
                listtoScan.add(interf);
            }
        }
        return listtoScan;
    }
    private Boolean verifyInterfacesBeforeScan(List<Interface> intfs) {
        List<NessusScan> manualRunningScans = nessusScanRepository.findByIsAutomaticAndRunning(false, true);
        for (NessusScan ns : manualRunningScans) {
            if (org.springframework.util.CollectionUtils.containsAny(intfs, ns.getInterfaces()))
                return true;

        }
        return false;
    }

    public void configureAutomaticScanForProject(Project project) {
        //Pobranie asetow i wybranie roznych domen routingowych
        List<Asset> uniqueRoutingDomainsForProject = project.getAssets().stream()
                .filter(distinctByKey(a -> a.getRoutingDomain()))
                .collect(Collectors.toList());

        //Dla kazdej unikalnej domeny zdefiniuj skan automatyczny
        for (Asset a : uniqueRoutingDomainsForProject) {
            configureInfrastructureScanForRoutingDomainAndProject(a.getRoutingDomain(), project);
        }
    }

    private void configureInfrastructureScanForRoutingDomainAndProject(RoutingDomain routingDomain, Project project) {
        final List<ScannerType> scannerTypes = Arrays.asList(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS), scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
        List<io.mixeway.db.entity.Scanner> infrastructureScanners = nessusRepository.findByRoutingDomainAndStatusAndScannerTypeIn(routingDomain, true, scannerTypes);
        // Dla każdego skanera, ktory znajduje sie w domenie routingowej zdefiniuj skan
        for (Scanner scanner : infrastructureScanners) {
            if (nessusScanRepository.findByIsAutomaticAndProjectAndNessus(true,project,scanner).size() == 0) {
                try {
                    NessusScan scan;
                    //Set<Interface> intfs =  getPublicAdresses(body,nessus.get(), project.get());
                    Set<Interface> intfs = getInterfacesForProjectAndRoutingDomains(routingDomain, project);
                    scan = new NessusScan();
                    scan = configureScan(scan, scanner, project, true);
                    scan.setInterfaces(intfs);
                    scan.setScanFrequency(EXECUTE_ONCE);
                    scan.setScheduled(true);
                    nessusScanRepository.save(scan);
                    for (NetworkScanClient networkScanClient :networkScanClients) {
                        if (networkScanClient.canProcessRequest(scan)) {
                            networkScanClient.runScan(scan);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace(new PrintStream(System.out));
                    log.warn("Exception came up during scan creation for project {} with message of '{}'", project.getName(), e.getMessage());
                }
                log.info("Configured scan for domain {}, project {}, and scanner {}",routingDomain.getName(),project.getName(),scanner.getScannerType().getName());
            }
        }

    }
    private Set<Interface> getInterfacesForProjectAndRoutingDomains(RoutingDomain routingDomain, Project project) {
        return interfaceRepository.findByAssetInAndRoutingDomainAndActive(project.getAssets(), routingDomain, true);
    }
    public static <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
        Set<Object> seen = ConcurrentHashMap.newKeySet();
        return t -> seen.add(keyExtractor.apply(t));
    }
    private void putRulesOnRfw(NessusScan nessusScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        for (String ipAddress : scanHelper.prepareTargetsForScan(nessusScan,false)){
            rfwApiClient.operateOnRfwRule(nessusScan.getNessus(),ipAddress, HttpMethod.PUT);
        }
    }
    public void deleteRulsFromRfw(NessusScan nessusScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        for (String ipAddress : scanHelper.prepareTargetsForScan(nessusScan,false)){
            rfwApiClient.operateOnRfwRule(nessusScan.getNessus(),ipAddress,HttpMethod.DELETE);
        }
    }
}

