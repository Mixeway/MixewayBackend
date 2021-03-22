package io.mixeway.integrations.infrastructurescan.service;


import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.infrastructurescan.model.NetworkScanRequestModel;
import io.mixeway.integrations.infrastructurescan.plugin.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.pojo.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.model.KeyValue;
import io.mixeway.rest.utils.InterfaceOperations;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import one.util.streamex.StreamEx;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ConnectException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.xml.bind.JAXBException;

/**
 * @author gsiewruk
 */
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
    private final WebAppHelper webAppHelper;
    private final RfwApiClient rfwApiClient;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final PermissionFactory permissionFactory;
    private final ScannerRepository scannerRepository;


    public NetworkScanService(ProjectRepository projectRepository, ScannerTypeRepository scannerTypeRepository, ScanHelper scanHelper,
                              List<NetworkScanClient> networkScanClients, NessusScanTemplateRepository nessusScanTemplateRepository, NessusScanRepository nessusScanRepository,
                              ScannerRepository nessusRepository, InterfaceRepository interfaceRepository, AssetRepository assetRepository,
                              RoutingDomainRepository routingDomainRepository, RfwApiClient rfwApiClient, WebAppHelper webAppHelper,
                              ProjectRiskAnalyzer projectRiskAnalyzer, PermissionFactory permissionFactory, ScannerRepository scannerRepository) {
        this.projectRepository = projectRepository;
        this.scannerRepository = scannerRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
        this.scannerTypeRepository = scannerTypeRepository;
        this.nessusRepository = nessusRepository;
        this.webAppHelper = webAppHelper;
        this.routingDomainRepository = routingDomainRepository;
        this.nessusScanTemplateRepository = nessusScanTemplateRepository;
        this.interfaceRepository = interfaceRepository;
        this.assetRepository = assetRepository;
        this.nessusScanRepository = nessusScanRepository;
        this.networkScanClients = networkScanClients;
        this.rfwApiClient = rfwApiClient;
        this.scanHelper =scanHelper;
        this.permissionFactory = permissionFactory;
    }

    /**
     * Method which is checking running NessusScan entities for particular proejct by externalId
     *
     * @param ciid externalId for system
     * @return HttpStatus.OK if scan ended, LOCKED if scan is running, NOT_FOUND if there is no such project
     */
    public ResponseEntity<Status> checkScanStatusForCiid(String ciid){
        Optional<List<Project>> project = projectRepository.findByCiid(ciid);
        if (project.isPresent()){
            for (Project p :project.get()){
                List<NessusScan> nessusScans = nessusScanRepository.findByProjectAndIsAutomatic(p,false).stream().filter(NessusScan::getRunning).collect(Collectors.toList());
                if (nessusScans.size()>0){
                    return new ResponseEntity<>(new Status("At least one scan for "+p.getName()+" is running."), HttpStatus.LOCKED);
                }
            }
            return new ResponseEntity<>(new Status("Can't find running network scan for ciid "+ HtmlUtils.htmlEscape(ciid)), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("Project not found"), HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Method is creating nessusScan entity and run it on configured netowrk scanner.
     *
     * @param req NetworkScanRequestModel which contain information about object to be sacn
     * @return HttpStatus.CREATED if scan is started, PREDONDITION_FAILED when exception occured
     */
    public ResponseEntity<Status> createAndRunNetworkScan(NetworkScanRequestModel req, Principal principal) throws Exception {
        log.info("Got request for scan from koordynator - system {}, asset no: {}", LogUtil.prepare(req.getProjectName()),  LogUtil.prepare(String.valueOf(req.getIpAddresses().size())));
        Optional<List<Project>> projectFromReq = projectRepository.findByCiid(req.getCiid());
        Project project;
        if (projectFromReq.isPresent() && projectFromReq.get().size() > 0) {
            project = projectFromReq.get().get(0);
        } else {
            project = new Project();
            project.setName(req.getProjectName());
            project.setCiid(req.getCiid());
            project.setOwner(permissionFactory.getUserFromPrincipal(principal));
            project.setEnableVulnManage(req.getEnableVulnManage().isPresent() ? req.getEnableVulnManage().get() : true);
            project = projectRepository.saveAndFlush(project);
            if (!principal.getName().equals("admin")) {
                permissionFactory.grantPermissionToProjectForUser(project, principal);
            }
        }
        List<Interface> intfs = updateAssetsAndPrepareInterfacesForScan(req, project);
        //GET RUNNING MANUAL SCANS AND CHECK IF INTERFACE ON LIST
        if (verifyInterfacesBeforeScan(intfs))
            return new ResponseEntity<>(new Status("Request containts IP with running test. Omitting.."),
                    HttpStatus.EXPECTATION_FAILED);
        //CONFIGURE MANUAL SCAN
        List<NessusScan> ns;
        try {
            ns = configureAndRunManualScanForScope(project, intfs);
        } catch (IndexOutOfBoundsException e){
            return new ResponseEntity<>(new Status("One or more hosts does not have Routing domain or no scanner avaliable in given Routing Domain. Omitting.."),
                    HttpStatus.EXPECTATION_FAILED);
        }

//        //RUN MANUAL SCAN
//        for (NessusScan nessusScan : ns){
//            if (!nessusScan.getRunning()) {
//                for (NetworkScanClient networkScanClient :networkScanClients){
//                    if (networkScanClient.canProcessRequest(nessusScan)){
//                        putRulesOnRfw(nessusScan);
//                        networkScanClient.runScan(nessusScan);
//                    }
//                }
//            }
//        }
        if (ns.stream().allMatch(NessusScan::getRunning)) {
            return new ResponseEntity<>(new Status("ok",
                    StringUtils.join(ns.stream().map(NessusScan::getRequestId).collect(Collectors.toSet()), ",")),
                    HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(new Status("Problem with running scan..."), HttpStatus.PRECONDITION_FAILED);
        }
    }


    /**
     * Method set state of runnig=true for give Intercace list. Also update Asset with proper requestId.
     *
     * @param interfaces interaces to update state
     * @param requestId requestId to update on asset entity
     */
    private void updateIntfsStateAndAssetRequestId(List<Interface> interfaces, String requestId){
        Set<Asset> assets = new HashSet<>();
        for (Interface i : interfaces){
            i.setScanRunning(true);
            interfaceRepository.save(i);
        }
        interfaces.stream().filter(i -> assets.add(i.getAsset())).collect(Collectors.toList());
        for (Asset asset : assets){
            asset.setRequestId(requestId);
            assetRepository.save(asset);
        }
    }

    /**
     * Method is creating NessusScan entity properly for given resources. And use Network Scanner API to create and run scan
     * Ignores Interfaces with running=true
     *
     * @param project context
     * @param intfs List of Interfaces to configure scan
     * @return NessusScan which is configured and running network scan
     */
    public List<NessusScan> configureAndRunManualScanForScope(Project project, List<Interface> intfs) throws Exception {
        log.info("Preparing scan for {}", project.getName());
        List<NessusScan> nessusScans = new ArrayList<>();
        intfs = intfs.stream().filter(i -> !i.isScanRunning()).collect(Collectors.toList());

        // Partitioning scans for smaller parts
        int partitionSize = 15;
        List<List<Interface>> sublists = StreamEx.ofSubLists(intfs, partitionSize).toList();

        String requestUIDD = UUID.randomUUID().toString();
        Map<NetworkScanClient, Set<Interface>> scannerInterfaceMap = new HashMap<>();

        for (List<Interface> interfacesPartial : sublists){
            scannerInterfaceMap.putAll(findNessusForInterfaces(new HashSet<>(interfacesPartial)));
        }

        for (Map.Entry<NetworkScanClient, Set<Interface>> keyValue: scannerInterfaceMap.entrySet()) {
            try {
                NessusScan scan = new NessusScan();
                scan = configureScan(scan,
                        keyValue.getKey().getScannerFromClient(
                                Objects.requireNonNull(keyValue.getValue().stream().findFirst().orElse(null)).getRoutingDomain()),
                        project,
                        false);
                scan.setInterfaces(keyValue.getValue());
                scan.setRequestId(requestUIDD);
                scan.setScanFrequency(EXECUTE_ONCE);
                scan.setScheduled(false);
                scan.setRunning(false);
                scan.setInQueue(true);

                scan = nessusScanRepository.saveAndFlush(scan);
                //putRulesOnRfw(scan);
                //keyValue.getKey().runScan(scan);
                for (Interface i : scan.getInterfaces()) {
                    i.getAsset().setRequestId(scan.getRequestId());
                    i.setScanRunning(true);
                    interfaceRepository.save(i);
                    assetRepository.save(i.getAsset());
                }
                nessusScans.add(scan);
            } catch (Exception e){
                log.error("Problem with connection to scanner {}", keyValue.getKey().printInfo());
            }
        }

        return nessusScans;
    }

    /**
     * Reconfiguration of a scan
     *
     * @param scan
     * @param nessus
     * @param project
     * @param auto
     * @return Configured NessusScan
     */
    private NessusScan configureScan(NessusScan scan, Scanner nessus, Project project, Boolean auto){
        scan.setIsAutomatic(auto);
        scan.setNessus(nessus);
        scan.setNessusScanTemplate(nessusScanTemplateRepository.findByNameAndNessus(NESSUS_TEMPLATE, nessus));
        scan.setProject(project);
        scan.setPublicip(false);
        scan.setRunning(false);
        return scan;
    }


    /**
     * Method which is finding a proper Scanner for particular Interface. Match is being done for RoutingDomain match.
     * Assumption is that there is one scanner in one routing domian
     *
     * @param intfs
     * @return
     */
    public Map<NetworkScanClient, Set<Interface>> findNessusForInterfaces(Set<Interface> intfs) {
        Map<NetworkScanClient, Set<Interface>> scannerInterfaceMap = new HashMap<>();
        List<RoutingDomain> uniqueDomainInProjectAssets = intfs.stream().map(Interface::getRoutingDomain).distinct().collect(Collectors.toList());
        for (RoutingDomain rd : uniqueDomainInProjectAssets) {
            for (NetworkScanClient networkScanClient : networkScanClients){
                if (networkScanClient.canProcessRequest(rd)){
                    log.debug("Got scanner to scan target {}", networkScanClient.printInfo());
                    scannerInterfaceMap.put(networkScanClient, intfs.stream().filter(i -> i.getRoutingDomain().getId().equals(rd.getId())).collect(Collectors.toSet()));
                }
            }
        }
        return scannerInterfaceMap;
    }

    /**
     * Prepare object to be scan from ScanManager module
     * TODO multiple domains in one model request
     * @param req properly created NetworkScanRequestModel
     * @param project context
     * @return list of interface in request
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<Interface> updateAssetsAndPrepareInterfacesForScan(NetworkScanRequestModel req, Project project) {
        List<Interface> listtoScan = new ArrayList<>();
        Optional<Interface> interfaceOptional = Optional.empty();
        for (AssetToCreate atc : req.getIpAddresses()){
            if (project.getAssets() != null){
                interfaceRepository.findByAssetInAndPrivateip(project.getAssets(), atc.getIp());
            }
           if (interfaceOptional.isPresent()){
                listtoScan.add(interfaceOptional.get());
            } else {
                Asset a = new Asset();
                a.setName(atc.getHostname() != null ? atc.getHostname() : atc.getIp());
                a.setActive(true);
                a.setProject(project);
                a.setOrigin("manual");
                a.setRoutingDomain(routingDomainRepository.findByName(atc.getRoutingDomain()));
                assetRepository.save(a);
                List<Interface> interfacesToBeCreated = InterfaceOperations.createInterfacesForModel(a, a.getRoutingDomain(),atc.getIp());
                interfacesToBeCreated = interfaceRepository.saveAll(interfacesToBeCreated);
                listtoScan.addAll(interfacesToBeCreated);
            }

        }
        return listtoScan;
    }

    /**
     * Double check for already running scan on interface
     *
     * @param intfs
     * @return
     */
    private Boolean verifyInterfacesBeforeScan(List<Interface> intfs) {
        List<NessusScan> manualRunningScans = nessusScanRepository.findByIsAutomaticAndRunning(false, true);
        for (NessusScan ns : manualRunningScans) {
            if (org.springframework.util.CollectionUtils.containsAny(intfs, ns.getInterfaces()))
                return true;

        }
        return false;
    }

    /**
     * Configure NessuScan and set it to automatic for each routing domain within project
     *
     * @param project
     */
    public void configureAutomaticScanForProject(Project project) {
        //Pobranie asetow i wybranie roznych domen routingowych
        List<Asset> uniqueRoutingDomainsForProject = project.getAssets().stream()
                .filter(distinctByKey(Asset::getRoutingDomain))
                .collect(Collectors.toList());

        //Dla kazdej unikalnej domeny zdefiniuj skan automatyczny
        for (Asset a : uniqueRoutingDomainsForProject) {
            configureInfrastructureScanForRoutingDomainAndProject(a.getRoutingDomain(), project);
        }
    }

    /**
     * Create NessuScan for given unique routing domian within given project
     *
     * @param routingDomain
     * @param project
     */
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

    /**
     * Returning List of Intrafces within specified project in specified RoutingDomain
     * @param routingDomain
     * @param project
     * @return
     */
    private Set<Interface> getInterfacesForProjectAndRoutingDomains(RoutingDomain routingDomain, Project project) {
        return interfaceRepository.findByAssetInAndRoutingDomainAndActive(project.getAssets(), routingDomain, true);
    }
    public static <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
        Set<Object> seen = ConcurrentHashMap.newKeySet();
        return t -> seen.add(keyExtractor.apply(t));
    }

    /**
     * Put proper RFW rules on defined Remote Firewall
     * @param nessusScan
     */
    @Transactional
    public void putRulesOnRfw(NessusScan nessusScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if (StringUtils.isNotBlank(nessusScan.getNessus().getRfwUrl())) {
            List<String> ipAddresses = scanHelper.prepareTargetsForScan(nessusScan, false);
            for (String ipAddress : ipAddresses) {
                rfwApiClient.operateOnRfwRule(nessusScan.getNessus(), ipAddress, HttpMethod.PUT);
            }
            log.info("Putting rules on RFW for {} on {}", nessusScan.getProject().getName(), nessusScan.getNessus().getApiUrl());
        }
    }

    /**
     * Remove configured rules from RemoteFirewall
     * @param nessusScan
     */
    @Transactional
    public void deleteRulsFromRfw(NessusScan nessusScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if (StringUtils.isNotBlank(nessusScan.getNessus().getRfwUrl())) {
            List<String> ipAddresses = scanHelper.prepareTargetsForScan(nessusScan, false);
            for (String ipAddress : ipAddresses) {
                rfwApiClient.operateOnRfwRule(nessusScan.getNessus(), ipAddress, HttpMethod.DELETE);
            }
            log.info("Deleting rules from RFW for {} on {}", nessusScan.getProject().getName(), nessusScan.getNessus().getApiUrl());
        }
    }



    /**
     * Method which is cheacking for running nessusscan test and then it download results
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void scheduledCheckStatusAndLoadVulns() {
        try {
            List<NessusScan> nsl = nessusScanRepository.getRandom5RunningScans();
            for (NessusScan ns : nsl) {
                if (ns.getNessus().getStatus()) {
                    for (NetworkScanClient networkScanClient :networkScanClients) {
                        if (networkScanClient.canProcessRequest(ns) && networkScanClient.isScanDone(ns)) {
                            networkScanClient.loadVulnerabilities(ns);
                            deleteRulsFromRfw(ns);
                            updateRiskForInterfaces(ns);
                        }
                    }
                    //For nessus create webapp linking
                    if (ns.getNessus().getScannerType().equals(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS))) {
                        if (ns.getProject().getWebAppAutoDiscover() != null && ns.getProject().getWebAppAutoDiscover())
                            webAppHelper.discoverWebAppFromInfrastructureVulns(ns.getProject(), ns);
                    }
                    //Change state of interface which was not loaded for some reason
                    //interfaceRepository.updateStateForNotRunningScan();
                    return;
                }
            }
        } catch (UnexpectedRollbackException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException | JAXBException | ResourceAccessException ce ){
            log.warn("Exception during Network Scan synchro {}", ce.getLocalizedMessage());
            ce.printStackTrace();
        }
    }

    @Transactional
    void updateRiskForInterfaces(NessusScan ns) {
        List<String> ipAddresses = scanHelper.prepareTargetsForScan(ns, false);
        for (String ipAddress : ipAddresses) {
            Optional<Interface> interfaceOptional = interfaceRepository.findByPrivateipAndActiveAndAssetIn(ipAddress, true, new ArrayList<>(ns.getProject().getAssets())).stream().findFirst();
            interfaceOptional.ifPresent(anInterface -> anInterface.setRisk(Math.min(projectRiskAnalyzer.getInterfaceRisk(anInterface), 100)));
        }
    }

    /**
     * Method which check for nessusscan.isautomatic and run scan
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void scheduledRunScans() throws Exception {
        log.info("Starting Scheduled task for automatic test");
        List<Project> autoInfraProjectList = projectRepository.findByAutoInfraScan(true);
        for (Project project : autoInfraProjectList) {
            configureAndRunManualScanForScope(project, interfaceRepository.findByAssetInAndActive((List<Asset>) project.getAssets(), true));
        }

//        for (Project project : autoInfraProjectList){
//            List<NessusScan> nessusScan = nessusScanRepository.findByProjectAndIsAutomatic(project,true);
//            for (NessusScan ns : nessusScan) {
//                try {
//                    if (ns.getNessus().getStatus()) {
//                        for (NetworkScanClient networkScanClient :networkScanClients) {
//                            if (networkScanClient.canProcessRequest(ns) ) {
//                                putRulesOnRfw(ns);
//                                networkScanClient.runScan(ns);
//                                log.info("{} Starting automatic scan for {}",ns.getNessus().getScannerType().getName(), ns.getProject().getName());
//                            }
//                        }
//                    }
//                } catch (ResourceAccessException | NullPointerException | HttpServerErrorException | JAXBException | HttpClientErrorException e) {
//                    log.error("Exception - {} came up during scan for {}",e.getLocalizedMessage(), ns.getProject().getName());
//                } catch (Exception e) {
//                    log.error(e.getLocalizedMessage());
//                }
//            }
//        }
    }
    public void runNetworkScan(NessusScan nessusScan) throws Exception {
        for (NetworkScanClient networkScanClient : networkScanClients){
            if (networkScanClient.canProcessRequest(nessusScan)){
                networkScanClient.runScanManual(nessusScan);
            }
        }
    }

    /**
     * Method which verify if Network Scan is running (or some kind of error occured), if there is Interface.scanRunning with no nessusscan.running
     * terminate running interfaces. Otherwise another scan cannot be started
     */
    public void verifyInteraceState() {
        List<Project> projectRunning = projectRepository.getProjectWithInterfaceRunning();
        for (Project p : projectRunning){
            if (nessusScanRepository.findByProjectAndRunning(p,true).size() == 0){
                interfaceRepository.updateInterfaceStateForNotRunningScan(p);
                log.info("[Network Scan] Detected interface with status ScanRunning=true for project {}, disabling it.", p.getName());
            }
        }
    }

    /**
     * Running scans fromqueue (NessusScan.inQueue = true)
     */
    @Transactional
    public void runScansFromQueue() throws Exception {
        // Take all Network scanners
        List<Scanner> networkScanners = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_NETWORK), true);
        for (Scanner scanner: networkScanners){
            List<NessusScan> nessusScansInQueue = nessusScanRepository.findByNessusAndInQueue(scanner, true);
            List<NessusScan> nessusScansRunning = nessusScanRepository.findByNessusAndRunning(scanner, true);
            int difference = scanner.getScannerType().getScanLimit() - nessusScansRunning.size();
            if (nessusScansInQueue.size() > 0 ) {
                log.info("[NetworkScanService] Got {} scans in queue (Running: {}, max scans {}) for scanner {} with zone {}", nessusScansInQueue.size(), nessusScansRunning.size(), scanner.getScannerType().getScanLimit(), scanner.getApiUrl(), scanner.getRoutingDomain().getName());
                log.info("[NetworkScanService] Taking {} scans from queue for scanner {} with zone {}", difference, scanner.getApiUrl(), scanner.getRoutingDomain().getName());
            }
            if (scanner.getScannerType().getScanLimit() > nessusScansRunning.size()){
                for(NessusScan nessusScan : nessusScansInQueue.subList(0, Math.min(difference, nessusScansInQueue.size()))) {
                    for (NetworkScanClient networkScanClient : networkScanClients) {
                        if (networkScanClient.canProcessRequest(nessusScan)) {
                            putRulesOnRfw(nessusScan);
                            networkScanClient.runScan(nessusScan);
                            nessusScan.setInQueue(false);
                            nessusScan.setRunning(true);
                            for (Interface i : nessusScan.getInterfaces()) {
                                i.getAsset().setRequestId(nessusScan.getRequestId());
                                i.setScanRunning(true);
                                //interfaceRepository.save(i);
                                //assetRepository.save(i.getAsset());
                            }
                            log.info("[NetworkScanService] {} Starting automatic scan for {}", nessusScan.getNessus().getScannerType().getName(), nessusScan.getProject().getName());
                        }
                    }
                }
            }
        }
    }
}

