package io.mixeway.scanmanager.service.network;


import com.google.common.collect.LinkedHashMultimap;
import com.google.common.collect.Multimap;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.domain.exceptions.ScanException;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.domain.service.infrascan.FindInfraScanService;
import io.mixeway.domain.service.infrascan.GetOrCreateInfraScanService;
import io.mixeway.domain.service.infrascan.UpdateInfraScanService;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.intf.UpdateInterfaceService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.scanmanager.integrations.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.scanmanager.model.AssetToCreate;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import io.mixeway.utils.*;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import one.util.streamex.StreamEx;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.HttpClient;
import org.codehaus.jettison.json.JSONException;
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

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@Transactional
@RequiredArgsConstructor
@Log4j2
public class NetworkScanService {

    private final List<NetworkScanClient> networkScanClients;
    private final ScanHelper scanHelper;
    private final RfwApiClient rfwApiClient;
    private final InterfaceOperations interfaceOperations;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final FindProjectService findProjectService;
    private final FindInfraScanService findInfraScanService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final GetOrCreateInfraScanService getOrCreateInfraScanService;
    private final UpdateInterfaceService updateInterfaceService;
    private final GetScannerService getScannerService;
    private final FindInterfaceService findInterfaceService;
    private final UpdateInfraScanService updateInfraScanService;
    private final WebAppScanService webAppScanService;


    /**
     * Method which is checking running NessusScan entities for particular proejct by externalId
     *
     * @param ciid externalId for system
     * @return HttpStatus.OK if scan ended, LOCKED if scan is running, NOT_FOUND if there is no such project
     */
    public ResponseEntity<Status> checkScanStatusForCiid(String ciid){
        Optional<Project> project = findProjectService.findProjectByCiid(ciid);
        if (project.isPresent()){
            List<InfraScan> infraScans = findInfraScanService.findByProjectAndIsAutomatic(project.get());
            if (infraScans.size()>0){
                return new ResponseEntity<>(new Status("At least one scan for "+project.get().getName()+" is running."), HttpStatus.LOCKED);
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
    public ResponseEntity<Status> createAndRunNetworkScan(NetworkScanRequestModel req, Principal principal)  {
        try {
            log.info("[NetworkService] - Got request for scan from koordynator - system {}, asset no: {}", LogUtil.prepare(req.getProjectName()), LogUtil.prepare(String.valueOf(req.getIpAddresses().size())));
            Project project = getOrCreateProjectService.getProject(req, principal);

            List<Interface> intfs = updateAssetsAndPrepareInterfacesForScan(req, project);
            //GET RUNNING MANUAL SCANS AND CHECK IF INTERFACE ON LIST
            if (interfaceOperations.verifyInterfacesBeforeScan(intfs))
                return new ResponseEntity<>(new Status("Request containts IP with running test. Omitting.."),
                        HttpStatus.EXPECTATION_FAILED);

            //CONFIGURE MANUAL SCAN
            List<InfraScan> ns;
            try {
                ns = configureAndRunManualScanForScope(project, intfs, false, true);
            } catch (IndexOutOfBoundsException | NullPointerException e) {
                return new ResponseEntity<>(new Status("One or more hosts does not have Routing domain or no scanner available in given Routing Domain. Omitting.."),
                        HttpStatus.EXPECTATION_FAILED);
            } catch (Exception e){
                return new ResponseEntity<>(new Status(e.getMessage()), HttpStatus.PRECONDITION_FAILED);
            }

            if (ns.isEmpty()) {
                return new ResponseEntity<>(new Status("None of requested assets qualify for scan (probably scan is queued or running or Routing Domain mismatched)"), HttpStatus.PRECONDITION_FAILED);
            } else if (ns.stream().allMatch(InfraScan::getInQueue)) {
                List<Interface> interfaceToBeScanned = new ArrayList<>();
                ns.stream().map(InfraScan::getInterfaces).forEach(interfaceToBeScanned::addAll);
                String response = "Scan requested. Scope: [" +
                        StringUtils.join(interfaceToBeScanned.stream().map(Interface::getPrivateip).collect(Collectors.toSet()), ",") +
                        "]";
                return new ResponseEntity<>(new Status(response,
                        StringUtils.join(ns.stream().map(InfraScan::getRequestId).collect(Collectors.toSet()), ",")),
                        HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(new Status("Problem with running scan..."), HttpStatus.PRECONDITION_FAILED);
            }
        } catch (ScanException e){
            return new ResponseEntity<>(new Status(e.getMessage()), HttpStatus.PRECONDITION_FAILED);
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
    public List<InfraScan> configureAndRunManualScanForScope(Project project, List<Interface> intfs, boolean running, boolean inqueue) throws Exception {
        log.info("Infra Scan - Preparing scan for {}", project.getName());
        List<InfraScan> infraScans = new ArrayList<>();
        intfs = intfs.stream().filter(i -> !i.isScanRunning()).collect(Collectors.toList());

        // Partitioning scans for smaller parts
        int partitionSize = 4;
        List<List<Interface>> sublists = StreamEx.ofSubLists(intfs, partitionSize).toList();

        String requestUIDD = UUID.randomUUID().toString();
        Multimap<NetworkScanClient, Set<Interface>> scannerInterfaceMap = LinkedHashMultimap.create();

        for (List<Interface> interfacesPartial : sublists){
            scannerInterfaceMap.putAll(findNessusForInterfaces(new HashSet<>(interfacesPartial)));
        }

        for (Map.Entry<NetworkScanClient, Set<Interface>> keyValue: scannerInterfaceMap.entries()) {
            InfraScan scan = getOrCreateInfraScanService.create(keyValue,requestUIDD,project,false);
            //keyValue.getKey().runScan(scan);
            //putRulesOnRfw(scan);
            updateInterfaceService.changeRunningState(scan, running, inqueue);
            infraScans.add(scan);

        }
        return infraScans;
    }




    /**
     * Method which is finding a proper Scanner for particular Interface. Match is being done for RoutingDomain match.
     * Assumption is that there is one scanner in one routing domian
     *
     * @param intfs
     * @return
     */
    public Multimap<NetworkScanClient, Set<Interface>> findNessusForInterfaces(Set<Interface> intfs) {
        Multimap<NetworkScanClient, Set<Interface>> scannerInterfaceMap = LinkedHashMultimap.create();
        List<Long> uniqueDomainInProjectAssetsId = intfs.stream().map(Interface::getRoutingDomain).map(RoutingDomain::getId).distinct().collect(Collectors.toList());
        for (Long rd : uniqueDomainInProjectAssetsId) {
            RoutingDomain routingDomain = createOrGetRoutingDomainService.getById(rd);
            for (NetworkScanClient networkScanClient : networkScanClients){
                if (networkScanClient.canProcessRequest(routingDomain)){
                    log.debug("Got scanner to scan target {}", networkScanClient.printInfo());
                    scannerInterfaceMap.put(networkScanClient, intfs.stream().filter(i -> i.getRoutingDomain().getId().equals(routingDomain.getId())).collect(Collectors.toSet()));
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
    List<Interface> updateAssetsAndPrepareInterfacesForScan(NetworkScanRequestModel req, Project project) throws ScanException {
        List<Interface> listtoScan = new ArrayList<>();
        for (AssetToCreate atc : req.getIpAddresses()){
            Asset a = getOrCreateAssetService.getOrCreateAsset(atc, project, "manual");
            List<Interface> interfacesToBeCreated = interfaceOperations.createInterfacesForModel(a, a.getRoutingDomain(),atc.getIp());
            listtoScan.addAll(interfacesToBeCreated);
        }
        return listtoScan;
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
            configureAutomaticInfrastructureScanForRoutingDomainAndProject(a.getRoutingDomain(), project);
        }
    }

    /**
     * Create NessuScan for given unique routing domian within given project
     * SCOPE: AUTOMATIC
     *
     * @param routingDomain
     * @param project
     */
    private void configureAutomaticInfrastructureScanForRoutingDomainAndProject(RoutingDomain routingDomain, Project project) {
        List<Scanner> infrastructureScanners = getScannerService.getScannerForInfraScan(routingDomain);
        // Dla każdego skanera, ktory znajduje sie w domenie routingowej zdefiniuj skan
        for (Scanner scanner : infrastructureScanners) {
            if (findInfraScanService.canConfigureAutomaticScan(project,scanner)) {
                try {
                    Set<Interface> intfs = findInterfaceService.getInterfacesForProjectAndRoutingDomains(routingDomain,project);
                    InfraScan scan = getOrCreateInfraScanService.create(scanner,project,true,null,true);
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


    public static <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
        Set<Object> seen = ConcurrentHashMap.newKeySet();
        return t -> seen.add(keyExtractor.apply(t));
    }

    /**
     * Put proper RFW rules on defined Remote Firewall
     * @param infraScan
     */
    @Transactional
    public void putRulesOnRfw(InfraScan infraScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if (StringUtils.isNotBlank(infraScan.getNessus().getRfwUrl())) {
            List<String> ipAddresses = scanHelper.prepareTargetsForScan(infraScan, false);
            for (String ipAddress : ipAddresses) {
                rfwApiClient.operateOnRfwRule(infraScan.getNessus(), ipAddress, HttpMethod.PUT);
            }
            log.info("Putting rules on RFW for {} on {}", infraScan.getProject().getName(), infraScan.getNessus().getApiUrl());
        }
    }

    /**
     * Remove configured rules from RemoteFirewall
     * @param infraScan
     */
    @Transactional
    public void deleteRulsFromRfw(InfraScan infraScan)throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if (StringUtils.isNotBlank(infraScan.getNessus().getRfwUrl())) {
            List<String> ipAddresses = scanHelper.prepareTargetsForScan(infraScan, false);
            for (String ipAddress : ipAddresses) {
                rfwApiClient.operateOnRfwRule(infraScan.getNessus(), ipAddress, HttpMethod.DELETE);
            }
            log.info("Deleting rules from RFW for {} on {}", infraScan.getProject().getName(), infraScan.getNessus().getApiUrl());
        }
    }



    /**
     * Method which is cheacking for running nessusscan test and then it download results
     */
    @Transactional
    public void scheduledCheckStatusAndLoadVulns() {
        try {
            List<InfraScan> nsl = findInfraScanService.getRunning5Scans();
            for (InfraScan ns : nsl) {
                if (ns.getNessus().getStatus()) {
                    for (NetworkScanClient networkScanClient :networkScanClients) {
                        if (networkScanClient.canProcessRequest(ns) && networkScanClient.isScanDone(ns)) {
                            networkScanClient.loadVulnerabilities(ns);
                            webAppScanService.createWebAppsForProject(ns.getProject(), ns.getNessus().getRoutingDomain());
                            deleteRulsFromRfw(ns);
                            updateInterfaceService.changeRunningState(ns, false, false);
                            updateInterfaceService.updateRiskForInterfaces(ns);
                            log.info("[NetworkScan] Finished procesing scan for {}", ns.getProject().getName());
                        }
                    }
                    return;
                }
            }
        } catch (UnexpectedRollbackException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException | JAXBException | ResourceAccessException ce ){
            log.warn("Exception during Network Scan synchro {}", ce.getLocalizedMessage());
            ce.printStackTrace();
        }
    }



    /**
     * Method which check for nessusscan.isautomatic and run scan
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void scheduledRunScans() throws Exception {
        log.info("Starting Scheduled task for automatic test");
        List<Project> autoInfraProjectList = findProjectService.findProjectsWithAutoInfraScan();
        for (Project project : autoInfraProjectList) {
            configureAndRunManualScanForScope(project, findInterfaceService.getInterfacesInProject(project),false, true);
        }
    }

    public void runNetworkScan(InfraScan infraScan) throws Exception {
        for (NetworkScanClient networkScanClient : networkScanClients){
            if (networkScanClient.canProcessRequest(infraScan)){
                networkScanClient.runScanManual(infraScan);
            }
        }
    }

    /**
     * Method which verify if Network Scan is running (or some kind of error occured), if there is Interface.scanRunning with no nessusscan.running
     * terminate running interfaces. Otherwise another scan cannot be started
     */
    public void verifyInteraceState() {
        List<Project> projectRunning = findProjectService.findProjectsWithInfraScanRunning();
        for (Project p : projectRunning){
            if (findInfraScanService.hasProjectNoInfraScanRunning(p)){
                updateInterfaceService.clearState(p);
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

            List<Scanner> networkScanners = getScannerService.getScannerForInfraScan();
            for (Scanner scanner : networkScanners) {
                List<InfraScan> infraScansInQueue = findInfraScanService.findInQueue(scanner);
                List<InfraScan> infraScansRunning = findInfraScanService.findRunning(scanner);
                int difference = scanner.getScannerType().getScanLimit() - infraScansRunning.size();
                if (infraScansInQueue.size() > 0) {
                    log.info("[NetworkScanService] Got {} scans in queue (Running: {}, max scans {}) for scanner {} with zone {}", infraScansInQueue.size(), infraScansRunning.size(), scanner.getScannerType().getScanLimit(), scanner.getApiUrl(), scanner.getRoutingDomain().getName());
                }
                if (scanner.getScannerType().getScanLimit() > infraScansRunning.size()) {
                    for (InfraScan infraScan : infraScansInQueue.subList(0, Math.min(difference, infraScansInQueue.size()))) {
                        try {
                            for (NetworkScanClient networkScanClient : networkScanClients) {
                                if (networkScanClient.canProcessRequest(infraScan)) {
                                    log.info("[NetworkScanService] Running {}n-th scan from queue for scanner {} with zone {}", infraScansRunning.size() + 1, scanner.getApiUrl(), scanner.getRoutingDomain().getName());
                                    putRulesOnRfw(infraScan);
                                    networkScanClient.runScan(infraScan);
                                    updateInfraScanService.changeStateForRunningScan(infraScan);
                                    updateInterfaceService.updateIntfsStateAndAssetRequestId(new ArrayList<>(infraScan.getInterfaces()), infraScan.getRequestId());
                                }
                            }
                        } catch (ResourceAccessException | HttpServerErrorException | HttpClientErrorException e){
                            infraScan.setInQueue(false);
                            log.error("[NetworkScanService] Unable to perform scan for {} in RoutingDomain {}",
                                    infraScan.getProject().getName(),
                                    infraScan.getNessus().getRoutingDomain().getName());
                        }
                    }
                }
            }

    }
}

