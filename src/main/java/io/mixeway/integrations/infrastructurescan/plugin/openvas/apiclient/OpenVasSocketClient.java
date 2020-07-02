package io.mixeway.integrations.infrastructurescan.plugin.openvas.apiclient;

import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.infrastructurescan.plugin.openvas.model.*;
import io.mixeway.integrations.infrastructurescan.plugin.openvas.model.User;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.pojo.VaultHelper;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import io.mixeway.config.Constants;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanClient;
import io.mixeway.pojo.SecurityScanner;
import io.mixeway.rest.model.ScannerModel;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class OpenVasSocketClient implements NetworkScanClient, SecurityScanner {
    private final static Logger log = LoggerFactory.getLogger(OpenVasSocketClient.class);

    private final VaultHelper vaultHelper;
    private final ScannerRepository scannerRepository;
    private final NessusScanRepository nessusScanRepository;
    private final ScanHelper scanHelper;
    private final InterfaceRepository interfaceRepository;
    private final AssetRepository assetRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ProxiesRepository proxiesRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final VulnTemplate vulnTemplate;
    private final StatusRepository statusRepository;
    private DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");



    OpenVasSocketClient(VaultHelper vaultHelper, ScannerRepository scannerRepository,ScannerTypeRepository scannerTypeRepository,
                        NessusScanRepository nessusScanRepository, ScanHelper scanHelper, RoutingDomainRepository routingDomainRepository,
                        InterfaceRepository interfaceRepository, VulnTemplate vulnTemplate,
                        AssetRepository assetRepository, StatusRepository statusRepository, ProxiesRepository proxiesRepository){
        this.vaultHelper = vaultHelper;
        this.scannerRepository = scannerRepository;
        this.proxiesRepository = proxiesRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.nessusScanRepository = nessusScanRepository;
        this.scanHelper = scanHelper;
        this.interfaceRepository = interfaceRepository;
        this.assetRepository = assetRepository;
        this.statusRepository = statusRepository;
        this.vulnTemplate = vulnTemplate;
    }
    private NessusScan createTargets(NessusScan nessusScan) throws JAXBException {
        String targetName =  nessusScan.getProject().getName()+"-"+(nessusScan.getIsAutomatic()? Constants.SCAN_MODE_AUTO : Constants.SCAN_MODE_MANUAL)+"-"+ UUID.randomUUID();
        List<String> ipToScan = scanHelper.prepareTargetsForScan(nessusScan,true);
        String requestCreateTarget = XmlOperationBuilder.buildCreateTarget(getUserForScanner(nessusScan.getNessus()), String.join(",",ipToScan),targetName);
        JAXBContext jaxbContext = JAXBContext.newInstance(CommandResponseCreateTarget.class);
        Unmarshaller jaxbUnmarshallerScanners = jaxbContext.createUnmarshaller();
        CommandResponseCreateTarget createTarget = (CommandResponseCreateTarget) jaxbUnmarshallerScanners.unmarshal(
                new StringReader(Objects.requireNonNull(OpenVasSocketHelper.processRequest(requestCreateTarget, nessusScan.getNessus()))));
        if (createTarget.getStatus().equals("200")){
            nessusScan.setTargetId(createTarget.getCreateTargetResponse().getId());
        } else {
            log.error("Error during create Targets for {}", nessusScan.getProject().getName());
        }
        nessusScanRepository.save(nessusScan);
        return nessusScan;
    }
    private User getUserForScanner(Scanner scanner){
        return new User(scanner.getUsername(), vaultHelper.getPassword(scanner.getPassword()));
    }

    public void configureManualScan(NessusScan scan) throws JAXBException {
        createTargets(scan);
        createNewTask(scan);
    }

    private NessusScan createNewTask(NessusScan nessusScan) throws JAXBException {
        String requestCreateTask = XmlOperationBuilder.buildCreateTask(getUserForScanner(nessusScan.getNessus()), nessusScan);
        JAXBContext jaxbContext = JAXBContext.newInstance(CommandResponseCreateTask.class);
        Unmarshaller jaxbUnmarshallerScanners = jaxbContext.createUnmarshaller();
        CommandResponseCreateTask createTask = (CommandResponseCreateTask) jaxbUnmarshallerScanners.unmarshal(
                new StringReader(Objects.requireNonNull(OpenVasSocketHelper.processRequest(requestCreateTask, nessusScan.getNessus()))));
        if (createTask.getStatus().equals("200")){
            nessusScan.setTaskId(createTask.getCreateTaskResponse().getId());
            nessusScanRepository.save(nessusScan);
        } else {
            log.error("Error during create task for {}", nessusScan.getProject().getName());
        }
        return nessusScan;

    }

    public boolean runOnceManualScan(NessusScan nessusScan) throws JAXBException {
        createTargets(nessusScan);
        createNewTask(nessusScan);
        String requestStartTask = XmlOperationBuilder.buildStartTask(getUserForScanner(nessusScan.getNessus()), nessusScan);
        JAXBContext jaxbContext = JAXBContext.newInstance(CommandResponseStartTask.class);
        Unmarshaller jaxbUnmarshallerScanners = jaxbContext.createUnmarshaller();
        CommandResponseStartTask startTask = (CommandResponseStartTask) jaxbUnmarshallerScanners.unmarshal(
                new StringReader(Objects.requireNonNull(OpenVasSocketHelper.processRequest(requestStartTask, nessusScan.getNessus()))));
        if (startTask.getStatus().equals("200")){
            nessusScan.setRunning(true);
            nessusScan.setReportId(startTask.getStartTaskResponse().getReportId());
            nessusScanRepository.save(nessusScan);
            return true;
        } else {
            log.error("Error during running task for {}", nessusScan.getProject().getName());
        }
        return false;
    }

    private void getVulns(NessusScan nessusScan, ComandResponseGetReport reportResponse) throws JSONException {
        List<ProjectVulnerability> oldVulns = getVulnsForNessusScan(nessusScan);
        if (oldVulns.size() > 0)
            vulnTemplate.projectVulnerabilityRepository.updateVulnState(oldVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                    vulnTemplate.STATUS_REMOVED.getId());

        List<Asset> assetsActive = assetRepository.findByProject(nessusScan.getProject());
        Interface intfActive;
        for (Result result : reportResponse.getGetReportResponse().getReportFirstLvl().getReportSecondLvl().getResults().getResults()) {
           intfActive = loadInterface(nessusScan,assetsActive,reportResponse.getGetReportResponse().getReportFirstLvl().getReportSecondLvl().getHost().getIp() );
            if ( intfActive != null && intfActive.getSubnetId() == null && !intfActive.getAsset().getOrigin().equals("manual")) {
                assetsActive.add(intfActive.getAsset());
            }
            if (intfActive != null) {
                Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(result.getName());
                ProjectVulnerability projectVulnerability = new ProjectVulnerability(intfActive, null, vulnerability, result.getDescription(), null, result.getThreat(),
                        result.getPort(),null,null,vulnTemplate.SOURCE_NETWORK);
                projectVulnerability.updateStatusAndGrade(oldVulns, vulnTemplate);
                vulnTemplate.vulnerabilityPersist(oldVulns, projectVulnerability);
            } else  {
                log.error("Report contains ip {} which is not found in assets for project {}",result.getHost().getHostname(), nessusScan.getProject().getName());
            }
        }

        log.debug("Successfully loaded report results - {}", reportResponse.getGetReportResponse().getReportFirstLvl().getReportSecondLvl().getResults().getResults().size());
    }

    private Interface loadInterface(NessusScan ns, List<Asset> assets, String string) {
        try {
            List<Interface> intf = interfaceRepository.getInterfaceForIPandAssets(string.trim(), assets);

            Optional<Interface> intefaceMatchingPatter = intf.stream()
                    .filter(Interface::getActive)
                    .findFirst();
            if ( intefaceMatchingPatter.isPresent())
                return intefaceMatchingPatter.get();
            else if (intf.size() > 0){
                return intf.get(0);
            } else {
                return createInterface(ns,string,assets.size());
            }
        } catch (InvalidDataAccessResourceUsageException e) {
            log.error("psql exception in {} - {}",string,assets.size());
        }
        return null;
    }
    public Interface createInterface (NessusScan ns, String ip, int size) {
        Interface intf = new Interface();
        Asset a = new Asset();
        log.debug("Adding unknown resource... {} - {}", ip, size);
        a.setName("Unknown Resource");
        a.setProject(ns.getProject());
        a.setOrigin("ServiceDiscovery");
        a.setActive(true);
        a.setRoutingDomain(ns.getProject().getAssets().iterator().next().getRoutingDomain());
        assetRepository.save(a);
        intf.setRoutingDomain(a.getRoutingDomain());
        intf.setFloatingip(ip);
        intf.setPrivateip(ip);
        intf.setAsset(a);
        intf.setAutoCreated(true);
        intf.setActive(true);
        interfaceRepository.save(intf);
        return intf;
    }
    private List<ProjectVulnerability> getVulnsForNessusScan(NessusScan ns) {
        List<Interface> intfs = null;
        List<ProjectVulnerability> tmpVulns = new ArrayList<>();
        long deleted = 0;
        if (ns.getIsAutomatic() && ns.getPublicip())
            intfs = interfaceRepository.findByAssetInAndFloatingipNotNull(new ArrayList<>(ns.getProject().getAssets()));
        else if (ns.getIsAutomatic() && !ns.getPublicip())
            intfs = interfaceRepository.findByAssetInAndRoutingDomain(new ArrayList<>(ns.getProject().getAssets()), ns.getNessus().getRoutingDomain());
        else if (!ns.getIsAutomatic() ) {
            intfs = new ArrayList<>(ns.getInterfaces());
        }
        assert intfs != null;
        return getInfrastructureVulns(ns, intfs, tmpVulns, deleted, vulnTemplate.projectVulnerabilityRepository, interfaceRepository, log);
    }

    private static List<ProjectVulnerability> getInfrastructureVulns(NessusScan ns, List<Interface> intfs, List<ProjectVulnerability> tmpVulns, Long deleted, ProjectVulnerabilityRepository projectVulnerabilityRepository, InterfaceRepository interfaceRepository, Logger log) {
        assert intfs != null;
        for( Interface i : intfs) {
            tmpVulns.addAll(projectVulnerabilityRepository.findByAnInterface(i));
        }
        return tmpVulns;
    }
    private Boolean runAutomaticScan(NessusScan ns) throws JAXBException {

        if (ns.getIsAutomatic()) {
            log.debug("Creating new targets for automatic scan");
            try {
                ns = createTargets(ns);
                log.debug("Creating task configuration for automatic scan");
                ns = createNewTask(ns);
            } catch (HttpServerErrorException | JAXBException ex) {
                log.error("RunAutomaticScan server HTTP exception {} for {}", ex.getLocalizedMessage(), ns.getProject().getName());
            }
            nessusScanRepository.save(ns);
            log.debug("Starting running task");
            return runOnceManualScan(ns);
        }

        return false;
    }

    @Override
    public boolean runScan(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException {
        if (nessusScan.getIsAutomatic())
            return runAutomaticScan(nessusScan);
        else
            return runOnceManualScan(nessusScan);
    }

    @Override
    public void runScanManual(NessusScan nessusScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException, JAXBException {
        createTargets(nessusScan);
        createNewTask(nessusScan);
        runScan(nessusScan);
    }

    @Override
    public boolean isScanDone(NessusScan nessusScan) throws JAXBException {
        String status = XmlOperationBuilder.buildGetTask(getUserForScanner(nessusScan.getNessus()), nessusScan);
        JAXBContext jaxbContext = JAXBContext.newInstance(CommandCheckStatus.class);
        Unmarshaller jaxbUnmarshallerScanners = jaxbContext.createUnmarshaller();
        String response = OpenVasSocketHelper.processRequest(status,nessusScan.getNessus());
        assert response != null;
        CommandCheckStatus checkStatus = (CommandCheckStatus) jaxbUnmarshallerScanners.unmarshal(
                new StringReader(response));
        if (checkStatus.getStatus().equals("200")){
            String taskStatus = checkStatus.getGetTaskResponse().getTask().getStatus();
            if (taskStatus.equals(Constants.STATUS_DONE)){
                nessusScan.setRunning(false);
                nessusScanRepository.save(nessusScan);
                return true;
            } else if (taskStatus.equals(Constants.STATUS_RUNNING) || taskStatus.equals(Constants.STATUS_REQUESTED) || taskStatus.equals(Constants.STATUS_NEW)){
                return false;
            } else {
                nessusScan.setRunning(false);
                nessusScanRepository.save(nessusScan);
                log.warn("Scan for {} ended with {}", nessusScan.getProject().getName(),taskStatus);
                return false;
            }
        } else {
            log.error("Error during create task for {}", nessusScan.getProject().getName());
        }
        return false;
    }

    @Override
    public void loadVulnerabilities(NessusScan nessusScan) throws JAXBException, JSONException {
        String report = XmlOperationBuilder.buildGetReport(getUserForScanner(nessusScan.getNessus()), nessusScan);
        String response = OpenVasSocketHelper.processRequest(report,nessusScan.getNessus());
        try{

            //create a temp file
            File temp = File.createTempFile("tempfile", ".tmp");

            //write it
            BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
            bw.write(response);
            bw.close();

            System.out.println("Done");

        }catch(IOException e){

            e.printStackTrace();

        }

        JAXBContext jaxbContext = JAXBContext.newInstance(ComandResponseGetReport.class);
        Unmarshaller jaxbUnmarshallerScanners = jaxbContext.createUnmarshaller();
        assert response != null;
        ComandResponseGetReport reportResponse = (ComandResponseGetReport) jaxbUnmarshallerScanners.unmarshal(
                new StringReader(response));
        if (reportResponse.getStatus().equals("200")){
            getVulns(nessusScan, reportResponse);
        }
        vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
    }

    @Override
    public boolean initialize(Scanner scanner) throws JAXBException {
        String getConfig = XmlOperationBuilder.buildGetConfig(getUserForScanner(scanner));
        String getScanners = XmlOperationBuilder.buildGetScanners(getUserForScanner(scanner));
        JAXBContext jaxbContextConfig = JAXBContext.newInstance(ComandResponseGetConfig.class);
        JAXBContext jaxbContextScanners = JAXBContext.newInstance(ComandResponseGetScanners.class);
        Unmarshaller jaxbUnmarshallerConfig = jaxbContextConfig.createUnmarshaller();
        Unmarshaller jaxbUnmarshallerScanners = jaxbContextScanners.createUnmarshaller();
        ComandResponseGetConfig configResponse = (ComandResponseGetConfig) jaxbUnmarshallerConfig.unmarshal(new StringReader(Objects.requireNonNull(OpenVasSocketHelper.processRequest(getConfig, scanner))));
        ComandResponseGetScanners scannerResponse = (ComandResponseGetScanners) jaxbUnmarshallerScanners.unmarshal(new StringReader(Objects.requireNonNull(OpenVasSocketHelper.processRequest(getScanners, scanner))));
        if (configResponse.getStatus().equals("200") && scannerResponse.getStatus().equals("200")){
            scanner.setStatus(true);
            Optional<io.mixeway.integrations.infrastructurescan.plugin.openvas.model.Scanner> scannerId = scannerResponse.getGetScannersResponse().getScanner()
                    .stream()
                    .filter(s -> s.getName().equals(Constants.OPENVAS_DEFAULT_SCANNER))
                    .findFirst();
            Optional<Config> configId = configResponse.getGetConfigResponse().getConfig()
                    .stream()
                    .filter(s -> s.getName().equals(Constants.OPENVAS_DEFAULT_CONFIG))
                    .findFirst();
            if (scannerId.isPresent() && configId.isPresent()){
                scanner.setScannerid(scannerId.get().getId());
                scanner.setConfigId(configId.get().getId());
                scannerRepository.save(scanner);
                return true;
            } else {
                return false;
            }
        } else {
            log.error("Error during OpenVAS Socket initialization");
            return false;
        }
    }
    @Override
    public boolean canProcessRequest(NessusScan nessusScan) {
        return nessusScan.getNessus().getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET);
    }
    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET) && scanner.getStatus();
    }

    @Override
    public boolean canProcessInitRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET);
    }

    @Override
    public boolean canProcessRequest(RoutingDomain routingDomain) {
        List<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS_SOCKET));
        return scanner.size() == 1 && scanner.get(0).getRoutingDomain().getId().equals(routingDomain.getId());

    }

    @Override
    public Scanner getScannerFromClient(RoutingDomain routingDomain) {
        List<Scanner> scanner = scannerRepository.findByScannerTypeAndRoutingDomain(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS_SOCKET), routingDomain);
        return scanner.stream().findFirst().orElse(null);

    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_OPENVAS_SOCKET);
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

            nessus = nessusOperations(scannerModel.getRoutingDomain(),nessus,proxy,scannerModel.getApiUrl(),scannerType);
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(scannerModel.getPassword(), uuidToken)){
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
