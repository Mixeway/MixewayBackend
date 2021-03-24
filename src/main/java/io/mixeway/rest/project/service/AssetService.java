package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.rest.project.model.AssetCard;
import io.mixeway.rest.project.model.AssetModel;
import io.mixeway.rest.project.model.AssetPutModel;
import io.mixeway.rest.project.model.RunScanForAssets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanService;
import io.mixeway.pojo.Status;

import javax.transaction.Transactional;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AssetService {
    private static final Logger log = LoggerFactory.getLogger(AssetService.class);
    private final ProjectRepository projectRepository;
    private final InterfaceRepository interfaceRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final AssetRepository assetRepository;
    private final ScanHelper scanHelper;
    private final NetworkScanService networkScanService;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    private final InterfaceOperations interfaceOperations;
    private List<String> logs = new ArrayList<String>(){{
        add(Constants.LOG_SEVERITY);
        add(Constants.INFO_SEVERITY);
    }};

    AssetService(ProjectRepository projectRepository, InterfaceRepository interfaceRepository,
                 RoutingDomainRepository routingDomainRepository, AssetRepository assetRepository,
                 ScanHelper scanHelper, NetworkScanService networkScanService, InterfaceOperations interfaceOperations,
                 PermissionFactory permissionFactory, VulnTemplate vulnTemplate){
        this.projectRepository = projectRepository;
        this.interfaceOperations = interfaceOperations;
        this.interfaceRepository = interfaceRepository;
        this.permissionFactory = permissionFactory;
        this.routingDomainRepository = routingDomainRepository;
        this.assetRepository = assetRepository;
        this.scanHelper = scanHelper;
        this.networkScanService = networkScanService;
        this.vulnTemplate = vulnTemplate;
    }

    public ResponseEntity<AssetCard> showAssets(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            AssetCard assetCard = new AssetCard();
            List<AssetModel> assetModels = new ArrayList<>();
            assetCard.setAutoInfraScan(project.get().isAutoInfraScan());
            for (Interface i : interfaceRepository.findByAssetIn(new ArrayList<>(project.get().getAssets()))){
                try {
                    AssetModel am = new AssetModel();
                    am.setAssetId(i.getId());
                    am.setHostname(i.getAsset().getName());
                    am.setIpAddress(i.getPrivateip());
                    am.setRoutingDomain(i.getRoutingDomain() != null ? i.getRoutingDomain().getName() : i.getAsset().getRoutingDomain().getName());
                    am.setRunning(i.isScanRunning());
                    am.setRisk(i.getRisk());
                    assetModels.add(am);
                } catch (NullPointerException e) {
                    log.warn("Nullpointer on show assets of {} and interface {}", project.get().getName(), i.getAsset().getName());
                }
            }
            assetCard.setAssets(assetModels);
            return new ResponseEntity<>(assetCard, HttpStatus.OK);

        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    @Transactional
    public ResponseEntity<Status> saveAsset(Long id, AssetPutModel assetPutModel, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<RoutingDomain> routingDomain = routingDomainRepository.findById(assetPutModel.getRoutingDomainForAsset());
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()) && routingDomain.isPresent()){
            Asset asset = new Asset();
            asset.setProject(project.get());
            asset.setRoutingDomain(routingDomainRepository.getOne(assetPutModel.getRoutingDomainForAsset()));
            asset.setName(assetPutModel.getAssetName());
            asset.setOrigin("manual");
            asset.setActive(true);
            assetRepository.save(asset);
            List<Interface> interfaces = interfaceOperations.createInterfacesForModel(asset, routingDomain.get(), assetPutModel.getIpAddresses());
            interfaces = interfaceRepository.saveAll(interfaces);
            //asset = assetRepository.findById(asset.getId()).get();
            log.info("{} - Created new asset [{}]{} ", principal.getName(), project.get().getName(), asset.getName());
            return new ResponseEntity<>(new Status("created"), HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> runScanForAssets(Long id, List<RunScanForAssets> runScanForAssets, Principal principal) throws Exception {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Set<Interface> intfs =  scanHelper.prepareInterfacesToScan(runScanForAssets, project.get());
            List<NessusScan> scans = networkScanService.configureAndRunManualScanForScope(project.get(), new ArrayList(intfs));
            if (scans.stream().allMatch(NessusScan::getInQueue)) {
                log.info("{} - Started scan for project {} - scope partial", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    public ResponseEntity<Status> runAllAssetScan(Long id, Principal principal) throws Exception {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<Interface> intfs =  interfaceRepository.findByAssetIn(new ArrayList<>(project.get().getAssets())).stream().filter(i -> !i.isScanRunning()).collect(Collectors.toList());
            List<NessusScan> scans = networkScanService.configureAndRunManualScanForScope(project.get(), new ArrayList(intfs));
            if (scans.stream().allMatch(NessusScan::getInQueue)) {
                log.info("{} - Started scan for project {} - scope full", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    public ResponseEntity<Status> runSingleAssetScan( Long assetId, Principal principal) throws Exception {
        List<Interface> i = new ArrayList<>();
        Optional<Interface> intf = interfaceRepository.findById(assetId);
        if (intf.isPresent() && permissionFactory.canUserAccessProject(principal, intf.get().getAsset().getProject())) {
            i.add(intf.get());
            List<NessusScan> scans = networkScanService.configureAndRunManualScanForScope(intf.get().getAsset().getProject(), i);
            if (scans.size() >0 && scans.stream().allMatch(NessusScan::getInQueue)) {
                log.info("{} - Started scan for project {} - scope single", principal.getName(), intf.get().getAsset().getProject().getName());
                return new ResponseEntity<>(HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            }
        } else
            return new ResponseEntity<>( HttpStatus.NOT_FOUND);
    }

    @Transactional
    public ResponseEntity<Status> deleteAsset(Long assetId, Principal principal) {
        Optional<Interface> interf = interfaceRepository.findById(assetId);
        if (interf.isPresent() && permissionFactory.canUserAccessProject(principal, interf.get().getAsset().getProject())) {
            String assetName = interf.get().getAsset().getName();
            String projectName = interf.get().getAsset().getProject().getName();
            String ip = interf.get().getPrivateip();
            interf.ifPresent(interfaceRepository::delete);
            log.info("{} - Deleted interface [{}] {} - {}", principal.getName(), projectName, assetName, ip);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<List<ProjectVulnerability>> showInfraVulns(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            List<ProjectVulnerability> vulnsNotLog = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySourceAndSeverityNotIn(project.get(),vulnTemplate.SOURCE_NETWORK, logs);
            return new ResponseEntity<>(vulnsNotLog,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> enableInfraAutoScan(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            project.get().setAutoInfraScan(true);
            projectRepository.save(project.get());
            networkScanService.configureAutomaticScanForProject(project.get());
            log.info("{} - Enabled auto infrastructure scan for project {} - scope single", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableInfraAutoScan(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            project.get().setAutoInfraScan(false);
            projectRepository.save(project.get());
            log.info("{} - Disabled auto infrastructure scan for project {} - scope single", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
}
