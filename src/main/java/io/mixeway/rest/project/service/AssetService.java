package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.rest.project.model.AssetCard;
import io.mixeway.rest.project.model.AssetModel;
import io.mixeway.rest.project.model.AssetPutModel;
import io.mixeway.rest.project.model.RunScanForAssets;
import io.mixeway.rest.utils.IpAddressUtils;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfrastructureVuln;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanService;
import io.mixeway.pojo.Status;

import javax.transaction.Transactional;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AssetService {
    private static final Logger log = LoggerFactory.getLogger(AssetService.class);
    private final ProjectRepository projectRepository;
    private final InterfaceRepository interfaceRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final RoutingDomainRepository routingDomainRepository;
    private final AssetRepository assetRepository;
    private final ScanHelper scanHelper;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final NetworkScanService networkScanService;
    private List<String> logs = new ArrayList<String>(){{
        add(Constants.LOG_SEVERITY);
        add(Constants.INFO_SEVERITY);
    }};

    @Autowired
    AssetService(ProjectRepository projectRepository, InterfaceRepository interfaceRepository,
                 ProjectRiskAnalyzer projectRiskAnalyzer,
                 RoutingDomainRepository routingDomainRepository, AssetRepository assetRepository,
                 ScanHelper scanHelper, InfrastructureVulnRepository infrastructureVulnRepository, NetworkScanService networkScanService){
        this.projectRepository = projectRepository;
        this.interfaceRepository = interfaceRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
        this.routingDomainRepository = routingDomainRepository;
        this.assetRepository = assetRepository;
        this.scanHelper = scanHelper;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.networkScanService = networkScanService;
    }

    public ResponseEntity<AssetCard> showAssets(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent()){
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
                    int risk = projectRiskAnalyzer.getInterfaceRisk(i);
                    am.setRisk(Math.min(risk, 100));
                    assetModels.add(am);
                } catch (NullPointerException e) {
                    log.warn("Nullpointer on show assets of {} and interface {}", project.get().getName(), i.getAsset().getName());
                }
            }
            assetCard.setAssets(assetModels);
            return new ResponseEntity<>(assetCard, HttpStatus.OK);

        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    @Transactional
    public ResponseEntity<Status> saveAsset(Long id, AssetPutModel assetPutModel, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            Asset asset = new Asset();
            asset.setProject(project.get());
            asset.setRoutingDomain(routingDomainRepository.getOne(assetPutModel.getRoutingDomainForAsset()));
            asset.setName(assetPutModel.getAssetName());
            asset.setOrigin("manual");
            asset.setActive(true);
            assetRepository.save(asset);
            for(String ip : assetPutModel.getIpAddresses().split(",")){
                if (IpAddressUtils.validate(ip)){
                    Interface inf = new Interface();
                    inf.setActive(true);
                    inf.setAsset(asset);
                    inf.setPrivateip(ip);
                    inf.setAutoCreated(false);
                    inf.setRoutingDomain(asset.getRoutingDomain());
                    interfaceRepository.save(inf);
                } else if (ip.contains("/")){
                    for (String ipFromCidr : IpAddressUtils.getIpAddressesFromCidr(ip)){
                        Interface inf = new Interface();
                        inf.setActive(true);
                        inf.setAsset(asset);
                        inf.setPrivateip(ipFromCidr);
                        inf.setAutoCreated(false);
                        inf.setRoutingDomain(asset.getRoutingDomain());
                        interfaceRepository.save(inf);
                    }
                } else if (ip.contains("-")){
                    for (String ipFromRange : IpAddressUtils.getIpAddressesFromRange(ip)){
                        Interface inf = new Interface();
                        inf.setActive(true);
                        inf.setAsset(asset);
                        inf.setPrivateip(ipFromRange);
                        inf.setAutoCreated(false);
                        inf.setRoutingDomain(asset.getRoutingDomain());
                        interfaceRepository.save(inf);
                    }
                }
            }
            //asset = assetRepository.findById(asset.getId()).get();
            log.info("{} - Created new asset [{}]{} ", username, project.get().getName(), asset.getName());
            return new ResponseEntity<>(new Status("created"), HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> runScanForAssets(Long id, List<RunScanForAssets> runScanForAssets, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            Set<Interface> intfs =  scanHelper.prepareInterfacesToScan(runScanForAssets, project.get());
            if (scanHelper.runInfraScanForScope(project.get(), intfs)) {
                log.info("{} - Started scan for project {} - scope partial", username, project.get().getName());
                return new ResponseEntity<>(null, HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.NOT_FOUND);
        }
    }
    public ResponseEntity<Status> runAllAssetScan(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            List<Interface> intfs =  interfaceRepository.findByAssetIn(new ArrayList<>(project.get().getAssets())).stream().filter(Interface::isScanRunning).collect(Collectors.toList());
            if (scanHelper.runInfraScanForScope(project.get(),new HashSet<>(intfs))) {
                log.info("{} - Started scan for project {} - scope full", username, project.get().getName());
                return new ResponseEntity<>(null, HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.NOT_FOUND);
        }
    }
    public ResponseEntity<Status> runSingleAssetScan( Long assetId, String username) {
        List<Interface> i = new ArrayList<>();
        Optional<Interface> intf = interfaceRepository.findById(assetId);
        if (intf.isPresent()) {
            i.add(intf.get());
            if (scanHelper.runInfraScanForScope(intf.get().getAsset().getProject(), new HashSet<>(i))) {
                log.info("{} - Started scan for project {} - scope single", username, intf.get().getAsset().getProject().getName());
                return new ResponseEntity<>(null, HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
            }
        } else
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
    }

    //TO JEST INTERFEJS DELETE
    @Transactional
    public ResponseEntity<Status> deleteAsset(Long assetId, String name) {
        Optional<Interface> interf = interfaceRepository.findById(assetId);
        String assetName = interf.isPresent() ? interf.get().getAsset().getName() : "";
        String projectName = interf.isPresent() ? interf.get().getAsset().getProject().getName() : "";
        String ip = interf.isPresent() ? interf.get().getPrivateip() : "";
        interf.ifPresent(interfaceRepository::delete);
        log.info("{} - Deleted interface [{}] {} - {}", name, projectName, assetName,ip);
        return new ResponseEntity<>(null,HttpStatus.OK);
    }

    public ResponseEntity<List<InfrastructureVuln>> showInfraVulns(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.get().getAssets()));
            List<InfrastructureVuln> vulnsNotLog = infrastructureVulnRepository.findByIntfInAndSeverityNotIn(interfaces, logs);
            return new ResponseEntity<>(vulnsNotLog,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> enableInfraAutoScan(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            project.get().setAutoInfraScan(true);
            projectRepository.save(project.get());
            networkScanService.configureAutomaticScanForProject(project.get());
            log.info("{} - Enabled auto infrastructure scan for project {} - scope single", username, project.get().getName());
            return new ResponseEntity<>(null, HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableInfraAutoScan(Long id, String name) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            project.get().setAutoInfraScan(false);
            projectRepository.save(project.get());
            log.info("{} - Disabled auto infrastructure scan for project {} - scope single", name, project.get().getName());
            return new ResponseEntity<>(null, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
}
