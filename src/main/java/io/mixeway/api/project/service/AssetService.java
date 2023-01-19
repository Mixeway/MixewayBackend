package io.mixeway.api.project.service;

import io.mixeway.api.project.model.AssetCard;
import io.mixeway.api.project.model.AssetModel;
import io.mixeway.api.project.model.AssetPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.domain.exceptions.ScanException;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.domain.service.intf.DeleteInterfaceService;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.routingdomain.FindRoutingDomainService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.AssetToCreate;
import io.mixeway.scanmanager.service.network.NetworkScanService;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.RunScanForAssets;
import io.mixeway.utils.ScanHelper;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Log4j2
@RequiredArgsConstructor
public class AssetService {
    private List<String> logs = new ArrayList<String>(){{
        add(Constants.LOG_SEVERITY);
        add(Constants.INFO_SEVERITY);
    }};
    private final ScanHelper scanHelper;
    private final NetworkScanService networkScanService;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    private final InterfaceOperations interfaceOperations;
    private final FindProjectService findProjectService;
    private final FindInterfaceService findInterfaceService;
    private final FindRoutingDomainService findRoutingDomainService;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final DeleteInterfaceService deleteInterfaceService;
    private final UpdateProjectService updateProjectService;

    public ResponseEntity<AssetCard> showAssets(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            AssetCard assetCard = new AssetCard();
            List<AssetModel> assetModels = new ArrayList<>();
            assetCard.setAutoInfraScan(project.get().isAutoInfraScan());
            for (Interface i : findInterfaceService.findByAssetIn(new ArrayList<>(project.get().getAssets()))){
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
        try {
            Optional<Project> project = findProjectService.findProjectById(id);
            Optional<RoutingDomain> routingDomain = findRoutingDomainService.findById(assetPutModel.getRoutingDomainForAsset());
            if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()) && routingDomain.isPresent()) {
                Asset asset = getOrCreateAssetService.getOrCreateAsset(
                        AssetToCreate
                                .builder()
                                .ip(null)
                                .hostname(assetPutModel.getAssetName())
                                .routingDomain(routingDomain.get().getName())
                                .build(),
                        project.get(),
                        "manual"
                );
                List<Interface> interfaces = interfaceOperations.createInterfacesForModel(asset, routingDomain.get(), assetPutModel.getIpAddresses());
                interfaceOperations.storeInterfaces(interfaces);
                //asset = assetRepository.findById(asset.getId()).get();
                log.info("{} - Created new asset [{}]{} ", principal.getName(), project.get().getName(), asset.getName());
                return new ResponseEntity<>(new Status("created"), HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            }
        } catch (ScanException e){
            return new ResponseEntity<>(new Status(e.getMessage()), HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> runScanForAssets(Long id, List<RunScanForAssets> runScanForAssets, Principal principal) throws Exception {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Set<Interface> intfs =  scanHelper.prepareInterfacesToScan(runScanForAssets, project.get());
            List<InfraScan> scans = networkScanService.configureAndRunManualScanForScope(project.get(), new ArrayList(intfs), false, true);
            if (scans.stream().allMatch(InfraScan::getInQueue)) {
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
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<Interface> intfs =  findInterfaceService.findByAssetIn(new ArrayList<>(project.get().getAssets())).stream().filter(i -> !i.isScanRunning()).collect(Collectors.toList());
            List<InfraScan> scans = networkScanService.configureAndRunManualScanForScope(project.get(), new ArrayList(intfs), false, true);
            if (scans.stream().allMatch(InfraScan::getInQueue)) {
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
        Optional<Interface> intf = findInterfaceService.findById(assetId);
        if (intf.isPresent() && permissionFactory.canUserAccessProject(principal, intf.get().getAsset().getProject())) {
            i.add(intf.get());
            List<InfraScan> scans = networkScanService.configureAndRunManualScanForScope(intf.get().getAsset().getProject(), i, false, true);
            if (scans.size() >0 && scans.stream().allMatch(InfraScan::getInQueue)) {
                log.info("{} - Started scan for project {} - scope single", principal.getName(), intf.get().getAsset().getProject().getName());
                return new ResponseEntity<>(HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            }
        } else
            return new ResponseEntity<>( HttpStatus.NOT_FOUND);
    }

    public ResponseEntity<Status> deleteAsset(Long assetId, Principal principal) {
        Optional<Interface> interf = findInterfaceService.findById(assetId);
        if (interf.isPresent() && permissionFactory.canUserAccessProject(principal, interf.get().getAsset().getProject())) {
            log.info("{} - Deleted interface [{}] {} - {}", principal.getName(), interf.get().getAsset().getProject().getName() , interf.get().getAsset().getName(), interf.get().getPrivateip());
            deleteInterfaceService.delete(interf);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<List<ProjectVulnerability>> showInfraVulns(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            List<ProjectVulnerability> vulnsNotLog = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySourceAndSeverityNotIn(project.get(),vulnTemplate.SOURCE_NETWORK, logs);
            return new ResponseEntity<>(vulnsNotLog,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> enableInfraAutoScan(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.enableInfraAutoScan(project.get());
            networkScanService.configureAutomaticScanForProject(project.get());
            log.info("{} - Enabled auto infrastructure scan for project {} - scope single", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableInfraAutoScan(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.disableInfraAutoScan(project.get());
            log.info("{} - Disabled auto infrastructure scan for project {} - scope single", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
}
