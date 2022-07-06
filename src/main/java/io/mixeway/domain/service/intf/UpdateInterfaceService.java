package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.domain.service.asset.UpdateAssetService;
import io.mixeway.utils.ProjectRiskAnalyzer;
import io.mixeway.utils.ScanHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateInterfaceService {
    private final InterfaceRepository interfaceRepository;
    private final AssetRepository assetRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final ScanHelper scanHelper;
    private final InfraScanRepository infraScanRepository;
    private final UpdateAssetService updateAssetService;

    @Transactional
    public void changeRunningState(InfraScan scan, boolean running, boolean inqueue) {
        scan.getInterfaces().forEach(i -> i.setScanRunning(true));
        scan.setRunning(running);
        scan.setInQueue(inqueue);
        scan = infraScanRepository.saveAndFlush(scan);
        updateAssetService.setRequestId(scan);
    }
    /**
     * Method set state of runnig=true for give Intercace list. Also update Asset with proper requestId.
     *
     * @param interfaces interaces to update state
     * @param requestId requestId to update on asset entity
     */
    public void updateIntfsStateAndAssetRequestId(List<Interface> interfaces, String requestId){
        Set<Asset> assets = new HashSet<>();
        for (Interface i : interfaces){
            i.setScanRunning(true);
            interfaceRepository.save(i);
            Optional<Asset> asset = assetRepository.findById(i.getAsset().getId());
            if(asset.isPresent()) {
                asset.get().setRequestId(requestId);
                assetRepository.save(asset.get());
            }
        }
    }

    @Transactional
    public void updateRiskForInterfaces(InfraScan ns) {
        List<String> ipAddresses = scanHelper.prepareTargetsForScan(ns, false);
        for (String ipAddress : ipAddresses) {
            Optional<Interface> interfaceOptional = interfaceRepository.findByPrivateipAndActiveAndAssetIn(ipAddress, true, new ArrayList<>(ns.getProject().getAssets())).stream().findFirst();
            if (interfaceOptional.isPresent()){
                int risk = Math.min(projectRiskAnalyzer.getInterfaceRisk(interfaceOptional.get()), 100);
                interfaceOptional.get().setRisk(risk);
            }
        }
    }

    /**
     * Updating interface state, chaniging running=false for interfaces in given project
     */
    @Transactional
    public void clearState(Project p) {
        interfaceRepository.updateInterfaceStateForNotRunningScan(p);
    }
}
