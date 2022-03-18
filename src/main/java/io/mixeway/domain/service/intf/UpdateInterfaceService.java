package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InterfaceRepository;
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

    public void changeRunningState(InfraScan scan) {
        for (Interface i : scan.getInterfaces()) {
            i.getAsset().setRequestId(scan.getRequestId());
            i.setScanRunning(true);
            interfaceRepository.save(i);
            assetRepository.save(i.getAsset());
        }
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
        }
        interfaces.stream().filter(i -> assets.add(i.getAsset())).collect(Collectors.toList());
        for (Asset asset : assets){
            asset.setRequestId(requestId);
            assetRepository.save(asset);
        }
    }

    @Transactional
    public void updateRiskForInterfaces(InfraScan ns) {
        List<String> ipAddresses = scanHelper.prepareTargetsForScan(ns, false);
        for (String ipAddress : ipAddresses) {
            Optional<Interface> interfaceOptional = interfaceRepository.findByPrivateipAndActiveAndAssetIn(ipAddress, true, new ArrayList<>(ns.getProject().getAssets())).stream().findFirst();
            interfaceOptional.ifPresent(anInterface -> anInterface.setRisk(Math.min(projectRiskAnalyzer.getInterfaceRisk(anInterface), 100)));
        }
    }

    /**
     * Updating interface state, chaniging running=false for interfaces in given project
     */
    public void clearState(Project p) {
        interfaceRepository.updateInterfaceStateForNotRunningScan(p);
    }
}
