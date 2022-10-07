package io.mixeway.utils;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.InfraScanRepository;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Log4j2
public class ScanHelper {
    private final AssetRepository assetRepository;
    private final InterfaceRepository interfaceRepository;
    private final InfraScanRepository infraScanRepository;


    @Lazy
    @Autowired
    ScanHelper(AssetRepository assetRepository, InterfaceRepository interfaceRepository, InfraScanRepository infraScanRepository){
        this.assetRepository = assetRepository;
        this.interfaceRepository = interfaceRepository;
        this.infraScanRepository = infraScanRepository;
    }

    public List<String> prepareTargetsForScan(InfraScan infraScan, boolean logInfo) {
        List<String> interfacesToScan;
        if (infraScan.getIsAutomatic()) {
            List<Asset> assets = assetRepository.findByProjectAndActive(infraScan.getProject(), true);
            List<Interface> interfaces = interfaceRepository.findByAssetInAndRoutingDomain(assets, infraScan.getNessus().getRoutingDomain());
            interfacesToScan = interfaces.stream()
                    .filter(n -> n.getPrivateip() != null && !n.getAutoCreated())
                    .map(Interface::getPrivateip)
                    .collect(Collectors.toList());
            interfacesToScan.addAll(interfaces.stream()
                    .filter(n -> n.getPool() != null && !n.getAutoCreated()  )
                    .map(Interface::getPool)
                    .collect(Collectors.toList()));
        } else {
            if (infraScan.getNessus().getUsePublic()) {
                interfacesToScan = infraScan.getInterfaces().stream()
                        .filter(n -> n.getFloatingip() != null && !n.getAutoCreated()  && n.getAsset().getActive())
                        .map(Interface::getFloatingip)
                        .collect(Collectors.toList());
                interfacesToScan.addAll(infraScan.getInterfaces().stream()
                        .filter(n -> n.getPool() != null && !n.getAutoCreated()  && n.getAsset().getActive())
                        .map(Interface::getPool)
                        .collect(Collectors.toList()));
            } else {
                interfacesToScan =
                        infraScan.getInterfaces().stream()
                                .filter(n -> n.getPrivateip() != null   )
                                .map(Interface::getPrivateip)
                                .collect(Collectors.toList());
                interfacesToScan.addAll(infraScan.getInterfaces().stream()
                        .filter(n -> n.getPool() != null && !n.getAutoCreated()  )
                        .map(Interface::getPool)
                        .collect(Collectors.toList()));

            }
        }
        if (logInfo) {
            log.info("Scope of scan is [{} - {}]: {}", infraScan.getProject().getName(), infraScan.getNessus().getRoutingDomain().getName(), StringUtils.join(interfacesToScan, ','));
            updateInterfaceState(infraScan, interfacesToScan);
        }
        return interfacesToScan;
    }

    private void updateInterfaceState(InfraScan infraScan, List<String> interfacesToScan) {
        try {
            for (String ip : interfacesToScan) {
                if (ip!=null && infraScan.getProject().getAssets() != null) {
                    List<Interface> inter = interfaceRepository.findByAssetInAndPrivateipAndActive(infraScan.getProject().getAssets(), ip, true);
                    inter.forEach(anInterface -> anInterface.setScanRunning(true));
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            log.error("{} during updating interface for {}",ex.getLocalizedMessage(), infraScan.getProject().getName());
        }
    }
    public Set<Interface> prepareInterfacesToScan(List<RunScanForAssets> runScanForAssets, Project project){
        Set<Interface> interfaces = new HashSet<>();
        for (RunScanForAssets assetToScan : runScanForAssets){
            Optional<Interface> intf = interfaceRepository.findById(assetToScan.getAssetId());
            if (intf.isPresent() && intf.get().getAsset().getProject().getId().equals(project.getId()))
                interfaces.add(intf.get());
        }
        return interfaces;
    }

}