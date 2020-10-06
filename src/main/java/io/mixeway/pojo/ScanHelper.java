package io.mixeway.pojo;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import io.mixeway.rest.project.model.RunScanForAssets;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class ScanHelper {
    private AssetRepository assetRepository;
    private InterfaceRepository interfaceRepository;
    private NessusScanRepository nessusScanRepository;


    @Lazy
    @Autowired
    ScanHelper(AssetRepository assetRepository, InterfaceRepository interfaceRepository, NessusScanRepository nessusScanRepository){
        this.assetRepository = assetRepository;
        this.interfaceRepository = interfaceRepository;
        this.nessusScanRepository = nessusScanRepository;
    }

    private final static Logger log = LoggerFactory.getLogger(ScanHelper.class);


    public List<String> prepareTargetsForScan(NessusScan nessusScan, boolean logInfo) {
        List<String> interfacesToScan;
        if (nessusScan.getIsAutomatic()) {
            List<Asset> assets = assetRepository.findByProjectAndActive(nessusScan.getProject(), true);
            List<Interface> interfaces = interfaceRepository.findByAssetInAndRoutingDomain(assets,nessusScan.getNessus().getRoutingDomain());
            interfacesToScan = interfaces.stream()
                    .filter(n -> n.getPrivateip() != null && !n.getAutoCreated())
                    .map(Interface::getPrivateip)
                    .collect(Collectors.toList());
            interfacesToScan.addAll(interfaces.stream()
                    .filter(n -> n.getPool() != null && !n.getAutoCreated()  )
                    .map(Interface::getPool)
                    .collect(Collectors.toList()));
        } else {
            if (nessusScan.getNessus().getUsePublic()) {
                interfacesToScan = nessusScan.getInterfaces().stream()
                        .filter(n -> n.getFloatingip() != null && !n.getAutoCreated()  && n.getAsset().getActive())
                        .map(Interface::getFloatingip)
                        .collect(Collectors.toList());
                interfacesToScan.addAll(nessusScan.getInterfaces().stream()
                        .filter(n -> n.getPool() != null && !n.getAutoCreated()  && n.getAsset().getActive())
                        .map(Interface::getPool)
                        .collect(Collectors.toList()));
            } else {
                interfacesToScan =
                        nessusScan.getInterfaces().stream()
                                .filter(n -> n.getPrivateip() != null   )
                                .map(Interface::getPrivateip)
                                .collect(Collectors.toList());
                interfacesToScan.addAll(nessusScan.getInterfaces().stream()
                        .filter(n -> n.getPool() != null && !n.getAutoCreated()  )
                        .map(Interface::getPool)
                        .collect(Collectors.toList()));

            }
        }
        if (logInfo) {
            log.info("Scope of scan is [{} - {}]: {}", nessusScan.getProject().getName(), nessusScan.getNessus().getRoutingDomain().getName(), StringUtils.join(interfacesToScan, ','));
            updateInterfaceState(nessusScan, interfacesToScan);
        }
        return interfacesToScan;
    }

    private void updateInterfaceState(NessusScan nessusScan, List<String> interfacesToScan) {
        try {
            for (String ip : interfacesToScan) {
                Optional<Interface> inter = interfaceRepository.findByAssetInAndPrivateipAndActive(nessusScan.getProject().getAssets(), ip, true);
                inter.ifPresent(anInterface -> anInterface.setScanRunning(true));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            log.error("{} during updating interface for {}",ex.getLocalizedMessage(), nessusScan.getProject().getName());
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