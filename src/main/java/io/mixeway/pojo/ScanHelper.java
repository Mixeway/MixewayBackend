package io.mixeway.pojo;

import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanClient;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import io.mixeway.config.Constants;
import io.mixeway.rest.project.model.RunScanForAssets;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class ScanHelper {
    private static final String NESSUS_TEMPLATE = "Basic Network Scan";
    private static final int EXECUTE_ONCE = 1;
    private AssetRepository assetRepository;
    private InterfaceRepository interfaceRepository;
    private ScannerTypeRepository scannerTypeRepository;
    private ScannerRepository scannerRepository;
    private NessusScanTemplateRepository nessusTemplateRepository;
    private NessusScanRepository nessusScanRepository;
    private List<NetworkScanClient> networkScanClients;

    @Lazy
    @Autowired
    ScanHelper(AssetRepository assetRepository, InterfaceRepository interfaceRepository, ScannerTypeRepository scannerTypeRepository,
               ScannerRepository scannerRepository, NessusScanTemplateRepository nessusScanTemplateRepository,
               List<NetworkScanClient> networkScanClients, NessusScanRepository nessusScanRepository){
        this.assetRepository = assetRepository;
        this.interfaceRepository = interfaceRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.nessusScanRepository = nessusScanRepository;
        this.scannerRepository = scannerRepository;
        this.nessusTemplateRepository = nessusScanTemplateRepository;
        this.networkScanClients = networkScanClients;
    }

    private final static Logger log = LoggerFactory.getLogger(ScanHelper.class);


    public List<String> prepareTargetsForScan(NessusScan nessusScan, boolean logInfo) {
        List<String> interfacesToScan;
        if (nessusScan.getIsAutomatic()) {
            List<Asset> assets = assetRepository.findByProjectAndActive(nessusScan.getProject(), true);
            if (nessusScan.getNessus().getUsePublic()) {
                List<Interface> intfs = interfaceRepository.findByAssetInAndFloatingipNotNull(assets);
                interfacesToScan = intfs.stream()
                        .filter(n -> n.getFloatingip() != null && !n.getAutoCreated() && n.getAsset().getActive())
                        .map(Interface::getFloatingip)
                        .collect(Collectors.toList());
                interfacesToScan.addAll(intfs.stream().filter(n -> n.getPool() != null && !n.getAutoCreated()).map(Interface::getPool).collect(Collectors.toList()));
            } else {
                Set<Interface> intfs = interfaceRepository.findByAssetInAndRoutingDomainAndActive(nessusScan.getProject().getAssets(), nessusScan.getNessus().getRoutingDomain(), true);
                interfacesToScan = intfs.stream()
                        .filter(n -> n.getPrivateip() != null && !n.getAutoCreated())
                        .map(Interface::getPrivateip)
                        .collect(Collectors.toList());
                interfacesToScan.addAll(intfs.stream()
                        .filter(n -> n.getPool() != null && !n.getAutoCreated()  )
                        .map(Interface::getPool)
                        .collect(Collectors.toList()));
            }
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
        if (logInfo)
            log.info("Scope of scan is [{} - {}]: {}",nessusScan.getProject().getName(),nessusScan.getNessus().getRoutingDomain().getName(), StringUtils.join(interfacesToScan, ','));
        updateInterfaceState(nessusScan,interfacesToScan);
        return interfacesToScan;
    }

    public void updateInterfaceState(NessusScan nessusScan, boolean state){
        // SETTING INTERFACE.SCANRUNNING
        for (String ip : prepareTargetsForScan(nessusScan,false)){
            Optional<Interface> inter = interfaceRepository.findByAssetInAndPrivateipAndActive(nessusScan.getProject().getAssets(), ip, true);
            if (inter.isPresent()){
                inter.get().setScanRunning(state);
                interfaceRepository.save(inter.get());
                log.info("Update inerface state for {} to {}", inter.get().getPrivateip(),state);
            }
        }
    }

    private void updateInterfaceState(NessusScan nessusScan, List<String> interfacesToScan) {
        try {
            String requestId = UUID.randomUUID().toString();
            for (String ip : interfacesToScan) {
                Optional<Interface> inter = interfaceRepository.findByAssetInAndPrivateipAndActive(nessusScan.getProject().getAssets(), ip, true);
                if (inter.isPresent()) {
                    inter.get().setScanRunning(true);
                    Asset asset = inter.get().getAsset();
                    asset.setRequestId(requestId);
                    interfaceRepository.save(inter.get());
                    assetRepository.save(asset);
                }
            }
            nessusScan.setRequestId(requestId);
            nessusScanRepository.save(nessusScan);
        } catch (Exception ex) {
            log.error("IllegalArgumentException during updating interface for {}", nessusScan.getProject().getName());
        }
    }
    public Set<Interface> prepareInterfacesToScan(List<RunScanForAssets> runScanForAssets, Project project){
        Set<Interface> interfaces = new HashSet<>();
        for (RunScanForAssets assetToScan : runScanForAssets){
            Optional<Interface> intf = interfaceRepository.findById(assetToScan.getAssetId());
            if (intf.isPresent() && intf.get().getAsset().getProject() == project)
                interfaces.add(intf.get());
        }
        return interfaces;
    }
    //Założenie, że jest tylko jedna domena routingowa w jednym projekcie
    private Scanner findNessusForInterfaces(Set<Interface> intfs) {
        List<Scanner> nessuses = new ArrayList<>();
        List<ScannerType> types = new ArrayList<>();
        types.add(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS));
        types.add(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
        types.add(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
        types.add(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS_SOCKET));
        List<RoutingDomain> uniqueDomainInProjectAssets = intfs.stream().map(Interface::getRoutingDomain).distinct().collect(Collectors.toList());
        for (RoutingDomain rd : uniqueDomainInProjectAssets) {
            nessuses.addAll(scannerRepository.findByRoutingDomainAndScannerTypeIn(rd, types));
        }
        return nessuses.stream()
                .filter(s -> s.getScannerType() == scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS))
                .findFirst().orElseGet(() -> nessuses.get(0));

    }
    public boolean runInfraScanForScope(Project project, Set<Interface> intfs)  {
        try {
            NessusScan scan;
            Scanner nessus = this.findNessusForInterfaces(intfs);
            if (nessus == null)
                throw new Exception("No suitable network scanner for project");
            scan = new NessusScan();
            scan.setIsAutomatic(false);
            scan.setNessus(nessus);
            scan.setNessusScanTemplate(nessusTemplateRepository.findByNameAndNessus(NESSUS_TEMPLATE, nessus));
            scan.setProject(project);
            scan.setPublicip(nessus.getUsePublic());
            scan.setRunning(false);
            scan.setInterfaces(intfs);
            scan.setScanFrequency(EXECUTE_ONCE);
            scan.setScheduled(false);
            nessusScanRepository.save(scan);
            for (NetworkScanClient networkScanClient : networkScanClients){
                if (networkScanClient.canProcessRequest(scan)){
                    networkScanClient.runScanManual(scan);
                }
            }
            return true;
        } catch (Exception e){
            e.printStackTrace();
            log.error("Got error during running scan for scope - {} ",e.getLocalizedMessage());
            return false;
        }
    }

}