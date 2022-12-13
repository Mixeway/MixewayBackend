package io.mixeway.domain.service.intf;


import io.mixeway.db.entity.*;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.exceptions.ScanException;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.utils.IpAddressUtils;
import io.mixeway.utils.ProjectRiskAnalyzer;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class InterfaceOperations {
    private final InterfaceRepository interfaceRepository;
    private final InfraScanRepository infraScanRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final AssetRepository assetRepository;
    private final GetOrCreateAssetService getOrCreateAssetService;

    public Interface getOrCreateInterface(String ip, RoutingDomain routingDomain, Project project){
        Asset asset = getOrCreateAssetService.getOrCreateAsset(ip, routingDomain,project);

        return createAndReturnInterfaceForAsset(asset,ip);
    }

    public Interface createInterfaceForAsset(Asset asset, String ip) {
        if (canCreateInterfaceForAsset(asset, ip)) {
            Interface intf = new Interface();
            intf.setAsset(asset);
            intf.setActive(true);
            intf.setPrivateip(ip);
            return interfaceRepository.save(intf);
        }
        return null;
    }
    public Interface createAndReturnInterfaceForAsset(Asset a, String ip){
        if (canCreateInterfaceForAsset(a, ip)) {
            Interface intf = new Interface();
            intf.setRoutingDomain(a.getRoutingDomain());
            intf.setFloatingip(ip);
            intf.setPrivateip(ip);
            intf.setAsset(a);
            intf.setAutoCreated(true);
            intf.setActive(true);
            interfaceRepository.save(intf);
            return intf;
        } else {
            return interfaceRepository.findByAssetInAndPrivateip(a.getProject().getAssets(),ip).get();
        }
    }

    private boolean canCreateInterfaceForAsset(Asset asset, String ip) {
        if (asset.getProject().getAssets() != null) {
            Optional<Interface> anInterface = interfaceRepository.findByAssetInAndPrivateip(asset.getProject().getAssets(), ip);
            return !anInterface.isPresent();
        } else
            return true;
    }

    public List<Interface> createInterfacesForModel(Asset asset, RoutingDomain routingDomain, String ips) throws ScanException {
        List<Interface> interfaces = new ArrayList<>();
        for(String ip : ips.trim().split(",")){
            if (IpAddressUtils.validate(ip) ){
                checkAndCreateInterface(asset, interfaces, ip);
            } else if (ip.contains("/")){
                for (String ipFromCidr : IpAddressUtils.getIpAddressesFromCidr(ip)){
                    checkAndCreateInterface(asset, interfaces, ipFromCidr);
                }
            } else if (ip.contains("-")){
                for (String ipFromRange : IpAddressUtils.getIpAddressesFromRange(ip)){
                    checkAndCreateInterface(asset, interfaces, ipFromRange);
                }
            }
        }
        return interfaces;
    }

    private void checkAndCreateInterface(Asset asset, List<Interface> interfaces, String ip) throws ScanException {
        if (canCreateInterfaceForAsset(asset, ip)) {
            Interface inf = new Interface();
            inf.setActive(true);
            inf.setAsset(asset);
            inf.setPrivateip(ip);
            inf.setAutoCreated(false);
            inf.setRoutingDomain(asset.getRoutingDomain());
            interfaces.add(interfaceRepository.saveAndFlush(inf));
        } else {
            Interface interfaceToScan = interfaceRepository.findByAssetInAndPrivateip(asset.getProject().getAssets(),ip).get();
            if (!Objects.equals(interfaceToScan.getRoutingDomain().getId(), asset.getRoutingDomain().getId()) && interfaceToScan.isScanRunning()){
                StringBuilder exceptionText = new StringBuilder();
                exceptionText
                        .append("Trying to change RoutingDomain for asset ")
                        .append(interfaceToScan.getPrivateip())
                        .append(" which is in running state. Scan will not be requested.");
                throw new ScanException(exceptionText.toString());
            }
            interfaceToScan.setRoutingDomain(asset.getRoutingDomain());
            interfaceRepository.save(interfaceToScan);
            interfaces.add(interfaceToScan);
        }
    }

    public boolean isInterfaceAlreadyDefinedForAsset(Asset a, String ips, List<Interface> interfacesDefined){
        try {
            for (String ip : ips.trim().split(",")) {
                if (IpAddressUtils.validate(ip)) {
                    return interfacesDefined.stream().anyMatch(i -> i.getPrivateip().equals(ip));
                } else if (ip.contains("/")) {
                    for (String ipFromCidr : IpAddressUtils.getIpAddressesFromCidr(ip)) {
                        if (interfacesDefined.stream().anyMatch(i -> i.getPrivateip().equals(ipFromCidr))) {
                            return true;
                        }
                    }
                } else if (ip.contains("-")) {
                    for (String ipFromRange : IpAddressUtils.getIpAddressesFromRange(ip)) {
                        if (interfacesDefined.stream().anyMatch(i -> i.getPrivateip().equals(ipFromRange))) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (NullPointerException e){
            log.warn("[Interface Operations] Nullpointer for got during checking if interface is already defined");
            return false;
        }
    }
    /**
     * Double check for already running scan on interface
     *
     * @param intfs
     * @return
     */
    public Boolean verifyInterfacesBeforeScan(List<Interface> intfs) {
        List<InfraScan> manualRunningScans = infraScanRepository.findByIsAutomaticAndRunning(false, true);
        for (InfraScan ns : manualRunningScans) {
            if (org.springframework.util.CollectionUtils.containsAny(intfs, ns.getInterfaces()))
                return true;

        }
        return false;
    }

    public void storeInterfaces(List<Interface> interfaceList){
        interfaceRepository.saveAll(interfaceList);
    }

    @Transactional
    public void setRiskForInterfaces() {
        for (Interface i : interfaceRepository.findByActive(true)){
            int risk = projectRiskAnalyzer.getInterfaceRisk(i);
            i.setRisk(Math.min(risk, 100));
        }
    }
}