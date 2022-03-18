package io.mixeway.domain.service.intf;


import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.utils.IpAddressUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class InterfaceOperations {
    private final InterfaceRepository interfaceRepository;


    public void createInterfaceForAsset(Asset asset, String ip) {
        if (canCreateInterfaceForAsset(asset, ip)) {
            Interface intf = new Interface();
            intf.setAsset(asset);
            intf.setActive(true);
            intf.setPrivateip(ip);
            interfaceRepository.save(intf);
        }
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

    public List<Interface> createInterfacesForModel(Asset asset, RoutingDomain routingDomain, String ips) {
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

    private void checkAndCreateInterface(Asset asset, List<Interface> interfaces, String ip) {
        if (canCreateInterfaceForAsset(asset, ip)) {
            Interface inf = new Interface();
            inf.setActive(true);
            inf.setAsset(asset);
            inf.setPrivateip(ip);
            inf.setAutoCreated(false);
            inf.setRoutingDomain(asset.getRoutingDomain());
            interfaces.add(inf);
        } else {
            interfaces.add(interfaceRepository.findByAssetInAndPrivateip(asset.getProject().getAssets(),ip).get());
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
}