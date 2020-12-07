/*
 * @created  2020-12-07 : 12:34
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.utils;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.rest.project.model.AssetPutModel;

import java.util.ArrayList;
import java.util.List;

public class InterfaceOperations {

    public static List<Interface> createInterfacesForModel(Asset asset, RoutingDomain routingDomain, String ips) {
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

    private static void checkAndCreateInterface(Asset asset, List<Interface> interfaces, String ip) {
        if (!isInterfaceAlreadyDefinedForAsset(asset, ip)) {
            Interface inf = new Interface();
            inf.setActive(true);
            inf.setAsset(asset);
            inf.setPrivateip(ip);
            inf.setAutoCreated(false);
            inf.setRoutingDomain(asset.getRoutingDomain());
            interfaces.add(inf);
        } else {
            interfaces.add(asset.getInterfaces().stream().filter(i -> i.getPrivateip().equals(ip)).findFirst().orElse(null));
        }
    }

    public static boolean isInterfaceAlreadyDefinedForAsset(Asset a, String ips){
        for(String ip : ips.trim().split(",")){
            if (IpAddressUtils.validate(ip)){
                return a.getInterfaces().stream().anyMatch(i -> i.getPrivateip().equals(ip));
            } else if (ip.contains("/")){
                for (String ipFromCidr : IpAddressUtils.getIpAddressesFromCidr(ip)){
                    if (a.getInterfaces().stream().anyMatch(i -> i.getPrivateip().equals(ipFromCidr))){
                        return true;
                    }
                }
            } else if (ip.contains("-")){
                for (String ipFromRange : IpAddressUtils.getIpAddressesFromRange(ip)){
                    if (a.getInterfaces().stream().anyMatch(i -> i.getPrivateip().equals(ipFromRange))){
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
