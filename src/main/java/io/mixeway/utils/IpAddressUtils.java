package io.mixeway.utils;

import org.apache.commons.net.util.SubnetUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class IpAddressUtils {
    private static final Pattern PATTERN = Pattern.compile(
            "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
    public static boolean validate(final String ip) {
        return PATTERN.matcher(ip).matches();
    }
    public static boolean isValidSubnetFormat(String subnet) {
        try {
            SubnetUtils subnetUtils = new SubnetUtils(subnet);
            subnetUtils.getInfo();
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    private boolean checkIp(String apiip) {
        boolean result =false;
        String[] ips = apiip.split(",");
        for(String ip : ips) {
            if (validate(apiip))
                result=true;
        }

        return result;
    }
    public static List<String> getIpAddressesFromRange(String range){
        List<String> ipAddressesFromRange = new ArrayList<>();
        if (validate(range.split("-")[0]) && validate(range.split("-")[1])){
            String[] startParts = range.split("-")[0].split("(?<=\\.)(?!.*\\.)");
            String[] endParts = range.split("-")[1].split("(?<=\\.)(?!.*\\.)");

            int first = Integer.parseInt(startParts[1]);
            int last = Integer.parseInt(endParts[1]);

            for (int i = first; i <= last; i++) {
                if ( validate(startParts[0] + i)){
                    ipAddressesFromRange.add(startParts[0] + i);
                }
            }
        }
        return ipAddressesFromRange;
    }
    public static List<String> getIpAddressesFromCidr(String cidr){
        SubnetUtils utils = new SubnetUtils(cidr);
        String[] allIps = utils.getInfo().getAllAddresses();
        List<String> ipAddressesFromRange = new ArrayList<>();
        for (String ip: allIps){
            if (validate(ip)){
                ipAddressesFromRange.add(ip);
            }
        }
        return ipAddressesFromRange;
    }
}
