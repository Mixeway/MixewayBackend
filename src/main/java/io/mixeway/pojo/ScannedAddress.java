package io.mixeway.pojo;

import java.util.List;

public class ScannedAddress {
    String ip;
    String os;
    List<NetworkService> networkServices;

    public List<NetworkService> getNetworkServices() {
        return networkServices;
    }

    public void setNetworkServices(List<NetworkService> networkServices) {
        this.networkServices = networkServices;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }
}
