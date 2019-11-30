package io.mixeway.rest.project.model;

public class AssetModel {
    Long assetId;
    String hostname;
    String ipAddress;
    String routingDomain;
    int risk;
    boolean running;

    public boolean isRunning() {
        return running;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public Long getAssetId() {
        return assetId;
    }

    public void setAssetId(Long assetId) {
        this.assetId = assetId;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getRoutingDomain() {
        return routingDomain;
    }

    public void setRoutingDomain(String routingDomain) {
        this.routingDomain = routingDomain;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        this.risk = risk;
    }
}
