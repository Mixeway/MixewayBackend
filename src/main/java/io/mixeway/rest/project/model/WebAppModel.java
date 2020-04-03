package io.mixeway.rest.project.model;

import io.mixeway.db.entity.RoutingDomain;

public class WebAppModel {
    Long webAppId;
    String url;
    boolean publicScan;
    RoutingDomain routingDomain;
    int risk;
    boolean running;
    boolean inQueue;

    public RoutingDomain getRoutingDomain() {
        return routingDomain;
    }

    public void setRoutingDomain(RoutingDomain routingDomain) {
        this.routingDomain = routingDomain;
    }

    public boolean isInQueue() {
        return inQueue;
    }

    public void setInQueue(boolean inQueue) {
        this.inQueue = inQueue;
    }

    public boolean isRunning() {
        return running;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public Long getWebAppId() {
        return webAppId;
    }

    public void setWebAppId(Long webAppId) {
        this.webAppId = webAppId;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isPublicScan() {
        return publicScan;
    }

    public void setPublicScan(boolean publicScan) {
        this.publicScan = publicScan;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        this.risk = risk;
    }
}
