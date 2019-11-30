package io.mixeway.rest.project.model;

public class WebAppModel {
    Long webAppId;
    String url;
    boolean publicScan;
    int risk;
    boolean running;

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
