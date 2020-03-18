package io.mixeway.rest.project.model;

public class OpenSourceConfig {
    boolean openSourceScannerIntegration;
    String openSourceScannerApiUrl;
    String openSourceScannerProjectId;
    String openSourceScannerCredentials;
    String tech;
    String scannerType;

    public String getScannerType() {
        return scannerType;
    }

    public void setScannerType(String scannerType) {
        this.scannerType = scannerType;
    }

    public String getTech() {
        return tech;
    }

    public void setTech(String tech) {
        this.tech = tech;
    }

    public boolean isOpenSourceScannerIntegration() {
        return openSourceScannerIntegration;
    }

    public void setOpenSourceScannerIntegration(boolean openSourceScannerIntegration) {
        this.openSourceScannerIntegration = openSourceScannerIntegration;
    }

    public String getOpenSourceScannerApiUrl() {
        return openSourceScannerApiUrl;
    }

    public void setOpenSourceScannerApiUrl(String openSourceScannerApiUrl) {
        this.openSourceScannerApiUrl = openSourceScannerApiUrl;
    }

    public String getOpenSourceScannerProjectId() {
        return openSourceScannerProjectId;
    }

    public void setOpenSourceScannerProjectId(String openSourceScannerProjectId) {
        this.openSourceScannerProjectId = openSourceScannerProjectId;
    }

    public String getOpenSourceScannerCredentials() {
        return openSourceScannerCredentials;
    }

    public void setOpenSourceScannerCredentials(String openSourceScannerCredentials) {
        this.openSourceScannerCredentials = openSourceScannerCredentials;
    }
}
