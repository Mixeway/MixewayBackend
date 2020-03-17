package io.mixeway.rest.project.model;

public class OpenSourceConfig {
    boolean openSourceScannerIntegration;
    String openSourceScannerApiUrl;
    String openSourceScannerProjectId;
    String openSourceScannerCredentials;

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
