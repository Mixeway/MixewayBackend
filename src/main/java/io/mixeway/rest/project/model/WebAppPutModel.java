package io.mixeway.rest.project.model;

public class WebAppPutModel {
    private String webAppUrl;
    private String webAppHeaders;
    private boolean scanPublic;

    public boolean isScanPublic() {
        return scanPublic;
    }

    public void setScanPublic(boolean scanPublic) {
        this.scanPublic = scanPublic;
    }

    public String getWebAppUrl() {
        return webAppUrl;
    }

    public void setWebAppUrl(String webAppUrl) {
        this.webAppUrl = webAppUrl;
    }

    public String getWebAppHeaders() {
        return webAppHeaders;
    }

    public void setWebAppHeaders(String webAppHeaders) {
        this.webAppHeaders = webAppHeaders;
    }
}
