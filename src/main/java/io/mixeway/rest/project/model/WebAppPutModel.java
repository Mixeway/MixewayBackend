package io.mixeway.rest.project.model;

public class WebAppPutModel {
    private String webAppUrl;
    private String webAppHeaders;
    private boolean isPublic;

    public boolean isPublic() {
        return isPublic;
    }

    public void setPublic(boolean aPublic) {
        isPublic = aPublic;
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
