package io.mixeway.rest.project.model;

import org.apache.commons.lang3.StringUtils;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

public class WebAppPutModel {
    private String webAppUrl;
    private String webAppHeaders;
    private boolean scanPublic;
    private String webAppUsername;
    private String webAppPassword;
    private String appClient;

    public String getAppClient() {
        return appClient;
    }

    public void setAppClient(String appClient) {
        this.appClient = appClient;
    }

    @NotNull
    @Min(1) private Long routingDomainForAsset;

    public Long getRoutingDomainForAsset() {
        return routingDomainForAsset;
    }

    public void setRoutingDomainForAsset(Long routingDomainForAsset) {
        this.routingDomainForAsset = routingDomainForAsset;
    }

    public String getWebAppUsername() {
        return webAppUsername;
    }
    public boolean isPasswordAuthSet(){
        return StringUtils.isNotBlank(webAppPassword) && StringUtils.isNotBlank(webAppUsername);
    }

    public void setWebAppUsername(String webAppUsername) {
        this.webAppUsername = webAppUsername;
    }

    public String getWebAppPassword() {
        return webAppPassword;
    }

    public void setWebAppPassword(String webAppPassword) {
        this.webAppPassword = webAppPassword;
    }

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
