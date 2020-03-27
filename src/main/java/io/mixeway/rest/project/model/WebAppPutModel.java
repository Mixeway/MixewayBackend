package io.mixeway.rest.project.model;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

public class WebAppPutModel {
    private String webAppUrl;
    private String webAppHeaders;
    private boolean scanPublic;
    @NotNull
    @Min(1) private Long routingDomainForAsset;

    public Long getRoutingDomainForAsset() {
        return routingDomainForAsset;
    }

    public void setRoutingDomainForAsset(Long routingDomainForAsset) {
        this.routingDomainForAsset = routingDomainForAsset;
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
