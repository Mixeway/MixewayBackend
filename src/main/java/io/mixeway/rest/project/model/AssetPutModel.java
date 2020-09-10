package io.mixeway.rest.project.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AssetPutModel {
    @NotEmpty private String assetName;
    @NotEmpty
    private String ipAddresses;
    @NotNull
    @Min(1) private Long routingDomainForAsset;

    public String getAssetName() {
        return assetName;
    }

    public void setAssetName(String assetName) {
        this.assetName = assetName;
    }

    public String getIpAddresses() {
        return ipAddresses;
    }

    public void setIpAddresses(String ipAddresses) {
        this.ipAddresses = ipAddresses;
    }

    public Long getRoutingDomainForAsset() {
        return routingDomainForAsset;
    }

    public void setRoutingDomainForAsset(Long routingDomainForAsset) {
        this.routingDomainForAsset = routingDomainForAsset;
    }
}
