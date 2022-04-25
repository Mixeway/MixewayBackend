package io.mixeway.scanmanager.integrations.nexpose.model;

import java.util.List;

public class AssetVulnerabilitiesResponseDTO {
    List<AssetVulnerabilitiesResource> resources;
    Page page;

    public Page getPage() {
        return page;
    }

    public void setPage(Page page) {
        this.page = page;
    }

    public List<AssetVulnerabilitiesResource> getResources() {
        return resources;
    }

    public void setResources(List<AssetVulnerabilitiesResource> resources) {
        this.resources = resources;
    }
}
