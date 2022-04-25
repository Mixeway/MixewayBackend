package io.mixeway.scanmanager.integrations.nexpose.model;

import java.util.List;

public class SiteAssetsDTO {
    private List<SiteAssetsResources> resources;
    private Page page;

    public List<SiteAssetsResources> getResources() {
        return resources;
    }

    public void setResources(List<SiteAssetsResources> resources) {
        this.resources = resources;
    }

    public Page getPage() {
        return page;
    }

    public void setPage(Page page) {
        this.page = page;
    }
}
