package io.mixeway.scanmanager.integrations.nexpose.model;

import java.util.List;

public class ScanTemplateResponseDTO {

    private List<ScanTemplateResource> resources;

    public List<ScanTemplateResource> getResources() {
        return resources;
    }

    public void setResources(List<ScanTemplateResource> resources) {
        this.resources = resources;
    }
}
