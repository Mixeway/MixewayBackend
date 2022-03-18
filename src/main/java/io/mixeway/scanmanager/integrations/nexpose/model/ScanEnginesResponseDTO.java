package io.mixeway.scanmanager.integrations.nexpose.model;

import java.util.List;

public class ScanEnginesResponseDTO {
    private List<ScanEngineResource> resources;

    public List<ScanEngineResource> getResources() {
        return resources;
    }

    public void setResources(List<ScanEngineResource> resources) {
        this.resources = resources;
    }

}
