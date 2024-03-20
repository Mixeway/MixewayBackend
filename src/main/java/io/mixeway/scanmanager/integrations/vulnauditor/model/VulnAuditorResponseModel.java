package io.mixeway.scanmanager.integrations.vulnauditor.model;

import java.util.List;

/**
 * @author gsiewruk
 */
public class VulnAuditorResponseModel {
    List<VulnAuditorResponse> vulnAuditorResponses;

    public List<VulnAuditorResponse> getVulnAuditorResponses() {
        return vulnAuditorResponses;
    }

    public void setVulnAuditorResponses(List<VulnAuditorResponse> vulnAuditorResponses) {
        this.vulnAuditorResponses = vulnAuditorResponses;
    }
}
