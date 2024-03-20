package io.mixeway.scanmanager.integrations.vulnauditor.model;

import java.util.List;

/**
 * @author gsiewruk
 */
public class VulnAuditorRequestModel {
    List<VulnAuditorRequest> vulnAuditorRequests;

    public VulnAuditorRequestModel(){}
    public VulnAuditorRequestModel(List<VulnAuditorRequest> vulnAuditorRequests){
        this.vulnAuditorRequests = vulnAuditorRequests;
    }

    public List<VulnAuditorRequest> getVulnAuditorRequests() {
        return vulnAuditorRequests;
    }

    public void setVulnAuditorRequests(List<VulnAuditorRequest> vulnAuditorRequests) {
        this.vulnAuditorRequests = vulnAuditorRequests;
    }
}
