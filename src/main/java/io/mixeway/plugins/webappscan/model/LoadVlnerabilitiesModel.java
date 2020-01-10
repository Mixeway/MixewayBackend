package io.mixeway.plugins.webappscan.model;

import java.util.List;

public class LoadVlnerabilitiesModel {
    List<VulnerabilityModel> vulnerabilities;
    Pagination pagination;

    public List<VulnerabilityModel> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<VulnerabilityModel> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public Pagination getPagination() {
        return pagination;
    }

    public void setPagination(Pagination pagination) {
        this.pagination = pagination;
    }
}
