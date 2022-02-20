package io.mixeway.rest.vulnmanage.model;

import lombok.Builder;

/**
 * @author gsiewruk
 */
@Builder
public class SecurityScans {
    private String project;
    private String scanType;
    private String scope;

    public String getProject() {
        return project;
    }

    public void setProject(String project) {
        this.project = project;
    }

    public String getScanType() {
        return scanType;
    }

    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
