/*
 * @created  2020-08-19 : 21:03
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.cioperations.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.rest.project.model.OpenSourceConfig;

public class PrepareCIOperation {
    Long projectId;
    Long codeProjectId;
    String openSourceScannerProjectId;
    String openSourceScannerCredentials;
    String openSourceScannerApiUrl;
    boolean openSourceScannerIntegration;
    String scannerType;

    public Long getCodeProjectId() {
        return codeProjectId;
    }

    public void setCodeProjectId(Long codeProjectId) {
        this.codeProjectId = codeProjectId;
    }

    public String getScannerType() {
        return scannerType;
    }

    public void setScannerType(String scannerType) {
        this.scannerType = scannerType;
    }

    public boolean isOpenSourceScannerIntegration() {
        return openSourceScannerIntegration;
    }

    public void setOpenSourceScannerIntegration(boolean openSourceScannerIntegration) {
        this.openSourceScannerIntegration = openSourceScannerIntegration;
    }

    public Long getProjectId() {
        return projectId;
    }

    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public String getOpenSourceScannerProjectId() {
        return openSourceScannerProjectId;
    }

    public void setOpenSourceScannerProjectId(String openSourceScannerProjectId) {
        this.openSourceScannerProjectId = openSourceScannerProjectId;
    }

    public String getOpenSourceScannerCredentials() {
        return openSourceScannerCredentials;
    }

    public void setOpenSourceScannerCredentials(String openSourceScannerCredentials) {
        this.openSourceScannerCredentials = openSourceScannerCredentials;
    }

    public String getOpenSourceScannerApiUrl() {
        return openSourceScannerApiUrl;
    }

    public void setOpenSourceScannerApiUrl(String openSourceScannerApiUrl) {
        this.openSourceScannerApiUrl = openSourceScannerApiUrl;
    }

    public PrepareCIOperation(OpenSourceConfig openSourceConfig, CodeProject codeProject, String type) {
        this.openSourceScannerCredentials = openSourceConfig.getOpenSourceScannerCredentials();
        this.openSourceScannerApiUrl = openSourceConfig.getOpenSourceScannerApiUrl();
        this.openSourceScannerProjectId = openSourceConfig.getOpenSourceScannerProjectId();
        if (this.openSourceScannerApiUrl !=null && this.openSourceScannerCredentials!=null){
            this.openSourceScannerIntegration = true;
        } else {
            this.openSourceScannerIntegration = false;
        }
        this.scannerType = type;
        this.projectId = codeProject.getCodeGroup().getProject().getId();
        this.codeProjectId = codeProject.getId();
    }
}
