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
    String openSourceScannerProjectId;
    String openSourceScannerCredentials;
    String openSourceScannerApiUrl;

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

    public PrepareCIOperation(OpenSourceConfig openSourceConfig, CodeProject codeProject) {
        this.openSourceScannerCredentials = openSourceConfig.getOpenSourceScannerCredentials();
        this.openSourceScannerApiUrl = openSourceConfig.getOpenSourceScannerApiUrl();
        this.openSourceScannerProjectId = openSourceConfig.getOpenSourceScannerProjectId();
        this.projectId = codeProject.getId();
    }
}
