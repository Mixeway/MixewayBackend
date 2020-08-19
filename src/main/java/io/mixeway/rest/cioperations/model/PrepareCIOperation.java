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
    String dTrackUuid;
    String dTrackApiKey;
    String dTrackUrl;

    public Long getProjectId() {
        return projectId;
    }

    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public String getdTrackUuid() {
        return dTrackUuid;
    }

    public void setdTrackUuid(String dTrackUuid) {
        this.dTrackUuid = dTrackUuid;
    }

    public String getdTrackApiKey() {
        return dTrackApiKey;
    }

    public void setdTrackApiKey(String dTrackApiKey) {
        this.dTrackApiKey = dTrackApiKey;
    }

    public String getdTrackUrl() {
        return dTrackUrl;
    }

    public void setdTrackUrl(String dTrackUrl) {
        this.dTrackUrl = dTrackUrl;
    }

    public PrepareCIOperation(OpenSourceConfig openSourceConfig, CodeProject codeProject) {
        this.dTrackApiKey = openSourceConfig.getOpenSourceScannerCredentials();
        this.dTrackUrl = openSourceConfig.getOpenSourceScannerApiUrl();
        this.dTrackUuid = openSourceConfig.getOpenSourceScannerProjectId();
        this.projectId = codeProject.getId();
    }
}
