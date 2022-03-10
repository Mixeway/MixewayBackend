package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProjectCode {
    private String projectName;
    private String projectRepoUrl;
    private int versionId;
    private String params;
    private String technique;
    private String branch;
    private String dTrackUuid;
}
