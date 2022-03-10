package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CreateFortifyScanRequest {
    private String repoUrl;
    private String groupName;
    private List<ProjectCode> projects;
    private String cloudCtrlToken;
    private String username;
    private String password;
    private int versionId;
    private Boolean single;
    private String dTrackUuid;
    private String sscUrl;
    private String dTrackUrl;
    private String dTrackToken;

}
