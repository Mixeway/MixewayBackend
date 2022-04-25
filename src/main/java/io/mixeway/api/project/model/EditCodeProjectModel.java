package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EditCodeProjectModel {
    private String dTrackUuid;
    private int sastProject;
    private String branch;
    private String repoUrl;
    private String repoUsername;
    private String repoPassword;
}
