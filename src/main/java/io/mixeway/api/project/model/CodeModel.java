package io.mixeway.api.project.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class CodeModel {
    private Long id;
    private String codeProject;
    private Boolean running;
    private String dTrackUuid;
    private String branch;
    private int versionId;
    private int risk;
    private String repoUrl;
    private String repoUsername;
    private String repoPassword;

}
