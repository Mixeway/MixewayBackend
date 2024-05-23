package io.mixeway.api.cicd.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ProjectMetadata {
    private long codeProjectId;
    private long webAppId;
    private String projectName;
    private String target;
    private String branch;
    private String commitId;
    private String scanType;
}
