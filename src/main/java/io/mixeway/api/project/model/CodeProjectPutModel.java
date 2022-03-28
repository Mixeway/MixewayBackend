package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CodeProjectPutModel {
    private Long codeGroup;
    private String codeProjectName;
    private String projectGiturl;
    private String projectTech;
    private String additionalPath;
    private String branch;
    private String dTrackUuid;

}
