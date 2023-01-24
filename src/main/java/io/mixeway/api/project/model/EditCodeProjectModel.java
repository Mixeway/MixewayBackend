package io.mixeway.api.project.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class EditCodeProjectModel {
    private String remoteId;
    private String remoteName;
    private int sastProject;
    private String branch;
    private String repoUrl;
    private String repoUsername;
    private String repoPassword;
}
