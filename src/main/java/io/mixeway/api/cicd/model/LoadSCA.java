package io.mixeway.api.cicd.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class LoadSCA {
    private Long codeProjectId;
    private String branch;
    private String commitId;
}
