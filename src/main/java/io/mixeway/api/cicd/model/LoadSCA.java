package io.mixeway.api.cicd.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoadSCA {
    private Long codeProjectId;
    private String branch;
    private String commitId;
}
