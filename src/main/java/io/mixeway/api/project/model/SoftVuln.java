package io.mixeway.api.project.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.ProjectVulnerability;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class SoftVuln implements Serializable {
    private CodeProject codeProject;
    private ProjectVulnerability softwarePacketVulnerability;

}
