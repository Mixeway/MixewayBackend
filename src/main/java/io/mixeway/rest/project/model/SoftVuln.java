package io.mixeway.rest.project.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.ProjectVulnerability;

import java.io.Serializable;

public class SoftVuln implements Serializable {
    CodeProject codeProject;
    ProjectVulnerability softwarePacketVulnerability;

    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }

    public ProjectVulnerability getSoftwarePacketVulnerability() {
        return softwarePacketVulnerability;
    }

    public void setSoftwarePacketVulnerability(ProjectVulnerability softwarePacketVulnerability) {
        this.softwarePacketVulnerability = softwarePacketVulnerability;
    }
}
