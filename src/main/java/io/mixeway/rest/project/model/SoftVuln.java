package io.mixeway.rest.project.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.SoftwarePacketVulnerability;

import java.io.Serializable;

public class SoftVuln implements Serializable {
    CodeProject codeProject;
    SoftwarePacketVulnerability softwarePacketVulnerability;

    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }

    public SoftwarePacketVulnerability getSoftwarePacketVulnerability() {
        return softwarePacketVulnerability;
    }

    public void setSoftwarePacketVulnerability(SoftwarePacketVulnerability softwarePacketVulnerability) {
        this.softwarePacketVulnerability = softwarePacketVulnerability;
    }
}
