package io.mixeway.rest.project.model;

public class CodeModel {
    Long id;
    String codeGroup;
    String codeProject;
    Boolean running;

    public Boolean getRunning() {
        return running;
    }

    public void setRunning(Boolean running) {
        this.running = running;
    }

    int risk;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCodeGroup() {
        return codeGroup;
    }

    public void setCodeGroup(String codeGroup) {
        this.codeGroup = codeGroup;
    }

    public String getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(String codeProject) {
        this.codeProject = codeProject;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        this.risk = risk;
    }
}