package io.mixeway.pojo;

public class ProjectCode {
    private String projectName;
    private String projectRepoUrl;
    private int versionId;
    private String params;
    private String technique;
    private String branch;

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getTechnique() {
        return technique;
    }

    public void setTechnique(String technique) {
        this.technique = technique;
    }

    public String getParams() {
        return params;
    }

    public void setParams(String params) {
        this.params = params;
    }

    public int getVersionId() {
        return versionId;
    }

    public void setVersionId(int versionId) {
        this.versionId = versionId;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectRepoUrl() {
        return projectRepoUrl;
    }

    public void setProjectRepoUrl(String projectRepoUrl) {
        this.projectRepoUrl = projectRepoUrl;
    }

}
