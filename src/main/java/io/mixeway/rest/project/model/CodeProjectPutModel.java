package io.mixeway.rest.project.model;

public class CodeProjectPutModel {
    private Long codeGroup;
    private String codeProjectName;
    private String projectGiturl;
    private String projectTech;
    private String additionalPath;
    private String branch;

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public Long getCodeGroup() {
        return codeGroup;
    }

    public void setCodeGroup(Long codeGroup) {
        this.codeGroup = codeGroup;
    }

    public String getCodeProjectName() {
        return codeProjectName;
    }

    public void setCodeProjectName(String codeProjectName) {
        this.codeProjectName = codeProjectName;
    }

    public String getProjectGiturl() {
        return projectGiturl;
    }

    public void setProjectGiturl(String projectGiturl) {
        this.projectGiturl = projectGiturl;
    }

    public String getProjectTech() {
        return projectTech;
    }

    public void setProjectTech(String projectTech) {
        this.projectTech = projectTech;
    }

    public String getAdditionalPath() {
        return additionalPath;
    }

    public void setAdditionalPath(String additionalPath) {
        this.additionalPath = additionalPath;
    }
}
