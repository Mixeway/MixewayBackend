package io.mixeway.integrations.codescan.model;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class CodeScanRequestModel {
    @NotBlank @NotNull String projectName;
    String ciid;
    @NotBlank @NotNull String codeProjectName;
    @NotBlank @NotNull String codeGroupName;
    @NotBlank @NotNull String tech;
    String repoUrl;
    String repoUsername;
    String branch;
    String repoPassword;
    int fortifySSCVersionId;

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getCiid() {
        return ciid;
    }

    public void setCiid(String ciid) {
        this.ciid = ciid;
    }

    public String getCodeProjectName() {
        return codeProjectName;
    }

    public void setCodeProjectName(String codeProjectName) {
        this.codeProjectName = codeProjectName;
    }

    public String getCodeGroupName() {
        return codeGroupName;
    }

    public void setCodeGroupName(String codeGroupName) {
        this.codeGroupName = codeGroupName;
    }

    public String getTech() {
        return tech;
    }

    public void setTech(String tech) {
        this.tech = tech;
    }

    public String getRepoUrl() {
        return repoUrl;
    }

    public void setRepoUrl(String repoUrl) {
        this.repoUrl = repoUrl;
    }

    public String getRepoUsername() {
        return repoUsername;
    }

    public void setRepoUsername(String repoUsername) {
        this.repoUsername = repoUsername;
    }

    public String getRepoPassword() {
        return repoPassword;
    }

    public void setRepoPassword(String repoPassword) {
        this.repoPassword = repoPassword;
    }

    public int getFortifySSCVersionId() {
        return fortifySSCVersionId;
    }

    public void setFortifySSCVersionId(int fortifySSCVersionId) {
        this.fortifySSCVersionId = fortifySSCVersionId;
    }
}
