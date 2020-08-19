package io.mixeway.rest.project.model;

public class EditCodeProjectModel {
    private String dTrackUuid;
    private int sastProject;
    private String branch;
    private String repoUrl;
    private String repoUsername;
    private String repoPassword;

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

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public int getSastProject() {
        return sastProject;
    }

    public void setSastProject(int sastProject) {
        this.sastProject = sastProject;
    }

    public String getdTrackUuid() {
        return dTrackUuid;
    }

    public void setdTrackUuid(String dTrackUuid) {
        this.dTrackUuid = dTrackUuid;
    }
}
