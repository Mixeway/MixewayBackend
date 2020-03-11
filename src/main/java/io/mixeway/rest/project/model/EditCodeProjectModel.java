package io.mixeway.rest.project.model;

public class EditCodeProjectModel {
    private String dTrackUuid;
    private int sastProject;
    private String branch;

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
