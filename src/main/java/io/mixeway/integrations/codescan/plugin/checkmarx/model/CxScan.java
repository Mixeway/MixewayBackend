package io.mixeway.integrations.codescan.plugin.checkmarx.model;

public class CxScan {
    private long id;
    private CxProject project;
    private CxStatus status;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public CxProject getProject() {
        return project;
    }

    public void setProject(CxProject project) {
        this.project = project;
    }

    public CxStatus getStatus() {
        return status;
    }

    public void setStatus(CxStatus status) {
        this.status = status;
    }
}
