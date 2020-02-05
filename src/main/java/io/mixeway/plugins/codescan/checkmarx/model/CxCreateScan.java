package io.mixeway.plugins.codescan.checkmarx.model;

public class CxCreateScan {
    private long projectId;
    private boolean isIncremental;
    private boolean isPublic;
    private boolean forceScan;

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public boolean isIncremental() {
        return isIncremental;
    }

    public void setIncremental(boolean incremental) {
        isIncremental = incremental;
    }

    public boolean isPublic() {
        return isPublic;
    }

    public void setPublic(boolean aPublic) {
        isPublic = aPublic;
    }

    public boolean isForceScan() {
        return forceScan;
    }

    public void setForceScan(boolean forceScan) {
        this.forceScan = forceScan;
    }
}
