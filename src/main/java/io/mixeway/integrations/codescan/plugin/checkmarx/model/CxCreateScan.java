package io.mixeway.integrations.codescan.plugin.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;

public class CxCreateScan {
    private long projectId;
    private boolean isIncremental;
    private boolean isPublic;
    private boolean forceScan;
    private String comment;
    public CxCreateScan(){}

    public CxCreateScan(CodeProject codeProject){
        this.projectId = codeProject.getCodeGroup().getVersionIdAll();
        this.isIncremental = false;
        this.isPublic = true;
        this.forceScan = true;
        this.comment = Constants.CX_SCAN_COMMENT;
    }

    public long getProjectId() {
        return projectId;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
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
