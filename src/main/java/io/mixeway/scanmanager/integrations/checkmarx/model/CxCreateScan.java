package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxCreateScan {
    private long projectId;
    private boolean isIncremental;
    private boolean isPublic;
    private boolean forceScan;
    private String comment;
    public CxCreateScan(){}

    public CxCreateScan(CodeProject codeProject){
        this.projectId = codeProject.getCodeGroup().getVersionIdAll() > 0 ? codeProject.getCodeGroup().getVersionIdAll() : codeProject.getCodeGroup().getRemoteid();
        this.isIncremental = false;
        this.isPublic = true;
        this.forceScan = true;
        this.comment = Constants.CX_SCAN_COMMENT;
    }
}
