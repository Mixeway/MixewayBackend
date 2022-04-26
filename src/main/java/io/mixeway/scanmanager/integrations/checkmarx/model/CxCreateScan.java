package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class CxCreateScan {
    private long projectId;
    private boolean isIncremental;
    private boolean isPublic;
    private boolean forceScan;
    private String comment;
    public CxCreateScan(){}

    public CxCreateScan(CodeProject codeProject){
        this.projectId = codeProject.getVersionIdAll() > 0 ? codeProject.getVersionIdAll() : codeProject.getRemoteid();
        this.isIncremental = false;
        this.isPublic = true;
        this.forceScan = true;
        this.comment = Constants.CX_SCAN_COMMENT;
    }
}
