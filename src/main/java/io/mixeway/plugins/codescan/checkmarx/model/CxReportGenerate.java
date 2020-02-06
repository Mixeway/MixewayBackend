package io.mixeway.plugins.codescan.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;

public class CxReportGenerate {
    private String reportType;
    private String scanId;

    public CxReportGenerate(CodeProject codeProject){
        this.reportType = Constants.CX_REPORT_TYPE;
        this.scanId = codeProject.getCodeGroup().getScanid();
    }
    public CxReportGenerate(){}

    public String getReportType() {
        return reportType;
    }

    public void setReportType(String reportType) {
        this.reportType = reportType;
    }

    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }
}
