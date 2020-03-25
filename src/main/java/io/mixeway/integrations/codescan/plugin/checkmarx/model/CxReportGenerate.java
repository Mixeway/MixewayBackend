package io.mixeway.integrations.codescan.plugin.checkmarx.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeGroup;

public class CxReportGenerate {
    private String reportType;
    private String scanId;

    public CxReportGenerate(CodeGroup codeGroup){
        this.reportType = Constants.CX_REPORT_TYPE;
        this.scanId = codeGroup.getScanid();
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
