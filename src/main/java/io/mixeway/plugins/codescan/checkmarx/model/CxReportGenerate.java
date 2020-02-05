package io.mixeway.plugins.codescan.checkmarx.model;

public class CxReportGenerate {
    private String reportType;
    private String scanId;

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
