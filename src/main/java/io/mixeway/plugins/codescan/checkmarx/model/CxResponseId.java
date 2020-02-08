package io.mixeway.plugins.codescan.checkmarx.model;

public class CxResponseId {
    private long id;
    private long reportId;

    public long getReportId() {
        return reportId;
    }

    public void setReportId(long reportId) {
        this.reportId = reportId;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }
}
