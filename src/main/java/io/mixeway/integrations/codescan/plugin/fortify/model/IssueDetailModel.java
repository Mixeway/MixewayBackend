package io.mixeway.integrations.codescan.plugin.fortify.model;

public class IssueDetailModel {
    String detail;
    String recommendation;
    String scanStatus;
    String fullFileName;
    String references;

    public String getReferences() {
        return references;
    }

    public void setReferences(String references) {
        this.references = references;
    }

    int lineNumber;

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public String getScanStatus() {
        return scanStatus;
    }

    public void setScanStatus(String scanStatus) {
        this.scanStatus = scanStatus;
    }

    public String getFullFileName() {
        return fullFileName;
    }

    public void setFullFileName(String fullFileName) {
        this.fullFileName = fullFileName;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(int lineNumber) {
        this.lineNumber = lineNumber;
    }
}
