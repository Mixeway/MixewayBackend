package io.mixeway.plugins.codescan.checkmarx.model;

public class CxResult {
    private String query, dstLocation, dstLine, analysis, severity, description, state;

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public String getDstLocation() {
        return dstLocation;
    }

    public void setDstLocation(String dstLocation) {
        this.dstLocation = dstLocation;
    }

    public String getDstLine() {
        return dstLine;
    }

    public void setDstLine(String dstLine) {
        this.dstLine = dstLine;
    }

    public String getAnalysis() {
        return analysis;
    }

    public void setAnalysis(String analysis) {
        this.analysis = analysis;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}
