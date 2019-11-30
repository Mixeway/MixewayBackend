package io.mixeway.pojo;

public class VulnManageResponse {
    String vulnerabilityName;
    String severity;
    String dateDiscovered;

    public String getVulnerabilityName() {
        return vulnerabilityName;
    }

    public void setVulnerabilityName(String vulnerabilityName) {
        this.vulnerabilityName = vulnerabilityName;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDateDiscovered() {
        return dateDiscovered;
    }

    public void setDateDiscovered(String dateDiscovered) {
        this.dateDiscovered = dateDiscovered;
    }
}
