package io.mixeway.pojo;

import io.mixeway.db.entity.SecurityGateway;

public class VulnManageResponse {
    String vulnerabilityName;
    String severity;
    String dateDiscovered;
    int grade;

    public int getGrade() {
        return grade;
    }

    public void setGrade(int grade) {
        this.grade = grade;
    }

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
