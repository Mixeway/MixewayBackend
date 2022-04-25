package io.mixeway.scanmanager.integrations.burpee.model;

/**
 * @author gsiewruk
 */
public class IssueDetail {
    String issue_type_id;
    String name;
    String description;
    String remediation;

    public String getIssue_type_id() {
        return issue_type_id;
    }

    public void setIssue_type_id(String issue_type_id) {
        this.issue_type_id = issue_type_id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRemediation() {
        return remediation;
    }

    public void setRemediation(String remediation) {
        this.remediation = remediation;
    }
}
