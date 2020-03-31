package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class GetIssueDetails {
    @JsonProperty("definitions")
    List<IssueDetail> issueDetails;

    public List<IssueDetail> getIssueDetails() {
        return issueDetails;
    }

    public void setIssueDetails(List<IssueDetail> issueDetails) {
        this.issueDetails = issueDetails;
    }
}
