package io.mixeway.scanmanager.integrations.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class SiteIssues {
    @JsonProperty("aggregated_issue_type_summaries")
    List<Issue> aggregated_issue_type_summaries;
    long timestamp;

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public List<Issue> getAggregated_issue_type_summaries() {
        return aggregated_issue_type_summaries;
    }

    public void setAggregated_issue_type_summaries(List<Issue> aggregated_issue_type_summaries) {
        this.aggregated_issue_type_summaries = aggregated_issue_type_summaries;
    }
}
