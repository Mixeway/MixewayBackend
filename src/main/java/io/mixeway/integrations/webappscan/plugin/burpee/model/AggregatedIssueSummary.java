package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class AggregatedIssueSummary {
    @JsonProperty("aggregated_issue_summaries")
    List<IssueSummary> issueSummaries;

    public List<IssueSummary> getIssueSummaries() {
        return issueSummaries;
    }

    public void setIssueSummaries(List<IssueSummary> issueSummaries) {
        this.issueSummaries = issueSummaries;
    }
}
