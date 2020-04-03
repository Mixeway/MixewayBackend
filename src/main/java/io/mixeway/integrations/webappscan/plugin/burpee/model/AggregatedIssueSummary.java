package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class AggregatedIssueSummary {
    List<IssueSummary> aggregated_issue_summaries;

    public List<IssueSummary> getAggregated_issue_summaries() {
        return aggregated_issue_summaries;
    }

    public void setAggregated_issue_summaries(List<IssueSummary> aggregated_issue_summaries) {
        this.aggregated_issue_summaries = aggregated_issue_summaries;
    }
}
