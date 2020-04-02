package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class GetIssueDetails {
    List<IssueDetail> definitions;

    public List<IssueDetail> getDefinitions() {
        return definitions;
    }

    public void setDefinitions(List<IssueDetail> definitions) {
        this.definitions = definitions;
    }
}
