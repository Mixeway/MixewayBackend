package io.mixeway.scanmanager.integrations.burpee.model;

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
