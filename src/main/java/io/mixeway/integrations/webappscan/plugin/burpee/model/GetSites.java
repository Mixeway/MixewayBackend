package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class GetSites {
    List<Site> trees;

    public List<Site> getTrees() {
        return trees;
    }

    public void setTrees(List<Site> trees) {
        this.trees = trees;
    }
}
