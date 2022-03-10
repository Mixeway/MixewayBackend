package io.mixeway.scanmanager.integrations.burpee.model;

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
