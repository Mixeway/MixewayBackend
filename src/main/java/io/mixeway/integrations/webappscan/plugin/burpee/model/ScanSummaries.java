package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class ScanSummaries {
    @JsonProperty("rows")
    List<Scan> scanList;

    public List<Scan> getScanList() {
        return scanList;
    }

    public void setScanList(List<Scan> scanList) {
        this.scanList = scanList;
    }
}
