package io.mixeway.scanmanager.integrations.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

import java.util.List;

/**
 * @author gsiewruk
 */
public class ScanSummaries {
    @JsonProperty("rows")
    List<Scan> rows;

    public List<Scan> getRows() {
        return rows;
    }

    public void setRows(List<Scan> rows) {
        this.rows = rows;
    }
}
