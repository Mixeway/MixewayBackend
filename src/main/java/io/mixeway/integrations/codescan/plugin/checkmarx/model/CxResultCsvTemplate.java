/*
 * @created  2020-11-05 : 20:15
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.codescan.plugin.checkmarx.model;

import com.univocity.parsers.annotations.Parsed;
import com.univocity.parsers.annotations.Trim;

public class CxResultCsvTemplate {
    @Trim
    @Parsed(field = "Query")
    private String query;

    @Parsed(field = "DestFileName")
    private String dstLocation;

    @Parsed(field = "DestLine")
    private String dstLine;

    @Parsed(field = "Result State")
    private String analysis;

    @Parsed(field = "Result Severity")
    private String severity;

    @Parsed(field = "Link")
    private String description;

    @Parsed(field = "Result Status")
    private String state;

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public String getDstLocation() {
        return dstLocation;
    }

    public void setDstLocation(String dstLocation) {
        this.dstLocation = dstLocation;
    }

    public String getDstLine() {
        return dstLine;
    }

    public void setDstLine(String dstLine) {
        this.dstLine = dstLine;
    }

    public String getAnalysis() {
        return analysis;
    }

    public void setAnalysis(String analysis) {
        this.analysis = analysis;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}
