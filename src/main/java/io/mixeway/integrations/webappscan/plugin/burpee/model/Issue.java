package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

/**
 * @author gsiewruk
 */
public class Issue {
    String type_index;
    String confidence;
    String severity;

    public String getType_index() {
        return type_index;
    }

    public void setType_index(String type_index) {
        this.type_index = type_index;
    }

    public String getConfidence() {
        return confidence;
    }

    public void setConfidence(String confidence) {
        this.confidence = confidence;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }
}
