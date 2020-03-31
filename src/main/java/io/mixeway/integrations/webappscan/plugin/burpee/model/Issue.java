package io.mixeway.integrations.webappscan.plugin.burpee.model;

import org.codehaus.jackson.annotate.JsonProperty;

/**
 * @author gsiewruk
 */
public class Issue {
    @JsonProperty("type_index")
    String typeIndex;
    String confidence;
    String severity;
}
