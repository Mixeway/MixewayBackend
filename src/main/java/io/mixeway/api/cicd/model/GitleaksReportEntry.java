package io.mixeway.api.cicd.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class GitleaksReportEntry {
    @JsonProperty("Description")
    String description;
    @JsonProperty("StartLine")
    int startLine;
    @JsonProperty("File")
    String file;
    @JsonProperty("Fingerprint")
    String fingerprint;
    @JsonProperty("Commit")
    String commit;
    @JsonProperty("Author")
    String author;
    @JsonProperty("RuleID")
    String ruleId;
}
