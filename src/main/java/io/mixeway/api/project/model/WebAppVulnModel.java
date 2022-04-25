package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WebAppVulnModel {
    private String description;
    private String location;
    private String vulnName;
    private String severity;
    private String detected;
    private String status;
}
