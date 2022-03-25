package io.mixeway.api.cioperations.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VulnManageResponse {
    String vulnerabilityName;
    String severity;
    String dateDiscovered;
    int grade;

}
