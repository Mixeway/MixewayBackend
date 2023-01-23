package io.mixeway.api.dashboard.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ProjectStat {
    private String name;
    private int risk;
    private int vulnerabilities;
}
