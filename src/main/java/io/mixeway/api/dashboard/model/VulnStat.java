package io.mixeway.api.dashboard.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class VulnStat {
    private String name;
    private int occurances;
}
