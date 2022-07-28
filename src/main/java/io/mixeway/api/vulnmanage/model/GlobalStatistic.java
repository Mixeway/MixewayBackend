package io.mixeway.api.vulnmanage.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class GlobalStatistic {
    private String project;
    private long scaVulns;
    private long codeVulns;
}
