package io.mixeway.utils;

import lombok.Getter;

@Getter
public class ProjectAudit {
    private long createdVulnerabilities;
    private long resolvedVulnerabilities;
    private double averageTimeToResolve;

    public ProjectAudit(long createdVulnerabilities, long resolvedVulnerabilities, double averageTimeToResolve) {
        this.createdVulnerabilities = createdVulnerabilities;
        this.resolvedVulnerabilities = resolvedVulnerabilities;
        this.averageTimeToResolve = averageTimeToResolve;
    }
}
