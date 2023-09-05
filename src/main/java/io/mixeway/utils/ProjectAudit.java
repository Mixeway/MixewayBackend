package io.mixeway.utils;

import lombok.Getter;

@Getter
public class ProjectAudit {
    private long createdVulnerabilities;
    private long resolvedVulnerabilities;
    private double averageTimeToResolve;
    private String percentCriticalsSolved;

    public ProjectAudit(long createdVulnerabilities, long resolvedVulnerabilities, double averageTimeToResolve, String criticalSovled) {
        this.createdVulnerabilities = createdVulnerabilities;
        this.resolvedVulnerabilities = resolvedVulnerabilities;
        this.averageTimeToResolve = averageTimeToResolve;
        this.percentCriticalsSolved = criticalSovled;
    }
}
