package io.mixeway.api.dashboard.model;

import lombok.*;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class DashboardStat {
    private int critical;
    private int medium;
    private int low;
    private List<ProjectStat> projectStats;
    private List<VulnStat> vulnStats;

}
