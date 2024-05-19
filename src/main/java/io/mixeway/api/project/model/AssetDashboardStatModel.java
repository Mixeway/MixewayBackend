package io.mixeway.api.project.model;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssetDashboardStatModel {
    int crit;
    int critPercent;
    int high;
    int highPercent;
    int medium;
    int mediumPercent;
    int low;
    int lowPercent;
    int total;
}
