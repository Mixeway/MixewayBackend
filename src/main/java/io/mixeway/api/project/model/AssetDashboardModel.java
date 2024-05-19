package io.mixeway.api.project.model;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AssetDashboardModel {
    String assetName;
    String target;
    String branch;
    String created;
    String securityGateway;
    AssetDashboardStatModel vulnerabilities;
    AssetDashboardStatModel solvedIssues;
    AssetDashboardStatModel timeToResolve;
    AssetDashboardStatModel reviewedIssues;
}
