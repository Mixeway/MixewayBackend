package io.mixeway.api.project.model;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DetailStats {
    private int detectedVulnerabilities;
    private int resolvedVulnerabilities;
    private int avgTimeToFix;
    private int resolvedCriticals;

}
