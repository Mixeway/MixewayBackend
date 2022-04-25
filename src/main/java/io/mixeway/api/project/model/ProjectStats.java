package io.mixeway.api.project.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * @author gsiewruk
 */
@Builder
@Getter
@Setter
public class ProjectStats {
    private int assets;
    private int webApps;
    private int repos;
    private Long libs;
    private Long vulnCrit;
    private Long vulnMedium;
    private Long vulnLow;

}
