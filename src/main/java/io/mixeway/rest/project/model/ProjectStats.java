package io.mixeway.rest.project.model;

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
    int assets;
    int webApps;
    int repos;
    Long libs;
    Long vulnCrit;
    Long vulnMedium;
    Long vulnLow;

}
