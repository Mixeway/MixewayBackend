package io.mixeway.api.cioperations.model;

import io.mixeway.utils.VulnerabilityModel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * @author gsiewruk
 */
@Getter
@Setter
@NoArgsConstructor
public class LoadVulnModel {
    String branch;
    String commitId;
    String projectName;
    List<VulnerabilityModel> vulns;
}
