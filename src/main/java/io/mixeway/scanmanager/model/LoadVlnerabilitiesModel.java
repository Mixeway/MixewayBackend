package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class LoadVlnerabilitiesModel {
    List<VulnerabilityModel> vulnerabilities;
    Pagination pagination;
}
