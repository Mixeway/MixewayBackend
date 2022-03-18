package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class LoadVlnerabilitiesModel {
    List<VulnerabilityModel> vulnerabilities;
    Pagination pagination;
}
