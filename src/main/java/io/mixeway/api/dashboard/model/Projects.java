package io.mixeway.api.dashboard.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Projects {
    Long id;
    String name;
    String description;
    int risk;
    String ciid;
    int enableVulnManage;

}
