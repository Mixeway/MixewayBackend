package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FortifyVulnList {
    private List<FortifyVuln> data;
    private FortifyLinks links;
}
