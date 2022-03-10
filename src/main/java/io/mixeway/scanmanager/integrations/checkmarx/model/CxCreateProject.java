package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxCreateProject {
    private String name;
    private String owningTeam;
    private boolean isPublic;
}
