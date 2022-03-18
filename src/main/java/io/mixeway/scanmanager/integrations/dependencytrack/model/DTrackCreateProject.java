package io.mixeway.scanmanager.integrations.dependencytrack.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DTrackCreateProject {
    private String name;
    private String version;
    private boolean active;

    public DTrackCreateProject(String name){
        this.name = name;
        this.version = "Default";
        this.active = true;
    }
}
