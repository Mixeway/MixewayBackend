package io.mixeway.integrations.opensourcescan.plugins.dependencytrack.model;

public class DTrackCreateProject {
    private String name;
    private String version;
    private boolean active;

    public DTrackCreateProject(String name){
        this.name = name;
        this.version = "Default";
        this.active = true;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
