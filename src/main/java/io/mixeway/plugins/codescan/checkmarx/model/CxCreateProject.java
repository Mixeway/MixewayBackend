package io.mixeway.plugins.codescan.checkmarx.model;

public class CxCreateProject {
    private String name;
    private String owningTeam;
    private boolean isPublic;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getOwningTeam() {
        return owningTeam;
    }

    public void setOwningTeam(String owningTeam) {
        this.owningTeam = owningTeam;
    }

    public boolean isPublic() {
        return isPublic;
    }

    public void setPublic(boolean aPublic) {
        isPublic = aPublic;
    }
}
