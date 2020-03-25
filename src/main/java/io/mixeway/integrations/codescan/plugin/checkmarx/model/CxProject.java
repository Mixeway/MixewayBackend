package io.mixeway.integrations.codescan.plugin.checkmarx.model;

import io.mixeway.db.entity.Scanner;

public class CxProject {
    private long id;
    private String teamId;
    private String name;
    private boolean isPublic;

    public CxProject(String name, Scanner scanner){
        this.name = name;
        this.teamId = scanner.getTeam();
        this.isPublic = true;
    }
    public CxProject(){}

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTeamId() {
        return teamId;
    }

    public void setTeamId(String teamId) {
        this.teamId = teamId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isPublic() {
        return isPublic;
    }

    public void setPublic(boolean aPublic) {
        isPublic = aPublic;
    }
}
