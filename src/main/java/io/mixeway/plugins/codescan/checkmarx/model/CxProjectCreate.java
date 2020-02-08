package io.mixeway.plugins.codescan.checkmarx.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mixeway.db.entity.Scanner;

public class CxProjectCreate {
    private String owningTeam;
    private String name;
    @JsonProperty("isPublic")
    private boolean isPublic;

    public CxProjectCreate(String name, Scanner scanner){
        this.name = name;
        this.owningTeam = scanner.getTeam();
        this.isPublic = true;
    }
    public CxProjectCreate(){}

    public String getOwningTeam() {
        return owningTeam;
    }

    public void setOwningTeam(String owningTeam) {
        this.owningTeam = owningTeam;
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
