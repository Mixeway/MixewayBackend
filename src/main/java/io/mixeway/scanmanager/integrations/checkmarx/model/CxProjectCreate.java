package io.mixeway.scanmanager.integrations.checkmarx.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scanner;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
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
    public CxProjectCreate(CodeProject codeProject){
        this.name=codeProject.getName()+"_"+codeProject.getBranch();
    }
    public CxProjectCreate(){}

}
