package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.db.entity.Scanner;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
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
}
