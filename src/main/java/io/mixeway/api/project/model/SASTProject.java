package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SASTProject {
    private long id;
    private String name;

    public SASTProject(long id, String name){
        this.name = name;
        this.id = id;
    }
}
