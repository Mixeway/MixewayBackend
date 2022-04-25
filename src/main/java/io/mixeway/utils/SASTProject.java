package io.mixeway.utils;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class SASTProject {
    private long id;
    private String name;

    public SASTProject(long id, String name) {
        this.name = name;
        this.id = id;
    }
}
