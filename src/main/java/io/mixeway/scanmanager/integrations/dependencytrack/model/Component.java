package io.mixeway.scanmanager.integrations.dependencytrack.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Component {
    private String group;
    private String name;
    private String version;
    private String description;
}
