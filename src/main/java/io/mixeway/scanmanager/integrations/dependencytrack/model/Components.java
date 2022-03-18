package io.mixeway.scanmanager.integrations.dependencytrack.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class Components {
    private List<Component> components;
}
