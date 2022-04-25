package io.mixeway.scanmanager.integrations.dependencytrack.model;

import lombok.Getter;
import lombok.Setter;

import java.sql.Timestamp;
import java.util.List;

@Getter
@Setter
public class DTrackVuln {
    private String vulnId;
    private String source;
    private String description;
    private Timestamp published;
    private String recommendation;
    private String references;
    private String Severity;
    private List<Component> components;
}
