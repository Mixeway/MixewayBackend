package io.mixeway.api.dashboard.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VulnResponse {
    private String name;
    private Long projectId;
    private String location;
    private String source;

}
