package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FortifyScan {
    private Long id;
    private String groupName;
    private String projectName;
    private String requestId;
    private String scanId;
    private Boolean inqueue;
    private Boolean running;
    private String technique;
    private Boolean error;
    private String commitid;
}
