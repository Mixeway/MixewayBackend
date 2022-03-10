package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FortifyVuln {
    private String issueName;
    private String friority;
    private Long id;
    private String primaryTag;
    private String fullFileName;
    private int lineNumber;
    private String issueInstanceId;
}
