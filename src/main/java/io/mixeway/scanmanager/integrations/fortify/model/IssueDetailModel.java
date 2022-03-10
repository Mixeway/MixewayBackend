package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class IssueDetailModel {
    private String detail;
    private String recommendation;
    private String scanStatus;
    private String fullFileName;
    private String references;
    private int lineNumber;
}
