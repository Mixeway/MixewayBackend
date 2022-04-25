package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RiskCards {
    private String projectName;
    private String projectDescription;
    private boolean enableVulnAuditor;
    private int assetNumber;
    private int assetRisk;
    private int webAppNumber;
    private int webAppRisk;
    private int codeRepoNumber;
    private int codeRisk;
    private int audit;
    private int auditRisk;
    private int openSourceLibs;
    private int openSourceRisk;
}
