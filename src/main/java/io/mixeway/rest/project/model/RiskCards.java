package io.mixeway.rest.project.model;

public class RiskCards {
    String projectName;
    String projectDescription;
    boolean enableVulnAuditor;
    int assetNumber;
    int assetRisk;
    int webAppNumber;
    int webAppRisk;
    int codeRepoNumber;
    int codeRisk;
    int audit;
    int auditRisk;
    int openSourceLibs;
    int openSourceRisk;

    public boolean isEnableVulnAuditor() {
        return enableVulnAuditor;
    }

    public void setEnableVulnAuditor(boolean enableVulnAuditor) {
        this.enableVulnAuditor = enableVulnAuditor;
    }

    public int getOpenSourceLibs() {
        return openSourceLibs;
    }

    public void setOpenSourceLibs(int openSourceLibs) {
        this.openSourceLibs = openSourceLibs;
    }

    public int getOpenSourceRisk() {
        return openSourceRisk;
    }

    public void setOpenSourceRisk(int openSourceRisk) {
        this.openSourceRisk = openSourceRisk;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectDescription() {
        return projectDescription;
    }

    public void setProjectDescription(String projectDescription) {
        this.projectDescription = projectDescription;
    }

    public int getAssetNumber() {
        return assetNumber;
    }

    public void setAssetNumber(int assetNumber) {
        this.assetNumber = assetNumber;
    }

    public int getAssetRisk() {
        return assetRisk;
    }

    public void setAssetRisk(int assetRisk) {
        this.assetRisk = assetRisk;
    }

    public int getWebAppNumber() {
        return webAppNumber;
    }

    public void setWebAppNumber(int webAppNumber) {
        this.webAppNumber = webAppNumber;
    }

    public int getWebAppRisk() {
        return webAppRisk;
    }

    public void setWebAppRisk(int webAppRisk) {
        this.webAppRisk = webAppRisk;
    }

    public int getCodeRepoNumber() {
        return codeRepoNumber;
    }

    public void setCodeRepoNumber(int codeRepoNumber) {
        this.codeRepoNumber = codeRepoNumber;
    }

    public int getCodeRisk() {
        return codeRisk;
    }

    public void setCodeRisk(int codeRisk) {
        this.codeRisk = codeRisk;
    }

    public int getAudit() {
        return audit;
    }

    public void setAudit(int audit) {
        this.audit = audit;
    }

    public int getAuditRisk() {
        return auditRisk;
    }

    public void setAuditRisk(int auditRisk) {
        this.auditRisk = auditRisk;
    }
}
