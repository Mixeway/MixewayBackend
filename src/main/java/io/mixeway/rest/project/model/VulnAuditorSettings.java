package io.mixeway.rest.project.model;

import javax.validation.constraints.Pattern;

/**
 * @author gsiewruk
 */
public class VulnAuditorSettings {
    boolean enableVulnAuditor;
    @Pattern(regexp = "(?i)customer|employe$")
    String appClient;
    @Pattern(regexp = "(?i)localdc|remotedc$")
    String dclocation;

    public boolean isEnableVulnAuditor() {
        return enableVulnAuditor;
    }

    public void setEnableVulnAuditor(boolean enableVulnAuditor) {
        this.enableVulnAuditor = enableVulnAuditor;
    }

    public String getAppClient() {
        return appClient;
    }

    public void setAppClient(String appClient) {
        this.appClient = appClient;
    }

    public String getDclocation() {
        return dclocation;
    }

    public void setDclocation(String dclocation) {
        this.dclocation = dclocation;
    }
}
