package io.mixeway.scanmanager.integrations.vulnauditor.model;

/**
 * @author gsiewruk
 */
public class VulnAuditorRequest {
    Long id;
    String appName;
    String appContext;
    String vulnName;
    String vulnDescription;
    String severity;

    public VulnAuditorRequest(){}
    public VulnAuditorRequest(Long id, String appName, String appContext, String vulnName, String vulnDescription, String severity){
        this.id = id;
        this.appContext = appContext;
        this.appName =appName;
        this.vulnDescription = vulnDescription;
        this.vulnName = vulnName;
        this.severity = severity;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getAppContext() {
        return appContext;
    }

    public void setAppContext(String appContext) {
        this.appContext = appContext;
    }

    public String getVulnName() {
        return vulnName;
    }

    public void setVulnName(String vulnName) {
        this.vulnName = vulnName;
    }

    public String getVulnDescription() {
        return vulnDescription;
    }

    public void setVulnDescription(String vulnDescription) {
        this.vulnDescription = vulnDescription;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }
}
