package io.mixeway.rest.admin.model;

import io.mixeway.db.entity.Settings;

/**
 * @author gsiewruk
 */
public class VulnAuditorEditSettings {
    private String url;
    private boolean enabled;

    public VulnAuditorEditSettings(Settings settings) {
        this.url = settings.getVulnAuditorUrl();
        this.enabled = settings.isVulnAuditorEnable();
    }

    public VulnAuditorEditSettings(){}
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
