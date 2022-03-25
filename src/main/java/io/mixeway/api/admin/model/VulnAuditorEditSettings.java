package io.mixeway.api.admin.model;

import io.mixeway.db.entity.Settings;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author gsiewruk
 */
@Getter
@Setter
@NoArgsConstructor
public class VulnAuditorEditSettings {
    private String url;
    private boolean enabled;

    public VulnAuditorEditSettings(Settings settings) {
        this.url = settings.getVulnAuditorUrl();
        this.enabled = settings.isVulnAuditorEnable();
    }
}
