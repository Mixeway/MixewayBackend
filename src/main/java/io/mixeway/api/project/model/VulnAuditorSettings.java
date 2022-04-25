package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Pattern;

/**
 * @author gsiewruk
 */
@Getter
@Setter
public class VulnAuditorSettings {
    boolean enableVulnAuditor;
    @Pattern(regexp = "(?i)customer|employe$")
    String appClient;
    @Pattern(regexp = "(?i)localdc|remotedc$")
    String dclocation;
}
