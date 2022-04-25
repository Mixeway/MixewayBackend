package io.mixeway.api.vulnmanage.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * @author gsiewruk
 */
@Builder
@Getter
@Setter
public class SecurityScans {
    private String project;
    private String scanType;
    private String scope;
}
