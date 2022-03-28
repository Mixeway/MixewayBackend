package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OpenSourceConfig {
    private boolean openSourceScannerIntegration;
    private String openSourceScannerApiUrl;
    private String openSourceScannerProjectId;
    private String openSourceScannerCredentials;
    private String tech;
    private String scannerType;
    private Long codeProjectId;

}
