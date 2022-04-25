package io.mixeway.api.protocol;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class OpenSourceConfig {
    private boolean openSourceScannerIntegration;
    private String openSourceScannerApiUrl;
    private String openSourceScannerProjectId;
    private String openSourceScannerCredentials;
    private String tech;
    private String scannerType;
    private Long codeProjectId;
}
