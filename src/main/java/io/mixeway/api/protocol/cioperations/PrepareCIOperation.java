/*
 * @created  2020-08-19 : 21:03
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.protocol.cioperations;

import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.db.entity.CodeProject;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PrepareCIOperation {
    private Long projectId;
    private Long codeProjectId;
    private String openSourceScannerProjectId;
    private String openSourceScannerCredentials;
    private String openSourceScannerApiUrl;
    private boolean openSourceScannerIntegration;
    private String scannerType;


    public PrepareCIOperation(OpenSourceConfig openSourceConfig, CodeProject codeProject, String type) {
        this.openSourceScannerCredentials = openSourceConfig.getOpenSourceScannerCredentials();
        this.openSourceScannerApiUrl = openSourceConfig.getOpenSourceScannerApiUrl();
        this.openSourceScannerProjectId = openSourceConfig.getOpenSourceScannerProjectId();
        if (this.openSourceScannerApiUrl !=null && this.openSourceScannerCredentials!=null){
            this.openSourceScannerIntegration = true;
        } else {
            this.openSourceScannerIntegration = false;
        }
        this.scannerType = type;
        this.projectId = codeProject.getCodeGroup().getProject().getId();
        this.codeProjectId = codeProject.getId();
    }
}
