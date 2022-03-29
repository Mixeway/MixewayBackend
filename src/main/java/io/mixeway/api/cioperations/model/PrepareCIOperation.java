/*
 * @created  2020-08-19 : 21:03
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.cioperations.model;

import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.db.entity.CodeProject;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PrepareCIOperation {
    Long projectId;
    Long codeProjectId;
    String openSourceScannerProjectId;
    String openSourceScannerCredentials;
    String openSourceScannerApiUrl;
    boolean openSourceScannerIntegration;
    String scannerType;


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
        this.projectId = codeProject.getProject().getId();
        this.codeProjectId = codeProject.getId();
    }
}
