package io.mixeway.api.vulnmanage.model;

import io.mixeway.config.Constants;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import io.mixeway.scanmanager.model.WebAppScanRequestModel;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Getter
@Setter
public class CreateScanManageRequest {
    @NotNull @NotBlank String testType;
    private WebAppScanRequestModel webAppScanRequest;
    private NetworkScanRequestModel networkScanRequest;
    private CodeScanRequestModel codeScanRequest;

    public boolean isValid(){
        if (testType.equals(Constants.REQUEST_SCAN_WEBAPP) && webAppScanRequest !=null){
            return true;
        } else if (testType.equals(Constants.REQUEST_SCAN_NETWORK) && networkScanRequest != null){
            return true;
        } else if ( testType.equals(Constants.REQUEST_SCAN_CODE) && codeScanRequest != null){
            return true;
        } else {
            return false;
        }
    }
}
