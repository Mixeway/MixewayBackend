package io.mixeway.rest.vulnmanage.model;

import io.mixeway.config.Constants;
import io.mixeway.plugins.codescan.model.CodeScanRequestModel;
import io.mixeway.plugins.infrastructurescan.model.NetworkScanRequestModel;
import io.mixeway.plugins.webappscan.model.WebAppScanRequestModel;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class CreateScanManageRequest {
    @NotNull @NotBlank String testType;
    WebAppScanRequestModel webAppScanRequest;
    NetworkScanRequestModel networkScanRequest;
    CodeScanRequestModel codeScanRequest;

    public String getTestType() {
        return testType;
    }

    public void setTestType(String testType) {
        this.testType = testType;
    }

    public WebAppScanRequestModel getWebAppScanRequest() {
        return webAppScanRequest;
    }

    public void setWebAppScanRequest(WebAppScanRequestModel webAppScanRequest) {
        this.webAppScanRequest = webAppScanRequest;
    }

    public NetworkScanRequestModel getNetworkScanRequest() {
        return networkScanRequest;
    }

    public void setNetworkScanRequest(NetworkScanRequestModel networkScanRequest) {
        this.networkScanRequest = networkScanRequest;
    }

    public CodeScanRequestModel getCodeScanRequest() {
        return codeScanRequest;
    }

    public void setCodeScanRequest(CodeScanRequestModel codeScanRequest) {
        this.codeScanRequest = codeScanRequest;
    }

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
