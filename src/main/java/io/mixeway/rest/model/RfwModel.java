package io.mixeway.rest.model;

public class RfwModel {
    String rfwUrl;
    String rfwUsername;
    String rfwPassword;
    String rfwScannerIp;

    public String getRfwScannerIp() {
        return rfwScannerIp;
    }

    public void setRfwScannerIp(String rfwScannerIp) {
        this.rfwScannerIp = rfwScannerIp;
    }

    public String getRfwUrl() {
        return rfwUrl;
    }

    public void setRfwUrl(String rfwUrl) {
        this.rfwUrl = rfwUrl;
    }

    public String getRfwUsername() {
        return rfwUsername;
    }

    public void setRfwUsername(String rfwUsername) {
        this.rfwUsername = rfwUsername;
    }

    public String getRfwPassword() {
        return rfwPassword;
    }

    public void setRfwPassword(String rfwPassword) {
        this.rfwPassword = rfwPassword;
    }
}
