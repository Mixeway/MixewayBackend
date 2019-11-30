package io.mixeway.rest.model;

public class ScannerModel {
    String scannerType;
    Long routingDomain;
    Long proxy;
    String apiUrl;
    String username;
    String password;
    String secretkey;
    String accesskey;
    String apiKey;
    String cloudCtrlToken;

    public String getSecretkey() {
        return secretkey;
    }

    public void setSecretkey(String secretkey) {
        this.secretkey = secretkey;
    }

    public Long getProxy() {
        return proxy;
    }

    public void setProxy(Long proxy) {
        this.proxy = proxy;
    }

    public String getScannerType() {
        return scannerType;
    }

    public void setScannerType(String scannerType) {
        this.scannerType = scannerType;
    }

    public Long getRoutingDomain() {
        return routingDomain;
    }

    public void setRoutingDomain(Long routingDomain) {
        this.routingDomain = routingDomain;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAccesskey() {
        return accesskey;
    }

    public void setAccesskey(String accesskey) {
        this.accesskey = accesskey;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getCloudCtrlToken() {
        return cloudCtrlToken;
    }

    public void setCloudCtrlToken(String cloudCtrlToken) {
        this.cloudCtrlToken = cloudCtrlToken;
    }
}
