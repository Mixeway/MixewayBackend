package io.mixeway.rest.admin.model;

public class AuthSettingsModel {

    Boolean passwordAuth;
    Boolean certificateAuth;

    public Boolean getPasswordAuth() {
        return passwordAuth;
    }

    public void setPasswordAuth(Boolean passwordAuth) {
        this.passwordAuth = passwordAuth;
    }

    public Boolean getCertificateAuth() {
        return certificateAuth;
    }

    public void setCertificateAuth(Boolean certificateAuth) {
        this.certificateAuth = certificateAuth;
    }
}
