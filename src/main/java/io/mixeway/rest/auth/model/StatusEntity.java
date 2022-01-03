package io.mixeway.rest.auth.model;

public class StatusEntity {
    Boolean initialized;
    Boolean password;
    Boolean cert;
    Boolean facebook;
    Boolean gitHub;
    Boolean keycloak;

    public Boolean getFacebook() {
        return facebook;
    }

    public void setFacebook(Boolean facebook) {
        this.facebook = facebook;
    }

    public Boolean getGitHub() {
        return gitHub;
    }

    public void setGitHub(Boolean gitHub) {
        this.gitHub = gitHub;
    }

    public Boolean getPassword() {
        return password;
    }

    public void setPassword(Boolean password) {
        this.password = password;
    }

    public Boolean getCert() {
        return cert;
    }

    public void setCert(Boolean cert) {
        this.cert = cert;
    }

    public StatusEntity(Boolean init, Boolean cert, Boolean password, Boolean facebook, Boolean gitHub,Boolean keycloak){
        this.initialized = init;
        this.cert = cert;
        this.password = password;
        this.facebook = facebook;
        this.gitHub = gitHub;
        this.keycloak = keycloak;
    }

    public Boolean getInitialized() {
        return initialized;
    }

    public void setInitialized(Boolean initialized) {
        this.initialized = initialized;
    }


    public Boolean getKeycloak() {
        return keycloak;
    }

    public void setKeycloak(Boolean keycloak) {
        this.keycloak = keycloak;
    }
}
