package io.mixeway.rest.auth.model;

public class StatusEntity {
    Boolean initialized;
    Boolean password;
    Boolean cert;

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

    public StatusEntity(Boolean init, Boolean cert, Boolean password){
        this.initialized = init;
        this.cert = cert;
        this.password = password;
    }

    public Boolean getInitialized() {
        return initialized;
    }

    public void setInitialized(Boolean initialized) {
        this.initialized = initialized;
    }
}
