package io.mixeway.rest.auth.model;

import com.sun.org.apache.xpath.internal.operations.Bool;

public class StatusEntity {
    Boolean initialized;
    Boolean password;
    Boolean cert;
    Boolean facebook;
    Boolean gitHub;

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

    public StatusEntity(Boolean init, Boolean cert, Boolean password, Boolean facebook, Boolean gitHub){
        this.initialized = init;
        this.cert = cert;
        this.password = password;
        this.facebook = facebook;
        this.gitHub = gitHub;
    }

    public Boolean getInitialized() {
        return initialized;
    }

    public void setInitialized(Boolean initialized) {
        this.initialized = initialized;
    }
}
