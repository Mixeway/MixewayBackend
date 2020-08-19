/*
 * @created  2020-08-19 : 21:04
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.cioperations.model;

public class GetInfoRequest {
    String repoUrl;
    String scope;

    public String getRepoUrl() {
        return repoUrl;
    }

    public void setRepoUrl(String repoUrl) {
        this.repoUrl = repoUrl;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
