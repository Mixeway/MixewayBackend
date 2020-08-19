/*
 * @created  2020-08-19 : 23:53
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.cioperations.model;

public class InfoScanPerformed {
    String scope;
    Long codeProjectId;
    String branch;
    String commitId;

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Long getCodeProjectId() {
        return codeProjectId;
    }

    public void setCodeProjectId(Long codeProjectId) {
        this.codeProjectId = codeProjectId;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getCommitId() {
        return commitId;
    }

    public void setCommitId(String commitId) {
        this.commitId = commitId;
    }
}
