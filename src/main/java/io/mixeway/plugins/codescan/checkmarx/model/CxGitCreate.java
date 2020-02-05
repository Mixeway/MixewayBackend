package io.mixeway.plugins.codescan.checkmarx.model;

public class CxGitCreate {
     private String url;
     private String branch;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }
}
