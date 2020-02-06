package io.mixeway.plugins.codescan.checkmarx.model;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;

public class CxGitCreate {
     private String url;
     private String branch;

     public CxGitCreate(CodeProject codeProject, String pass){
        // if (codeGroup.)
     }

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
