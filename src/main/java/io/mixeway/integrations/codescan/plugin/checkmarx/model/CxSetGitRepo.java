/*
 * @created  2020-10-14 : 17:25
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.codescan.plugin.checkmarx.model;

import io.mixeway.db.entity.CodeProject;
import org.springframework.security.core.parameters.P;

public class CxSetGitRepo {
    String url;
    String branch;

    public CxSetGitRepo(CodeProject codeProject, String pass){
        if (pass != null){
            this.url ="https://"+pass+"@"+codeProject.getRepoUrl().split("://")[1];
        } else {
            this.url = codeProject.getRepoUrl();
        }
        this.branch = "refs/heads/" + codeProject.getBranch();
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
