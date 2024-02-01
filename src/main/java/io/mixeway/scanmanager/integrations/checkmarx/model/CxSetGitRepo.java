/*
 * @created  2020-10-14 : 17:25
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.db.entity.CodeProject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Objects;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CxSetGitRepo {
    String url;
    String branch;

    public CxSetGitRepo(CodeProject codeProject, String pass){
        if (pass != null){
            this.url ="https://"+pass+"@"+codeProject.getRepoUrl().split("://")[1];
        } else {
            this.url = codeProject.getRepoUrl();
        }
        if (codeProject.getActiveBranch() != null && !Objects.equals(codeProject.getActiveBranch(), "")) {
            this.branch = "refs/heads/" + codeProject.getActiveBranch();
        } else {
            this.branch = "refs/heads/" + codeProject.getBranch();
        }
    }

}
