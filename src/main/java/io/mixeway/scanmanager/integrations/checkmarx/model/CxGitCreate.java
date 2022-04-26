package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.db.entity.CodeProject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class CxGitCreate {
     private String url;
     private String branch;

     public CxGitCreate(){}

     public CxGitCreate(CodeProject codeProject, String pass){
         this.branch = codeProject.getBranch();
         String[] urlToParse;
         if (codeProject.getRepoUrl() != null){
             urlToParse = codeProject.getRepoUrl().split("://");
         } else {
             urlToParse = codeProject.getRepoUrl().split("://");
         }
         if (codeProject.getRepoUsername() ==null && codeProject.getRepoPassword() == null){
             this.url = urlToParse[0] + "://" + urlToParse[1];
         } else {
             this.url = urlToParse[0] + "://" + (codeProject.getRepoUsername() != null ? codeProject.getRepoUsername() + ":" + pass + "@" : pass + "@") + urlToParse[1];
         }
     }
}
