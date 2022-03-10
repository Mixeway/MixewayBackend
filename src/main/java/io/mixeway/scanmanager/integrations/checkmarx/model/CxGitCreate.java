package io.mixeway.scanmanager.integrations.checkmarx.model;

import io.mixeway.db.entity.CodeProject;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
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
             urlToParse = codeProject.getCodeGroup().getRepoUrl().split("://");
         }
         if (codeProject.getCodeGroup().getRepoUsername() ==null && codeProject.getCodeGroup().getRepoPassword() == null){
             this.url = urlToParse[0] + "://" + urlToParse[1];
         } else {
             this.url = urlToParse[0] + "://" + (codeProject.getCodeGroup().getRepoUsername() != null ? codeProject.getCodeGroup().getRepoUsername() + ":" + pass + "@" : pass + "@") + urlToParse[1];
         }
     }
}
