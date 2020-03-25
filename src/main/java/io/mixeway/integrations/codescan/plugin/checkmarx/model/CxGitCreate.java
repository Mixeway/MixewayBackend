package io.mixeway.integrations.codescan.plugin.checkmarx.model;

import io.mixeway.db.entity.CodeProject;

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
