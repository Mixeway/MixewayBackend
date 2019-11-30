package io.mixeway.rest.project.model;

public class CodeGroupPutModel {
    private String codeGroupName;
    private int versionIdAll;
    private int versionIdSingle;
    private String giturl;
    private String gitusername;
    private String gitpassword;
    private String tech;
    private boolean autoScan;
    private boolean childs;

    public String getCodeGroupName() {
        return codeGroupName;
    }

    public void setCodeGroupName(String codeGroupName) {
        this.codeGroupName = codeGroupName;
    }

    public int getVersionIdAll() {
        return versionIdAll;
    }

    public void setVersionIdAll(int versionIdAll) {
        this.versionIdAll = versionIdAll;
    }

    public int getVersionIdSingle() {
        return versionIdSingle;
    }

    public void setVersionIdSingle(int versionIdSingle) {
        this.versionIdSingle = versionIdSingle;
    }

    public String getGiturl() {
        return giturl;
    }

    public void setGiturl(String giturl) {
        this.giturl = giturl;
    }

    public String getGitusername() {
        return gitusername;
    }

    public void setGitusername(String gitusername) {
        this.gitusername = gitusername;
    }

    public String getGitpassword() {
        return gitpassword;
    }

    public void setGitpassword(String gitpassword) {
        this.gitpassword = gitpassword;
    }

    public String getTech() {
        return tech;
    }

    public void setTech(String tech) {
        this.tech = tech;
    }

    public boolean isAutoScan() {
        return autoScan;
    }

    public void setAutoScan(boolean autoScan) {
        this.autoScan = autoScan;
    }

    public boolean isChilds() {
        return childs;
    }

    public void setChilds(boolean childs) {
        this.childs = childs;
    }
}
