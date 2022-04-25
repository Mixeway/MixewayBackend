package io.mixeway.api.project.model;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
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
    private String dTrackUuid;
    private String appClient;
    private String branch;

    public CodeGroupPutModel(String codeGroupName, String giturl, boolean autoScan, boolean childs, String branch){
        this.codeGroupName = codeGroupName;
        this.giturl = giturl;
        this.autoScan = autoScan;
        this.childs = childs;
        this.branch = branch;
    }
}
