package io.mixeway.scanmanager.integrations.fortify.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scanner;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FortifyProjectVersions {
    private FortifyProject project;
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    private int id;
    private String name;
    private boolean active;
    private boolean committed;
    private String issueTemplateId;

    public FortifyProjectVersions () {};
    public FortifyProjectVersions(CodeProject codeProject, Scanner scanner){
        this.project = new FortifyProject(codeProject,scanner);
        this.name = codeProject.getBranch() != null ? codeProject.getBranch() : "master";
        this.active = true;
        this.committed = true;
        this.issueTemplateId = Constants.FORTIFY_ISSUE_TEMPLATE;
    }
}
