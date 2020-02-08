package io.mixeway.plugins.codescan.fortify.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scanner;

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

    public boolean isCommitted() {
        return committed;
    }

    public void setCommitted(boolean committed) {
        this.committed = committed;
    }

    public boolean isActive() {
        return active;
    }

    public String getIssueTemplateId() {
        return issueTemplateId;
    }

    public void setIssueTemplateId(String issueTemplateId) {
        this.issueTemplateId = issueTemplateId;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public FortifyProject getProject() {
        return project;
    }

    public void setProject(FortifyProject project) {
        this.project = project;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
