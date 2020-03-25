package io.mixeway.integrations.codescan.plugin.fortify.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scanner;

public class FortifyProject {
    private String name;
    private String createdBy;
    private String description;
    private String issueTemplateId;
    public FortifyProject() {}
    public FortifyProject(CodeProject codeProject, Scanner scanner) {
        this.name = codeProject.getCodeGroup().getName();
        this.description = Constants.CREATED_BY_MIXEWAY;
        this.createdBy = scanner.getUsername();
        this.issueTemplateId = Constants.FORTIFY_ISSUE_TEMPLATE;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getIssueTemplateId() {
        return issueTemplateId;
    }

    public void setIssueTemplateId(String issueTemplateId) {
        this.issueTemplateId = issueTemplateId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
