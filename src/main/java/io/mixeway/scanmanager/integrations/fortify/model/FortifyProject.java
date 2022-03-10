package io.mixeway.scanmanager.integrations.fortify.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Scanner;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
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
}
