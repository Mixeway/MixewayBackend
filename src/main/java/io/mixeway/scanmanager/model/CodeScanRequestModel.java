package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Optional;

@Getter
@Setter
@NoArgsConstructor
public class CodeScanRequestModel {
    @NotBlank @NotNull String projectName;
    String ciid;
    Optional<Boolean> enableVulnManage;

    public Optional<Boolean> getEnableVulnManage() {
        return enableVulnManage;
    }

    public void setEnableVulnManage(Optional<Boolean> enableVulnManage) {
        this.enableVulnManage = enableVulnManage;
    }
    @NotBlank @NotNull String codeProjectName;
    @NotBlank @NotNull String codeGroupName;
    @NotBlank @NotNull String tech;
    String repoUrl;
    String repoUsername;
    String branch;
    String repoPassword;
    int fortifySSCVersionId;

}
