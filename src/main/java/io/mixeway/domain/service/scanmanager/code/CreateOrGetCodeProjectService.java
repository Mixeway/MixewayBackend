package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class CreateOrGetCodeProjectService {

    private final CodeProjectRepository codeProjectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final CreateOrGetCodeGroupService createOrGetCodeGroupService;

    /**
     *
     * Creating CodeProject based on given CodeGroup
     *
     */
    public CodeProject createOrGetCodeProject(CodeGroup codeGroup, String name, String branch){
        Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(codeGroup,name);
        return codeProject.orElseGet(() -> createCodeProject(codeGroup, name, branch));
    }

    /**
     *
     * Create CodeProject or return existing based on existing codeGroup name
     *
     */
    public CodeProject createOrGetCodeProjectWithGroupName(Project project, String codeGroupName, String codeProjectName, String branch){
        Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project,codeGroupName);
        return codeGroup.map(group -> createOrGetCodeProject(group, codeGroupName, branch)).orElse(null);
    }

    /**
     *
     * Create Code project based on given Code Group
     *
     */
    private CodeProject createCodeProject(CodeGroup codeGroup, String codeProjectName, String branch){
        CodeProject codeProjectToCreate = new CodeProject();
        codeProjectToCreate.setName(codeProjectName);
        codeProjectToCreate.setCodeGroup(codeGroup);
        codeProjectToCreate.setTechnique(codeGroup.getTechnique());
        codeProjectToCreate.setBranch(branch);
        codeProjectToCreate.setRepoUrl(codeGroup.getRepoUrl());
        codeProjectToCreate = codeProjectRepository.saveAndFlush(codeProjectToCreate);
        log.info("Creating new CodeProject {} in group {}", codeProjectName,codeGroup.getName());
        return codeProjectToCreate;
    }

    /**
     *
     * Create CodeGroup and CodeProject based on given parameters
     *
     */
    public CodeProject createCodeProject(String repoUrl, String repoUsername, String repoPassword, String branch, String tech,
                                         String name, Project project, Principal principal) {
        CodeGroup codeGroup = createOrGetCodeGroupService.createOrGetCodeGroup(principal,name,repoUrl,project,repoUsername,repoPassword,tech);
        return createCodeProject(codeGroup,name,branch);
    }
    /**
     *
     * Create CodeGroup and CodeProject based on CodeScanRequestModel
     *
     */
    public CodeProject createCodeProject(CodeScanRequestModel codeScanRequest, CodeGroup codeGroup) {
        CodeProject codeProject = new CodeProject();
        codeProject.setName(codeScanRequest.getCodeProjectName());
        codeProject.setCodeGroup(codeGroup);
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Created new CodeProject [{}] {}", "ScanManager", codeGroup.getProject().getName(), codeProject.getName());
        return codeProject;
    }
}
