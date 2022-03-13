package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.domain.service.project.GetProjectsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

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
    private final GetProjectsService getProjectsService;

    public CodeProject createOrGetCodeProject(CodeGroup codeGroup, String name, String branch){
        Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(codeGroup,name);
        return codeProject.orElseGet(() -> createCodeProject(codeGroup, name, branch));
    }

    public CodeProject createOrGetCodeProjectWithGroupName(long projectId, String codeGroupName, String codeProjectName, String branch){
        Project project = getProjectsService.getProject(projectId);
        if (project != null) {
            Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project,codeGroupName);
            if (codeGroup.isPresent()){
                return createOrGetCodeProject(codeGroup.get(), codeGroupName, branch);
            }
        }
        return null;
    }

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
}
