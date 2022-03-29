package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.service.scanmanager.code.VerifySASTPermissionsService;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Log4j2
@AllArgsConstructor
public class CodeAccessVerifier {
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final VerifySASTPermissionsService verifySASTPermissionsService;

    public SASTRequestVerify verifyIfCodeProjectInProject(long projectId, String codeProjectName){
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent()){
            Optional<CodeProject> codeProject = codeProjectRepository.findByProjectAndName(project.get(),codeProjectName);
            if (codeProject.isPresent()){
                return SASTRequestVerify.builder()
                        .valid(true)
                        .cp(codeProject.get())
                        .build();
            }

        }

        return SASTRequestVerify.builder()
                .valid(false)
                .build();
    }


}
