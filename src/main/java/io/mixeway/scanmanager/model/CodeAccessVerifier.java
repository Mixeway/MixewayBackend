package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
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
    private final CodeGroupRepository codeGroupRepository;
    private final VerifySASTPermissionsService verifySASTPermissionsService;



    public SASTRequestVerify verifyPermissions(long projectId, String groupName, String projectName, boolean depCheck){
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent()){
            if( projectName != null){
                Optional<CodeGroup> cg = codeGroupRepository.findByProjectAndName(project.get(),groupName);
                if (cg.isPresent()){
                    return verifySASTPermissionsService.verifyIfCodeGroupIsPresent(cg,projectName,depCheck);
                } else{
                    return verifySASTPermissionsService.verifyIfCodeGroupIsNotPresent();
                }
            } else{
                Optional<CodeGroup> cg = codeGroupRepository.findByProjectAndName(project.get(),groupName);
                if (cg.isPresent()){
                    return verifySASTPermissionsService.returnNotValidRequestWithGroup(cg);
                }
                else{
                    return verifySASTPermissionsService.returnNotValidRequestWithLog(groupName, "CodeProject request Has no group");
                }
            }

        } else{
            return verifySASTPermissionsService.returnNotValidRequestWithLog(Long.toString(projectId), "Request has no project assigned");
        }
    }
}
