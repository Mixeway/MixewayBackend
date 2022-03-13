package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.VaultHelper;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Optional;
import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@AllArgsConstructor
@Log4j2
public class CreateOrGetCodeGroupService {
    private final CodeGroupRepository codeGroupRepository;
    private final PermissionFactory permissionFactory;
    private final VaultHelper vaultHelper;

    public CodeGroup createOrGetCodeGroupService(Principal principal, String codeGroupName, String repoUrl,
                                                 Project project, String repoUsername, String repoPassword,
                                                 String tech){
        Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project, codeGroupName);
        if (codeGroup.isPresent() && permissionFactory.canUserAccessProject(principal,project)) {
            return codeGroup.get();
        }
        else if (!codeGroup.isPresent() && permissionFactory.canUserAccessProject(principal,project)) {
            CodeGroup codeGroupToCreate = new CodeGroup();
            codeGroupToCreate.setName(codeGroupName);
            codeGroupToCreate.setRepoUrl(repoUrl);
            codeGroupToCreate.setProject(project);
            codeGroupToCreate.setTechnique(tech);
            codeGroupToCreate.setRepoUsername(repoUsername);
            codeGroupToCreate.setHasProjects(false);
            codeGroupToCreate.setAuto(false);
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(repoPassword, uuidToken)){
                codeGroupToCreate.setRepoPassword(uuidToken);
            } else {
                codeGroupToCreate.setRepoPassword(repoPassword);
            }
            codeGroupRepository.saveAndFlush(codeGroupToCreate);
            log.info("Creating new CodeGroup {} for project {}", codeGroupName, project.getName());
            return codeGroupToCreate;
        }
        else {
            log.warn("Not authorized user {} trying to access project {}",principal.getName(),project.getName());
            return null;
        }
    }

}
