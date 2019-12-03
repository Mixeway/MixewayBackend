package io.mixeway.plugins.utils;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.plugins.audit.mvndependencycheck.model.SASTRequestVerify;

import java.util.Optional;

@Service
public class CodeAccessVerifier {
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final static Logger log = LoggerFactory.getLogger(CodeAccessVerifier.class);
    @Autowired
    CodeAccessVerifier(ProjectRepository projectRepository, CodeProjectRepository codeProjectRepository, CodeGroupRepository codeGroupRepository){
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.codeGroupRepository = codeGroupRepository;
    }
    public SASTRequestVerify verifyPermissions(long projectId, String groupName, String projectName){
        SASTRequestVerify sastRequestVerify= new SASTRequestVerify();
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent()){
            if( projectName != null){
                Optional<CodeGroup> cg = codeGroupRepository.findByProjectAndName(project.get(),groupName);
                if (cg.isPresent()){
                    Optional<CodeProject> cp = codeProjectRepository.findByCodeGroupAndName(cg.get(),projectName);
                    if (cp.isPresent() && cp.get().getCodeGroup().getVersionIdsingle() > 0){
                        sastRequestVerify.setValid(true);
                        sastRequestVerify.setCg(cg.get());
                        sastRequestVerify.setCp(cp.get());
                        return sastRequestVerify;
                    }
                    else{
                        sastRequestVerify.setValid(false);
                        sastRequestVerify.setCg(cg.get());
                        return sastRequestVerify;
                    }

                } else{
                    sastRequestVerify.setValid(false);
                    return sastRequestVerify;
                }
            } else{
                Optional<CodeGroup> cg = codeGroupRepository.findByProjectAndName(project.get(),groupName);
                if (cg.isPresent()){
                    sastRequestVerify.setValid(false);
                    sastRequestVerify.setCg(cg.get());
                    return sastRequestVerify;
                }
                else{
                    log.info("Has no group {} and no projec {}", groupName,projectName);
                    sastRequestVerify.setValid(false);
                    return sastRequestVerify;
                }
            }

        } else{
            log.info("Has no project {} ", projectId);
            sastRequestVerify.setValid(false);
            return sastRequestVerify;
        }
    }
}
