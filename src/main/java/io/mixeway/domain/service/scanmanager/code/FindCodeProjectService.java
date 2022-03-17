package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.repository.CodeProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindCodeProjectService {
    private final CodeProjectRepository codeProjectRepository;

    public Optional<CodeProject> findCodeProject(CodeGroup codeGroup, String codeProjectName){
        return codeProjectRepository.findByCodeGroupAndName(codeGroup,codeProjectName);
    }
    public List<CodeProject> findRunningCodeProjects(){
        return codeProjectRepository.findByRunning(true);
    }
    public Optional<CodeProject> findById(long id){
        return codeProjectRepository.findById(id);
    }
}
