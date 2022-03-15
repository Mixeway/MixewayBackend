package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.repository.CodeProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

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
}
