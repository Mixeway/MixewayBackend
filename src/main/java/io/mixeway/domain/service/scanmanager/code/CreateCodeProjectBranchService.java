package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeProjectBranch;
import io.mixeway.db.repository.CodeProjectBranchRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

@Service
@Log4j2
@RequiredArgsConstructor
public class CreateCodeProjectBranchService {
    private final CodeProjectBranchRepository codeProjectBranchRepository;

    public CodeProjectBranch createCodeProjectBranch(CodeProject codeProject, String branch){
        return codeProjectBranchRepository.save(new CodeProjectBranch(codeProject,branch));
    }
}
