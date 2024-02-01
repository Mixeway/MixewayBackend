package io.mixeway.db.repository;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeProjectBranch;
import io.mixeway.db.entity.CodeScan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CodeProjectBranchRepository extends JpaRepository<CodeProjectBranch,Long> {
    List<CodeProjectBranch> findCodeProjectBranchByCodeProject(CodeProject codeProject);
    CodeProjectBranch findCodeProjectBranchByCodeProjectAndName(CodeProject project, String name);
}
