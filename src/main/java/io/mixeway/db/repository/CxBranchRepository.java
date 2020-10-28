/*
 * @created  2020-10-28 : 10:19
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.db.repository;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CxBranch;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface CxBranchRepository extends JpaRepository<CxBranch, Long> {
    Optional<CxBranch> findByBranchAndCodeProject(String branch, CodeProject codeProject);
    @Query(value = "select b from CxBranch b where b.codeProject = :codeProject and b.branch = :branch")
    Optional<CxBranch> getCxBranchForProjectAndBranchAndCxProjectCreated(@Param("codeProject") CodeProject codeProject, @Param("branch") String branch);
}
