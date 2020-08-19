package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;

public interface CodeProjectRepository extends JpaRepository<CodeProject, Long> {
	Optional<CodeProject> findByCodeGroupAndName(CodeGroup codeGroup, String name);
	Optional<CodeProject> findByCodeGroupAndNameIgnoreCase(CodeGroup codeGroup, String name);
	List<CodeProject> findByCodeGroupIn(Set<CodeGroup> groups);
	@Query(value="select cp.* from codeproject cp, codegroup cg where cp.codegroup_id=cg.id and cg.project_id=?3 and cg.name=?2 and cp.name=?1", nativeQuery =true)
	Optional<CodeProject> getCodeProjectByNameCodeGroupNameAndProjectId(String codeProjectName,String codeGroupName,Long projectId);
	List<CodeProject> findByInQueue(Boolean inqueue);
	@Query(value = "select * from codeproject where name ilike %?1%", nativeQuery = true)
	List<CodeProject> searchForName(@Param("name") String name);
	@Query(value = "delete from codeproject where id=?1", nativeQuery = true)
	@Modifying
	int removeCodeGroup(Long id);
	List<CodeProject> findByRequestId(String requestId);
	List<CodeProject> findByCodeGroup(CodeGroup codeGroup);
	List<CodeProject> findBydTrackUuidNotNull();
	List<CodeProject> findByRunning(boolean running);
	List<CodeProject> findByCodeGroupAndRunning(CodeGroup codeGroup, boolean running);

	@Query(value = "Select * from codeproject where dtrackuuid is not null and dtrackuuid != ''", nativeQuery = true)
	List<CodeProject> getCodeProjectsWithOSIntegrationEnabled();
	Optional<CodeProject> findByName(String name);

}
