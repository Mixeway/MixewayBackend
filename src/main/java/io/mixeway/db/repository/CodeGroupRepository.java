package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.CodeGroup;

public interface CodeGroupRepository extends JpaRepository<CodeGroup, Long>{
	
	Optional<CodeGroup> findByProjectAndName(Project project, String name);
	Optional<CodeGroup> findByProjectAndNameIgnoreCase(Project project, String name);
	List<CodeGroup> findByRunningAndRequestidNotNullAndScanidNull(Boolean running);
	List<CodeGroup> findByRunningAndRequestidNotNullAndScanidNotNull(Boolean running);
	List<CodeGroup> findByRunningAndScanidNotNull(Boolean running);
	Long countByRunning(Boolean running);
	List<CodeGroup> findByInQueue(Boolean inqueue);
	List<CodeGroup> findByAuto(Boolean auto);
	List<CodeGroup> findByRunning(Boolean running);
}