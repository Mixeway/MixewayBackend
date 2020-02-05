package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Query;
import io.mixeway.db.entity.NessusScan;
import io.mixeway.db.entity.Scanner;

public interface NessusScanRepository extends JpaRepository<NessusScan, Long>{
	List<NessusScan> findByProject(Project project);
	List<NessusScan> findByProjectAndIsAutomatic(Project project, Boolean isAutomatic);
	List<NessusScan> findByRunning(Boolean running);
	List<NessusScan> findTop10ByRunningOrOrderByIdAsc(Boolean running);
	List<NessusScan> findByIsAutomatic(Boolean isAutomatic);
	List<NessusScan> findByIsAutomaticAndScanFrequency(Boolean isAutomatic, int scanFrequency);
	List<NessusScan> findByIsAutomaticAndRunning(Boolean isAutomatic, Boolean running);
	List<NessusScan> findByIsAutomaticAndProjectAndNessus(Boolean isAutomatic, Project project, Scanner scanner);

	@Query(value="select ns.* from nessusscan ns inner join nessus n on n.id = ns.nessus_id where ns.running=true and n.rfwurl is not null", nativeQuery = true)
	List<NessusScan> getRunningScansWithRfwConfigured();
	Optional<NessusScan> findByProjectAndRequestId(Project project, String requestId);
	

}
