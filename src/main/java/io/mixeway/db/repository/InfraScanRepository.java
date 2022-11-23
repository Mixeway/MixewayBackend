package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Query;
import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Scanner;
import org.springframework.data.repository.query.Param;

public interface InfraScanRepository extends JpaRepository<InfraScan, Long>{
	List<InfraScan> findByProject(Project project);
	List<InfraScan> findByProjectAndIsAutomatic(Project project, Boolean isAutomatic);
	List<InfraScan> findByRunning(Boolean running);
	List<InfraScan> findTop5ByRunningOrderByIdAsc(Boolean running);
	List<InfraScan> findByIsAutomatic(Boolean isAutomatic);
	List<InfraScan> findByIsAutomaticAndScanFrequency(Boolean isAutomatic, int scanFrequency);
	List<InfraScan> findByIsAutomaticAndRunning(Boolean isAutomatic, Boolean running);
	List<InfraScan> findByIsAutomaticAndProjectAndNessus(Boolean isAutomatic, Project project, Scanner scanner);

	@Query(value="select ns.* from nessusscan ns inner join nessus n on n.id = ns.nessus_id where ns.running=true and n.rfwurl is not null", nativeQuery = true)
	List<InfraScan> getRunningScansWithRfwConfigured();
	Optional<InfraScan> findByProjectAndRequestId(Project project, String requestId);

	@Query(value="select * from nessusscan where running=true order by random() limit 5", nativeQuery = true)
    List<InfraScan> getRandom5RunningScans();
	List<InfraScan> findByProjectAndRunning(Project project, boolean running);
	List<InfraScan> findByProjectAndRunningOrInQueue(Project project, boolean running, boolean inQueue);
	List<InfraScan> findByNessusAndInQueue(Scanner scanner, Boolean inQueue);
	List<InfraScan> findByNessusAndInQueueOrderByIdAsc(Scanner scanner, Boolean inQueue);
	List<InfraScan> findByNessusAndRunning(Scanner scanner, Boolean running);
	Long countByInQueue(Boolean inQueue);
	Long countByRunning(Boolean running);
	List<InfraScan> findByInQueue(Boolean inQueue);
	List<InfraScan> findByRunningOrInQueue(Boolean inQueue, Boolean running);

	@Query(value = "select * from nessusscan where project_id = :project and (running=true or inqueue=true)", nativeQuery = true)
	List<InfraScan> getInfraScansRunningOrInQueueByProject(@Param("project")Long project);
}
