package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProjectRepository extends JpaRepository<Project, Long>{
	List<Project> findByNodesNotNull();
	Optional<List<Project>> findByCiid(String ciid);
	Optional<List<Project>> findByName(String name);
	Optional<Project> findByIdAndApiKey(Long id, String apiKey);
	List<Project> findByAutoWebAppScan(boolean autoWebScan);
	List<Project> findByAutoCodeScan(boolean autoWebScan);
	List<Project> findByAutoInfraScan(boolean autoInfraScan);
}
