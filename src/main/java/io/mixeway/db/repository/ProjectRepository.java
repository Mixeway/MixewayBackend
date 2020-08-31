package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.pojo.BarChartProjection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ProjectRepository extends JpaRepository<Project, Long>{
	List<Project> findByNodesNotNull();
	Optional<List<Project>> findByCiid(String ciid);
	Optional<List<Project>> findByName(String name);
	Optional<List<Project>> findByNameAndOwner(String name, User user);
	Optional<Project> findByIdAndApiKey(Long id, String apiKey);
	List<Project> findByApiKey(String apiKey);
	List<Project> findByAutoWebAppScan(boolean autoWebScan);
	List<Project> findByAutoCodeScan(boolean autoWebScan);
	List<Project> findByAutoInfraScan(boolean autoInfraScan);
	List<Project> findByContactListNotNull();
	@Query(value="SELECT distinct(regexp_split_to_table(contactlist, E',')) FROM project",nativeQuery = true)
	List<String> getUniqueContactListEmails();
	@Query(value = "select p from Project p where name = :name")
	Optional<Project> getProjectByName(@Param("name") String name);
	@Query(value="select p from Project p where contactlist like CONCAT('%',:email,'%')")
	List<Project> getUniqueContactListEmails(@Param("email") String email);
	List<Project> findByVulnAuditorEnable(boolean vulnAuditorEnable);
	List<Project> findByEnableVulnManage(boolean vulnManage);
}
