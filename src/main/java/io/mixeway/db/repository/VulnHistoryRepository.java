package io.mixeway.db.repository;

import java.util.List;

import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.SourceDetectionChartData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import io.mixeway.db.entity.VulnHistory;
import org.springframework.data.repository.query.Param;

public interface VulnHistoryRepository extends JpaRepository<VulnHistory, Long>{
	List<VulnHistory> findByName(String name);
	@Query(value="select * from vulnhistory v where v.project_id = ?1 order by v.inserted desc limit 14",nativeQuery=true)
	List<VulnHistory> getVulnForProject( Long project);
	@Query(value="select * from vulnhistory v where v.project_id= ?1 order by v.inserted desc limit 7", nativeQuery = true)
	List<VulnHistory> getLastTwoVulnForProject(Long project);
	@Query(value="select * from vulnhistory v where v.project_id= ?1 order by v.inserted desc limit ?2", nativeQuery = true)
	List<VulnHistory> getVulnHistoryLimit(Long project, int limit);
	@Query(value="select sum(infrastructurevulnnumber+codevulnnumber+webappvulnnumber+auditvulnnumber+softwarepacketvulnnumber) as value, " +
			"split_part(inserted, ' ', 1) as date from vulnhistory where project_id in :projects group by date order by date desc limit 10", nativeQuery = true)
	List<OverAllVulnTrendChartData> getOverallVulnTrendData(@Param("projects") List<Long> projects);
	@Query(value="select sum(infrastructurevulnnumber) as infra, sum(codevulnnumber) as code," +
			"sum(webappvulnnumber) as webapp,sum(auditvulnnumber) as audit,sum(softwarepacketvulnnumber) as soft, " +
			"split_part(inserted, ' ', 1) as ins from vulnhistory where project_id in :projects group by ins order by ins desc limit 1;", nativeQuery = true)
	SourceDetectionChartData getSourceTrendChart(@Param("projects") List<Long> projects);
	@Query(value="select * from vulnhistory where inserted like (select substring(inserted,1,10) || '%' as i " +
			"from vulnhistory order by i desc limit 1 ) order by inserted desc", nativeQuery = true)
	List<VulnHistory> recentHistoryForAllProjects();
	@Query(value="select * from vulnhistory where project_id in :projects and inserted like (select substring(inserted,1,10) || '%' as i " +
			"from vulnhistory order by i desc limit 1 ) order by inserted desc", nativeQuery = true)
	List<VulnHistory> recentHistoryForProjects(@Param("projects") List<Long> projectIds);


}
