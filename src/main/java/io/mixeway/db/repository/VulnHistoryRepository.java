package io.mixeway.db.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import io.mixeway.db.entity.VulnHistory;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import io.mixeway.rest.model.SourceDetectionChartData;

public interface VulnHistoryRepository extends JpaRepository<VulnHistory, Long>{
	List<VulnHistory> findByName(String name);
	@Query(value="select * from vulnhistory v where v.project_id = ?1 order by v.inserted desc limit 14",nativeQuery=true)
	List<VulnHistory> getVulnForProject( Long project);
	@Query(value="select * from vulnhistory v where v.project_id= ?1 order by v.inserted desc limit 7", nativeQuery = true)
	List<VulnHistory> getLastTwoVulnForProject(Long project);
	@Query(value="select sum(infrastructurevulnnumber+codevulnnumber+webappvulnnumber+auditvulnnumber+softwarepacketvulnnumber) as value, " +
			"split_part(inserted, ' ', 1) as date from vulnhistory group by date order by date desc limit 10", nativeQuery = true)
	List<OverAllVulnTrendChartData> getOverallVulnTrendData();
	@Query(value="select sum(infrastructurevulnnumber) as infra, sum(codevulnnumber) as code," +
			"sum(webappvulnnumber) as webapp,sum(auditvulnnumber) as audit,sum(softwarepacketvulnnumber) as soft, " +
			"split_part(inserted, ' ', 1) as ins from vulnhistory group by ins order by ins desc limit 1;", nativeQuery = true)
	SourceDetectionChartData getSourceTrendChart();


}
