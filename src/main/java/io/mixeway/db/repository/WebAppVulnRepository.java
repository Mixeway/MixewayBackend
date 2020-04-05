package io.mixeway.db.repository;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import io.mixeway.pojo.BarChartProjection;
import io.mixeway.pojo.BarChartProjection2;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.entity.WebAppVuln;

public interface
WebAppVulnRepository extends JpaRepository<WebAppVuln, Long>{

	Long deleteByWebApp(WebApp webApp);
	Set<WebAppVuln> findByWebAppIn(Set<WebApp> webApps);
	@Query(value = "SELECT * from webappvuln where webapp_id in (select id from webapp where project_id=:projectId)", nativeQuery = true)
	Stream<WebAppVuln> getWebAppVulnsForProject(@Param("projectId")Long projectId);
	@Query(value = "SELECT * from webappvuln", nativeQuery = true)
	Stream<WebAppVuln> getAllWebAppVulns();
	Set<WebAppVuln> findByWebAppInAndSeverityNot(Set<WebApp> webApps, String severity);
	Set<WebAppVuln> findByWebAppInAndSeverityIn(Set<WebApp> webApps, List<String> severities);
	List<WebAppVuln> findByWebAppInAndSeverityContainingIgnoreCase(List<WebApp> webApps, String severity);
	@Query("SELECT distinct w.name from WebAppVuln w where severity != 'Log'")
	public List<String> findDistinctName();
	public Long countByName(String name);
	public List<WebAppVuln> findByName(String name);
	@Query(value = "select name, count(*) as value from webappvuln w where severity " +
			"in ('Critical','Critic','High') and w.webapp_id in (select id from webapp where project_id=?1) group by name order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection> getWebAppVulnByAsset(Long projectId);
	@Query(value = "select w.url as name, count(*) as value from webapp w, webappvuln wv where w.id=wv.webapp_id and wv.severity" +
			" in ('Critical','Critic','High') and w.project_id=?1 group by w.url order by value desc limit 10",nativeQuery = true)
	List<BarChartProjection> getWebAppVulnByName(Long projectId);
	Long countByWebAppInAndSeverity(Set<WebApp> webApps, String severity);
	@Query(value = "select count(*) as value, name as namee from webappvuln where severity in ('High','Critical')  group by name order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection2> getTopVulns();
	@Query(value = "select count(*) as value, w.url as namee from webappvuln wv, webapp w where w.id=wv.webapp_id and wv.severity in ('High','Critical')  group by w.url order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection2> getTopTargets();
	@Query(value = "select count(*) from webappvuln where webapp_id in (select id from webapp where project_id=?1) and severity=?2", nativeQuery =true)
	Long getCountByProjectIdAndSeverity(@Param("id")Long id, @Param("severity") String severity);
	@Query(value = "select count(*) from webappvuln where webapp_id=?1 and severity=?2", nativeQuery =true)
	Long getCountByWebAppIdAndSeverity(@Param("id")Long id, @Param("severity") String severity);
	@Query(value = "select * from webappvuln where name ilike %?1%", nativeQuery = true)
	List<WebAppVuln> searchForName(@Param("name") String name);
	List<WebAppVuln> findByWebApp(WebApp webApp);
	@Query(value = "select ((count(*) filter (where severity='Critical') * :critWage) + (count(*) filter (where severity='High') * :highWage) + (count(*) filter (where severity='Medium') * :mediumWage)) from " +
			"webappvuln where webapp_id in (select id from webapp where project_id=:project_id)", nativeQuery = true)
	int countRiskForProject(@Param("project_id")Long project_id,@Param("critWage") int critWage, @Param("highWage") int highWage,@Param("mediumWage") int mediumWage);
	@Query(value = "select ((count(*) filter (where severity='Critical') * :critWage) + (count(*) filter (where severity='High') * :highWage) + (count(*) filter (where severity='Medium') * :mediumWage)) from " +
			"webappvuln where webapp_id =:webapp_id", nativeQuery = true)
	int countRiskForWebApp(@Param("webapp_id")Long webapp_id,@Param("critWage") int critWage, @Param("highWage") int highWage,@Param("mediumWage") int mediumWage);

}
