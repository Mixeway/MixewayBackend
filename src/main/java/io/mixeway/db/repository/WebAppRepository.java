package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.WebApp;

import javax.transaction.Transactional;

public interface WebAppRepository extends JpaRepository<WebApp, Long> {
	List<WebApp> findByProject(Project project);
	List<WebApp> findByRunning(Boolean running);
	Optional<WebApp> findByProjectAndUrl(Project project, String url);	
	@Query(value="select count(*) from webapp v where v.running = ?1",nativeQuery=true)
	Long getCountOfRunningScans(Boolean running);
	@Query(value="select * from webapp v where v.inqueue=?1 limit ?2", nativeQuery=true)
	List<WebApp> getXInQueue(Boolean inQueue, int limit);
	List<WebApp> findByAutoStart(Boolean autostart);
	@Query(value = "select * from webapp w where w.lastexecuted<?1",nativeQuery = true)
	List<WebApp> getUnusedWebApps(String date);
	@Query(value="select * from webapp where project_id =?1 order by lastexecuted asc limit 1", nativeQuery = true)
	WebApp getLastExecutionForProject(Long projectid);
	@Query(value="select * from webapp wa where wa.url ilike %:url% and project_id=:id", nativeQuery = true)
	Optional<WebApp> getWebAppWithSimiliarUrlForProject(@Param("url") String url, @Param("id") Long project_id);
	@Query(value="select * from webapp wa where wa.url ~ :url and project_id=:id", nativeQuery = true)
	Optional<WebApp> getWebAppByRegex(@Param("url") String url, @Param("id") Long project_id);
	@Query(value="select * from webapp wa where wa.url ~ :url and project_id=:id", nativeQuery = true)
	List<WebApp> getWebAppByRegexAsList(@Param("url") String url, @Param("id") Long project_id);
	@Query(value = "select * from webapp where url ilike %?1% limit 100", nativeQuery = true)
	List<WebApp> searchForUrl(@Param("url") String url);
	List<WebApp> findByRequestId(String requestId);
	@Query(value = "delete from webapp where id in ?1", nativeQuery = true)
	@Modifying
	@Transactional
	int deleteWebApsById(@Param("ids") List<Long> ids);
	Optional<WebApp> findByUrl(String url);
	List<WebApp> findByInQueue(boolean inQueue);
	@Query(value="select * from webapp wa where (wa.url ilike :urlSimiliar or wa.url ~ :urlRegex) and project_id=:id", nativeQuery = true)
	List<WebApp> getWebAppBySimiliarUrlOrRegexUrl(@Param("urlSimiliar") String urlSimiliar,@Param("urlRegex") String urlRegex, @Param("id") Long project_id);
	Long countByInQueue(Boolean inQueue);
	Long countByRunning(Boolean running);
}
