package io.mixeway.db.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.entity.WebAppHeader;
import org.springframework.transaction.annotation.Transactional;

public interface WebAppHeaderRepository extends JpaRepository<WebAppHeader, Long>{

	@Transactional
	@Modifying
	Long deleteByWebApp(WebApp webApp);
	Optional<WebAppHeader> findByWebAppAndHeaderName(WebApp webApp, String headerName);
	@Modifying
	@Query(value="delete from webappheader where webapp_id =?1",nativeQuery=true)
	void deleteHeaderForWebApp(Long webapp_id);
}
