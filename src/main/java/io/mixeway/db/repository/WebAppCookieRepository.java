package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import io.mixeway.db.entity.WebAppCookies;

public interface WebAppCookieRepository extends JpaRepository<WebAppCookies,Long> {
    @Modifying
    @Query(value="delete from webappcookies where webapp_id =?1",nativeQuery=true)
    void deleteCookiesForWebApp(Long webapp_id);
}
